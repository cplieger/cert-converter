package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"software.sslmate.com/src/go-pkcs12"
)

// --- Configuration ---

const (
	// Fixed container paths — configured via volume mounts, not env vars.
	certsRootDir = "/input"
	outputDir    = "/output"

	// healthFile is touched on startup and removed on shutdown.
	// The "health" subcommand checks its existence for Docker healthchecks
	// without requiring an HTTP server or open port.
	healthFile = "/tmp/.healthy"

	// maxFileSize is the maximum allowed size for cert/key files (10 MB).
	// Prevents memory exhaustion from maliciously large files.
	maxFileSize = 10 << 20
)

// Encoder name constants for PFX encoding selection.
const (
	encNameModern2023 = "modern2023"
	encNameModern2026 = "modern2026"
	encNameLegacyDES  = "legacydes"
	encNameLegacyRC2  = "legacyrc2"
)

// --- Entrypoint ---

func main() {
	// CLI health probe for Docker healthcheck (distroless has no curl/wget).
	// Checks for a marker file instead of making an HTTP request — no port needed.
	if len(os.Args) > 1 && os.Args[1] == "health" {
		if _, err := os.Stat(healthFile); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}

	password := os.Getenv("PFX_PASSWORD")
	enc, encName := pickEncoder()
	interval := parseFallbackInterval()

	if interval > 0 {
		slog.Info("starting cert watcher",
			"input", certsRootDir, "output", outputDir,
			"fallback_interval", interval, "encoder", encName)
	} else {
		slog.Info("starting cert watcher",
			"input", certsRootDir, "output", outputDir,
			"fallback_scan", "disabled", "encoder", encName)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Health file is removed on exit; created/removed based on processAll results.
	defer setHealthy(false)

	// Initial full scan — health reflects whether processing succeeded.
	if err := processAll(certsRootDir, outputDir, password, enc); err != nil {
		slog.Error("initial processing failed", "error", err)
		setHealthy(false)
	} else {
		setHealthy(true)
	}

	// Try fsnotify; fall back to polling if it fails.
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		slog.Warn("fsnotify unavailable, using polling only", "error", err)
		pollLoop(ctx, certsRootDir, outputDir, password, enc, interval)
	} else {
		defer watcher.Close()
		if err := addWatchDirs(watcher, certsRootDir); err != nil {
			slog.Warn("failed to watch directories, using polling only", "error", err)
			pollLoop(ctx, certsRootDir, outputDir, password, enc, interval)
		} else {
			watchLoop(ctx, watcher, certsRootDir, outputDir, password, enc, interval)
		}
	}

	slog.Info("shutting down", "cause", context.Cause(ctx))
}

// --- Health ---

// setHealthy creates or removes the health marker file.
func setHealthy(ok bool) {
	if ok {
		if f, err := os.Create(healthFile); err == nil {
			f.Close()
		}
	} else {
		os.Remove(healthFile)
	}
}

// --- Environment Parsing ---

// parseFallbackInterval reads FALLBACK_SCAN_HOURS from the environment.
// Returns 0 to disable polling, or the parsed duration.
func parseFallbackInterval() time.Duration {
	v, ok := os.LookupEnv("FALLBACK_SCAN_HOURS")
	if !ok {
		return 6 * time.Hour
	}
	trimmed := strings.TrimSpace(v)
	switch strings.ToLower(trimmed) {
	case "", "0", "false":
		return 0
	default:
		if n, err := strconv.Atoi(trimmed); err == nil && n > 0 {
			return time.Duration(n) * time.Hour
		}
		return 6 * time.Hour
	}
}

// pickEncoder returns the PFX encoder and its name based on PFX_ENCODER env var.
func pickEncoder() (enc *pkcs12.Encoder, name string) {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("PFX_ENCODER"))) {
	case encNameLegacyRC2:
		return pkcs12.LegacyRC2, encNameLegacyRC2
	case "legacy", encNameLegacyDES:
		return pkcs12.LegacyDES, encNameLegacyDES
	case encNameModern2026:
		return pkcs12.Modern2026, encNameModern2026
	case "", "modern", encNameModern2023:
		return pkcs12.Modern2023, encNameModern2023
	default:
		return pkcs12.Modern2023, encNameModern2023
	}
}

// --- Watch Loop ---

// addWatchDirs recursively adds all directories under root to the watcher.
func addWatchDirs(watcher *fsnotify.Watcher, root string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return watcher.Add(path)
		}
		return nil
	})
}

// handleFsEvent processes a single fsnotify event, adding new directories
// to the watcher and flagging cert/key changes for debounced processing.
func handleFsEvent(event fsnotify.Event, watcher *fsnotify.Watcher, pending *bool, debounceTimer *time.Timer, debounce time.Duration) {
	if event.Has(fsnotify.Create) {
		if info, err := os.Stat(event.Name); err == nil && info.IsDir() {
			if addErr := watcher.Add(event.Name); addErr != nil {
				slog.Warn("failed to watch new directory", "path", event.Name, "error", addErr)
			}
		}
	}
	if strings.HasSuffix(event.Name, ".crt") || strings.HasSuffix(event.Name, ".key") {
		if !*pending {
			*pending = true
			debounceTimer.Reset(debounce)
		}
	}
}

// watchLoop uses fsnotify for immediate reaction to cert changes,
// with a periodic full scan as a safety net.
func watchLoop(ctx context.Context, watcher *fsnotify.Watcher, certsRoot, outRoot, password string, enc *pkcs12.Encoder, interval time.Duration) {
	const debounce = 2 * time.Second

	var fallbackTimer *time.Timer
	if interval > 0 {
		fallbackTimer = time.NewTimer(interval)
		defer fallbackTimer.Stop()
	}

	var pending bool
	debounceTimer := time.NewTimer(debounce)
	debounceTimer.Stop()
	defer debounceTimer.Stop()

	for {
		var fallbackC <-chan time.Time
		if fallbackTimer != nil {
			fallbackC = fallbackTimer.C
		}

		select {
		case <-ctx.Done():
			return

		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			handleFsEvent(event, watcher, &pending, debounceTimer, debounce)

		case <-debounceTimer.C:
			pending = false
			slog.Info("cert change detected, processing")
			processAndSetHealth(certsRoot, outRoot, password, enc)
			if fallbackTimer != nil {
				fallbackTimer.Reset(interval)
			}

		case <-fallbackC:
			processAndSetHealth(certsRoot, outRoot, password, enc)
			fallbackTimer.Reset(interval)

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			slog.Warn("watcher error", "error", err)
		}
	}
}

// --- Poll Loop ---

// pollLoop is the fallback when fsnotify is unavailable.
func pollLoop(ctx context.Context, certsRoot, outRoot, password string, enc *pkcs12.Encoder, interval time.Duration) {
	if interval <= 0 {
		slog.Info("polling disabled and fsnotify unavailable, waiting for shutdown")
		<-ctx.Done()
		return
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			processAndSetHealth(certsRoot, outRoot, password, enc)
		}
	}
}

// --- Processing ---

// processAndSetHealth runs processAll and updates the health marker.
func processAndSetHealth(certsRoot, outRoot, password string, enc *pkcs12.Encoder) {
	if err := processAll(certsRoot, outRoot, password, enc); err != nil {
		slog.Error("processing failed", "error", err)
		setHealthy(false)
	} else {
		setHealthy(true)
	}
}

// fileHash stores the last known hash of a cert+key pair to skip unchanged files.
type fileHash struct {
	certHash string
	keyHash  string
}

var (
	mu     sync.Mutex
	hashes = make(map[string]fileHash)
)

// hashFile returns the hex-encoded SHA-256 of a file's contents.
// Uses streaming hash to avoid loading the entire file into memory.
// Rejects files larger than maxFileSize to prevent resource exhaustion.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if info.Size() > maxFileSize {
		return "", fmt.Errorf("file %s exceeds 10 MB size limit (%d bytes)", filepath.Base(path), info.Size())
	}

	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, maxFileSize)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// changed returns true if the cert or key file has changed since last conversion.
func changed(crtPath, keyPath string) bool {
	certH, err := hashFile(crtPath)
	if err != nil {
		return true // can't read → treat as changed
	}
	keyH, err := hashFile(keyPath)
	if err != nil {
		return true
	}

	mu.Lock()
	defer mu.Unlock()

	prev, exists := hashes[crtPath]
	if !exists || prev.certHash != certH || prev.keyHash != keyH {
		hashes[crtPath] = fileHash{certHash: certH, keyHash: keyH}
		return true
	}
	return false
}

func processAll(certsRoot, outRoot, password string, enc *pkcs12.Encoder) error {
	return filepath.WalkDir(certsRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".crt") {
			return nil
		}

		keyPath := strings.TrimSuffix(path, ".crt") + ".key"
		if _, statErr := os.Stat(keyPath); statErr != nil {
			return nil
		}

		if !changed(path, keyPath) {
			return nil
		}

		rel, err := filepath.Rel(certsRoot, path)
		if err != nil {
			return err
		}
		dir, file := filepath.Split(rel)
		base := strings.TrimSuffix(file, ".crt")

		destDir := filepath.Join(outRoot, dir)
		if err := os.MkdirAll(destDir, 0o755); err != nil {
			return err
		}
		destPath := filepath.Join(destDir, base+".pfx")

		if err := convertToPFX(path, keyPath, destPath, password, enc); err != nil {
			slog.Error("conversion failed", "cert", rel, "error", err)
			return nil
		}

		destRel := strings.TrimSuffix(rel, ".crt") + ".pfx"
		slog.Info("wrote pfx", "path", destRel)
		return nil
	})
}

// --- PFX Conversion ---

// readFileWithLimit opens a file, validates its size, and returns its contents.
// Uses a single file handle to avoid TOCTOU races between stat and read.
func readFileWithLimit(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("file exceeds %d byte limit (%d bytes)", limit, info.Size())
	}

	return io.ReadAll(io.LimitReader(f, limit))
}

func convertToPFX(crtPath, keyPath, destPath, password string, enc *pkcs12.Encoder) error {
	certPEM, err := readFileWithLimit(crtPath, maxFileSize)
	if err != nil {
		return fmt.Errorf("read cert: %w", err)
	}

	keyPEM, err := readFileWithLimit(keyPath, maxFileSize)
	if err != nil {
		return fmt.Errorf("read key: %w", err)
	}

	chain, err := parseCertChain(certPEM)
	if err != nil {
		return err
	}
	leaf := chain[0]
	var caCerts []*x509.Certificate
	if len(chain) > 1 {
		caCerts = chain[1:]
	}

	privKey, err := parsePrivateKey(keyPEM)
	if err != nil {
		return err
	}

	pfxData, err := enc.Encode(privKey, leaf, caCerts, password)
	if err != nil {
		return err
	}

	// Atomic write: temp file + rename prevents corruption on crash.
	tmp, err := os.CreateTemp(filepath.Dir(destPath), ".cert-convert-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(pfxData); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, destPath); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}

// --- PEM Parsing ---

func parseCertChain(pemBytes []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	for {
		var block *pem.Block
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}

	if len(certs) == 0 {
		return nil, errors.New("no certificate PEM block found")
	}
	return certs, nil
}

func parsePrivateKey(pemBytes []byte) (crypto.PrivateKey, error) {
	var block *pem.Block
	for {
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			return nil, errors.New("no private key PEM block found")
		}
		if strings.Contains(block.Type, "PRIVATE KEY") {
			break
		}
	}

	// Try PKCS8 first — modern standard, handles RSA, ECDSA, and Ed25519.
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		switch key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("unsupported private key type in PKCS8 container")
		}
	}

	// Fall back to legacy format-specific parsers.
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	return nil, errors.New("failed to parse private key (tried PKCS8, PKCS1, SEC1)")
}
