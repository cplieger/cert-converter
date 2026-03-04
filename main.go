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
	"io/fs"
	"log"
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

// fileHash stores the last known hash of a cert+key pair to skip unchanged files.
type fileHash struct {
	certHash string
	keyHash  string
}

var (
	mu     sync.Mutex
	hashes = make(map[string]fileHash)
)

const (
	// Fixed container paths — configured via volume mounts, not env vars.
	certsRootDir = "/input"
	outputDir    = "/output"

	// healthFile is touched on startup and removed on shutdown.
	// The "health" subcommand checks its existence for Docker healthchecks
	// without requiring an HTTP server or open port.
	healthFile = "/tmp/.healthy"
)

func main() {
	log.SetOutput(os.Stdout)

	// CLI health probe for Docker healthcheck (distroless has no curl/wget).
	// Checks for a marker file instead of making an HTTP request — no port needed.
	if len(os.Args) > 1 && os.Args[1] == "health" {
		if _, err := os.Stat(healthFile); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}

	certsRoot := certsRootDir
	outRoot := outputDir
	password := os.Getenv("PFX_PASSWORD")

	interval := 6 * time.Hour
	if v, ok := os.LookupEnv("FALLBACK_SCAN_HOURS"); ok {
		low := strings.ToLower(strings.TrimSpace(v))
		switch low {
		case "", "0", "false":
			interval = 0
		default:
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				interval = time.Duration(n) * time.Hour
			}
		}
	}

	if interval > 0 {
		log.Printf("Starting cert watcher: input=%s output=%s fallback_interval=%s",
			certsRoot, outRoot, interval)
	} else {
		log.Printf("Starting cert watcher: input=%s output=%s fallback_scan=disabled",
			certsRoot, outRoot)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Health file is removed on exit; created/removed based on processAll results.
	defer removeHealthFile()

	// Initial full scan — health reflects whether processing succeeded.
	if err := processAll(certsRoot, outRoot, password); err != nil {
		log.Printf("error during initial processing: %v", err)
		removeHealthFile()
	} else {
		touchHealthFile()
	}

	// Try fsnotify; fall back to polling if it fails
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("fsnotify unavailable (%v), using polling only", err)
		pollLoop(ctx, certsRoot, outRoot, password, interval)
	} else {
		defer watcher.Close()
		if err := addWatchDirs(watcher, certsRoot); err != nil {
			log.Printf("failed to watch directories (%v), using polling only", err)
			pollLoop(ctx, certsRoot, outRoot, password, interval)
		} else {
			watchLoop(ctx, watcher, certsRoot, outRoot, password, interval)
		}
	}

	log.Println("Shutting down...")
}

// touchHealthFile creates the health marker file.
func touchHealthFile() {
	if f, err := os.Create(healthFile); err == nil {
		f.Close()
	}
}

// removeHealthFile removes the health marker file.
func removeHealthFile() {
	os.Remove(healthFile)
}

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
				log.Printf("failed to watch new directory %s: %v", event.Name, addErr)
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

// resetFallbackTimer resets the fallback timer if it is enabled.
func resetFallbackTimer(timer *time.Timer, interval time.Duration) {
	if timer != nil {
		timer.Reset(interval)
	}
}

// watchLoop uses fsnotify for immediate reaction to cert changes,
// with a periodic full scan as a safety net.
func watchLoop(ctx context.Context, watcher *fsnotify.Watcher, certsRoot, outRoot, password string, interval time.Duration) {
	const debounce = 2 * time.Second

	var timer *time.Timer
	if interval > 0 {
		timer = time.NewTimer(interval)
		defer timer.Stop()
	}

	var pending bool
	debounceTimer := time.NewTimer(debounce)
	debounceTimer.Stop()
	defer debounceTimer.Stop()

	for {
		var timerC <-chan time.Time
		if timer != nil {
			timerC = timer.C
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
			log.Println("cert change detected, processing...")
			if err := processAll(certsRoot, outRoot, password); err != nil {
				log.Printf("error during processing: %v", err)
				removeHealthFile()
			} else {
				touchHealthFile()
			}
			resetFallbackTimer(timer, interval)

		case <-timerC:
			if err := processAll(certsRoot, outRoot, password); err != nil {
				log.Printf("error during periodic processing: %v", err)
				removeHealthFile()
			} else {
				touchHealthFile()
			}
			timer.Reset(interval)

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Printf("watcher error: %v", err)
		}
	}
}

// pollLoop is the fallback when fsnotify is unavailable.
func pollLoop(ctx context.Context, certsRoot, outRoot, password string, interval time.Duration) {
	if interval <= 0 {
		log.Println("Polling disabled and fsnotify unavailable, waiting for shutdown...")
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
			if err := processAll(certsRoot, outRoot, password); err != nil {
				log.Printf("error during processing: %v", err)
				removeHealthFile()
			} else {
				touchHealthFile()
			}
		}
	}
}

// hashFile returns the hex-encoded SHA-256 of a file's contents.
func hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
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

func processAll(certsRoot, outRoot, password string) error {
	return filepath.WalkDir(certsRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".crt") {
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

		if err := convertToPFX(path, keyPath, destPath, password); err != nil {
			log.Printf("failed to convert %s / %s: %v", path, keyPath, err)
			return nil
		}

		log.Printf("wrote %s", destPath)
		return nil
	})
}

func pickEncoder() *pkcs12.Encoder {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("PFX_ENCODER"))) {
	case "legacyrc2":
		return pkcs12.LegacyRC2
	case "legacy", "legacydes":
		return pkcs12.LegacyDES
	case "modern2026":
		return pkcs12.Modern2026
	case "", "modern", "modern2023":
		return pkcs12.Modern2023
	default:
		return pkcs12.Modern2023
	}
}

func convertToPFX(crtPath, keyPath, destPath, password string) error {
	certPEM, err := os.ReadFile(crtPath)
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return err
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

	enc := pickEncoder()
	pfxData, err := enc.Encode(privKey, leaf, caCerts, password)
	if err != nil {
		return err
	}

	tmp := destPath + ".tmp." + strconv.FormatInt(time.Now().UnixNano(), 36)
	if err := os.WriteFile(tmp, pfxData, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, destPath); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

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

	// Try PKCS8 first — modern standard, handles RSA, ECDSA, and Ed25519
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		switch k := key.(type) {
		case *rsa.PrivateKey:
			return k, nil
		case *ecdsa.PrivateKey:
			return k, nil
		case ed25519.PrivateKey:
			return k, nil
		default:
			return nil, errors.New("unsupported private key type in PKCS8 container")
		}
	}

	// Fall back to legacy format-specific parsers
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	return nil, errors.New("failed to parse private key (tried PKCS8, PKCS1, SEC1)")
}
