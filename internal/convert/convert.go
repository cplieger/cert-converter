// Package convert provides PEM parsing and PFX encoding utilities.
package convert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"software.sslmate.com/src/go-pkcs12"
)

// MaxFileSize is the maximum allowed size for cert/key files (10 MB).
const MaxFileSize = 10 << 20

// PEM block type constants.
const (
	PEMTypeCertificate   = "CERTIFICATE"
	PEMTypePrivateKey    = "PRIVATE KEY"
	PEMTypeRSAPrivateKey = "RSA PRIVATE KEY"
	PEMTypeECPrivateKey  = "EC PRIVATE KEY"
)

// ReadFileWithLimit opens a file, validates its size, and returns its contents.
func ReadFileWithLimit(path string, limit int64) ([]byte, error) {
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

	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file grew past %d byte limit during read", limit)
	}
	return data, nil
}

// ParseCertChain decodes all CERTIFICATE PEM blocks from pemBytes,
// returning them in order. Returns an error if no certificates are found.
func ParseCertChain(pemBytes []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	for {
		var block *pem.Block
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			break
		}
		if block.Type != PEMTypeCertificate {
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

// ParsePrivateKey extracts a private key from PEM data, trying PKCS8
// first, then falling back to PKCS1 (RSA) and SEC1 (EC) formats.
func ParsePrivateKey(pemBytes []byte) (crypto.PrivateKey, error) {
	var block *pem.Block
	var sawEncrypted bool
	for {
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			if sawEncrypted {
				return nil, errors.New("private key PEM block is encrypted (ENCRYPTED PRIVATE KEY); decrypt it before use")
			}
			return nil, errors.New("no private key PEM block found")
		}
		switch block.Type {
		case PEMTypePrivateKey, PEMTypeRSAPrivateKey, PEMTypeECPrivateKey:
			// supported
		case "ENCRYPTED PRIVATE KEY":
			sawEncrypted = true
			continue
		default:
			continue
		}
		break
	}

	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		switch key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("unsupported private key type in PKCS8 container")
		}
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	return nil, errors.New("failed to parse private key (tried PKCS8, PKCS1, SEC1)")
}

// ToPFX encodes a private key, leaf certificate, and optional CA chain
// as PKCS#12 and writes the result atomically to destPath.
func ToPFX(privKey crypto.PrivateKey, leaf *x509.Certificate, caCerts []*x509.Certificate, destPath, password string, enc *pkcs12.Encoder) error {
	pfxData, err := enc.Encode(privKey, leaf, caCerts, password)
	if err != nil {
		return fmt.Errorf("encode pfx: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(destPath), ".cert-convert-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()

	if _, err := tmp.Write(pfxData); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("write pfx: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("sync pfx: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close pfx: %w", err)
	}
	if err := os.Rename(tmpName, destPath); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename pfx: %w", err)
	}
	if dir, dirErr := os.Open(filepath.Dir(destPath)); dirErr == nil {
		if syncErr := dir.Sync(); syncErr != nil {
			slog.Warn("dir sync failed, durability not guaranteed", "dir", filepath.Dir(destPath), "error", syncErr)
		}
		dir.Close()
	}
	return nil
}
