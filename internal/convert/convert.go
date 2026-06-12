// Package convert provides PEM parsing and PFX encoding utilities.
package convert

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/cplieger/atomicfile/v2"
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
func ReadFileWithLimit(ctx context.Context, path string, limit int64) ([]byte, error) {
	return atomicfile.ReadBounded(ctx, path, limit)
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
func ToPFX(ctx context.Context, privKey crypto.PrivateKey, leaf *x509.Certificate, caCerts []*x509.Certificate, destPath, password string, enc *pkcs12.Encoder) error {
	pfxData, err := enc.Encode(privKey, leaf, caCerts, password)
	if err != nil {
		return fmt.Errorf("encode pfx: %w", err)
	}

	if _, err := atomicfile.WriteFile(ctx, destPath, pfxData,
		atomicfile.WithMode(0o600),
	); err != nil {
		return fmt.Errorf("write pfx: %w", err)
	}
	return nil
}
