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
	"os"

	"github.com/cplieger/atomicfile/v2"
	"software.sslmate.com/src/go-pkcs12"
)

// MaxFileSize is the maximum allowed size for cert/key files (10 MB).
const MaxFileSize = 10 << 20

// PEM block type constants.
const (
	PEMTypeCertificate         = "CERTIFICATE"
	PEMTypePrivateKey          = "PRIVATE KEY"
	PEMTypeRSAPrivateKey       = "RSA PRIVATE KEY"
	PEMTypeECPrivateKey        = "EC PRIVATE KEY"
	PEMTypeEncryptedPrivateKey = "ENCRYPTED PRIVATE KEY"
)

// ReadBoundedFromRoot opens rel within root and reads it under a size limit,
// confining the read to root's tree: a symlink or ".." component in rel can
// never redirect the read outside root. It is the /input read seam — every
// certificate and key read flows through the *os.Root (Go 1.24+) so a malicious
// symlink planted in the watched directory cannot leak a file from outside it.
// The caller owns root; ReadBoundedFromRoot does not close it.
func ReadBoundedFromRoot(ctx context.Context, root *os.Root, rel string, limit int64) ([]byte, error) {
	f, err := root.Open(rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return atomicfile.ReadBoundedFile(ctx, f, limit)
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
	block, err := findPrivateKeyBlock(pemBytes)
	if err != nil {
		return nil, err
	}
	return parsePrivateKeyBlock(block)
}

// findPrivateKeyBlock scans pemBytes for the first PEM block holding a private
// key cert-converter can decode, skipping certificate and other blocks. It
// distinguishes "no key block at all" from "the only key blocks are encrypted"
// so the caller surfaces actionable guidance: both a PKCS#8 ENCRYPTED PRIVATE
// KEY block and a traditional OpenSSL key carrying "Proc-Type: 4,ENCRYPTED" +
// "DEK-Info" headers hold ciphertext none of the parsers can decode.
func findPrivateKeyBlock(pemBytes []byte) (*pem.Block, error) {
	var sawEncrypted bool
	for {
		var block *pem.Block
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			if sawEncrypted {
				return nil, errors.New("private key PEM block is encrypted; decrypt it before use")
			}
			return nil, errors.New("no private key PEM block found")
		}
		switch block.Type {
		case PEMTypePrivateKey, PEMTypeRSAPrivateKey, PEMTypeECPrivateKey:
			if isEncryptedPEMBlock(block) {
				sawEncrypted = true
				continue
			}
			return block, nil
		case PEMTypeEncryptedPrivateKey:
			sawEncrypted = true
			continue
		default:
			continue
		}
	}
}

// isEncryptedPEMBlock reports whether a traditional OpenSSL private-key block
// carries encryption headers ("Proc-Type: 4,ENCRYPTED" or "DEK-Info"), whose
// body is ciphertext the DER parsers cannot decode.
func isEncryptedPEMBlock(block *pem.Block) bool {
	return block.Headers["Proc-Type"] == "4,ENCRYPTED" || block.Headers["DEK-Info"] != ""
}

// parsePrivateKeyBlock decodes a single unencrypted private-key PEM block,
// trying PKCS8 first, then falling back to PKCS1 (RSA) and SEC1 (EC). A PKCS8
// container holding a key type cert-converter does not support is rejected with
// a distinct error rather than reported as unparseable.
func parsePrivateKeyBlock(block *pem.Block) (crypto.PrivateKey, error) {
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
