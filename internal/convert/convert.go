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
	"strings"
	"syscall"

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
// Only regular files are read, and the open is non-blocking, so a named pipe,
// device node, or socket planted in the watched tree cannot stall the scan.
// The caller owns root; ReadBoundedFromRoot does not close it.
func ReadBoundedFromRoot(ctx context.Context, root *os.Root, rel string, limit int64) ([]byte, error) {
	// O_NONBLOCK so a FIFO or device node planted in the watched tree cannot
	// wedge the open: open(2) on a FIFO with no writer blocks forever, and the
	// scan runs on the watch loop's only goroutine. The flag has no effect on a
	// regular file, the only input cert-converter accepts.
	f, err := root.OpenFile(rel, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file (type %s)", rel, fi.Mode().Type())
	}
	return atomicfile.ReadBoundedFile(ctx, f, limit)
}

// ParseCertChain decodes all CERTIFICATE PEM blocks from pemBytes, returning
// them in order. Blocks of any other type (the private key of a combined
// cert+key file, for instance) are skipped. It returns an error if no
// CERTIFICATE block is present, and also if any CERTIFICATE block holds DER
// that x509 cannot parse: a partially decodable chain is rejected outright
// rather than silently truncated, because a PFX built from a truncated chain
// fails validation obscurely at the consumer instead of here.
func ParseCertChain(pemBytes []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	var skipped int

	for {
		var block *pem.Block
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			break
		}
		if block.Type != PEMTypeCertificate {
			skipped++
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("certificate PEM block %d: %w", len(certs)+1, err)
		}
		certs = append(certs, c)
	}

	if len(certs) == 0 {
		if skipped > 0 {
			return nil, fmt.Errorf("no certificate PEM block found (skipped %d non-certificate PEM block(s))", skipped)
		}
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
	var skipped int
	for {
		var block *pem.Block
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			if sawEncrypted {
				return nil, errors.New("private key PEM block is encrypted; decrypt it before use")
			}
			if skipped > 0 {
				return nil, fmt.Errorf("no private key PEM block found (skipped %d PEM block(s))", skipped)
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
			skipped++
			continue
		}
	}
}

// isEncryptedPEMBlock reports whether a traditional OpenSSL private-key block
// carries encryption headers ("Proc-Type: 4,ENCRYPTED" or "DEK-Info"), whose
// body is ciphertext the DER parsers cannot decode. The Proc-Type value is
// compared case-insensitively and ignoring interior spaces, so a hand-written
// "4, ENCRYPTED" is still recognised.
func isEncryptedPEMBlock(block *pem.Block) bool {
	if block.Headers["DEK-Info"] != "" {
		return true
	}
	procType := strings.ToUpper(strings.ReplaceAll(block.Headers["Proc-Type"], " ", ""))
	return procType == "4,ENCRYPTED"
}

// parsePrivateKeyBlock decodes a single unencrypted private-key PEM block,
// trying PKCS8 first, then falling back to PKCS1 (RSA) and SEC1 (EC). A PKCS8
// container holding a key type cert-converter does not support is rejected with
// a distinct error rather than reported as unparseable.
func parsePrivateKeyBlock(block *pem.Block) (crypto.PrivateKey, error) {
	key, pkcs8Err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if pkcs8Err == nil {
		switch key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("unsupported private key type in PKCS8 container")
		}
	}

	if rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return rsaKey, nil
	}
	if ecKey, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return ecKey, nil
	}

	return nil, fmt.Errorf("failed to parse private key (tried PKCS8, PKCS1, SEC1): %w", pkcs8Err)
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

// ToPFXInRoot is ToPFX with the atomic write confined to root's tree, so a
// symlink planted under the output directory cannot redirect the
// private-key-bearing PFX outside it. rel is resolved relative to root.
func ToPFXInRoot(ctx context.Context, privKey crypto.PrivateKey, leaf *x509.Certificate, caCerts []*x509.Certificate, root *os.Root, rel, password string, enc *pkcs12.Encoder) error {
	pfxData, err := enc.Encode(privKey, leaf, caCerts, password)
	if err != nil {
		return fmt.Errorf("encode pfx: %w", err)
	}

	if _, err := atomicfile.WriteFileInRoot(ctx, root, rel, pfxData,
		atomicfile.WithMode(0o600),
	); err != nil {
		return fmt.Errorf("write pfx: %w", err)
	}
	return nil
}
