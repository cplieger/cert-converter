package convert

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"software.sslmate.com/src/go-pkcs12"
)

// Pair parses an already-read cert chain and private key, verifies the leaf
// certificate and key correspond, and writes the PFX to destPath. The caller
// reads the PEM bytes once (see process.Scanner.convertEntry, which reads them
// through the confined *os.Root); Pair performs no file reads.
func Pair(ctx context.Context, certPEM, keyPEM []byte, destPath, password string, enc *pkcs12.Encoder) error {
	leaf, caCerts, privKey, err := parseAndMatch(certPEM, keyPEM)
	if err != nil {
		return err
	}
	return ToPFX(ctx, privKey, leaf, caCerts, destPath, password, enc)
}

// PairInRoot is Pair with the PFX write confined to outRoot, so a symlink
// planted under the output directory cannot redirect the private-key-bearing
// PFX outside the mounted volume. rel is resolved relative to outRoot.
func PairInRoot(ctx context.Context, certPEM, keyPEM []byte, outRoot *os.Root, rel, password string, enc *pkcs12.Encoder) error {
	leaf, caCerts, privKey, err := parseAndMatch(certPEM, keyPEM)
	if err != nil {
		return err
	}
	return ToPFXInRoot(ctx, privKey, leaf, caCerts, outRoot, rel, password, enc)
}

// parseAndMatch parses an already-read cert chain and private key and verifies
// that the leaf certificate's public key corresponds to the private key,
// returning the leaf, the remaining chain (the CA certificates, if any) and the
// key. It is the shared front half of Pair and PairInRoot and performs no file
// I/O.
func parseAndMatch(certPEM, keyPEM []byte) (leaf *x509.Certificate, caCerts []*x509.Certificate, privKey crypto.PrivateKey, err error) {
	chain, err := ParseCertChain(certPEM)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse cert chain: %w", err)
	}
	leaf = chain[0]
	if len(chain) > 1 {
		caCerts = chain[1:]
	}
	privKey, err = ParsePrivateKey(keyPEM)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse private key: %w", err)
	}
	signer, ok := privKey.(crypto.Signer)
	if !ok {
		return nil, nil, nil, fmt.Errorf("private key type %T does not implement crypto.Signer", privKey)
	}
	matcher, ok := leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return nil, nil, nil, fmt.Errorf("leaf certificate public key type %T cannot be verified against the private key", leaf.PublicKey)
	}
	if !matcher.Equal(signer.Public()) {
		return nil, nil, nil, errors.New("leaf certificate public key does not match the private key")
	}
	return leaf, caCerts, privKey, nil
}
