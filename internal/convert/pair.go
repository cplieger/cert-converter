package convert

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// PairInRoot parses an already-read cert chain and private key, verifies the
// leaf certificate and key correspond, and writes the PFX under outRoot, so a
// symlink planted under the output directory cannot redirect the
// private-key-bearing PFX outside the mounted volume. rel is resolved relative
// to outRoot. The caller reads the PEM bytes once (see process's
// scanWalk.convertEntry, which reads them through the confined *os.Root);
// PairInRoot performs no file reads. The encoder profile is named with the
// app-owned EncoderType and resolved here, so the go-pkcs12 vendor type stays
// confined to this package.
func PairInRoot(ctx context.Context, certPEM, keyPEM []byte, outRoot *os.Root, rel, password string, encName EncoderType) error {
	leaf, caCerts, privKey, err := parseAndMatch(certPEM, keyPEM)
	if err != nil {
		return err
	}
	return toPFXInRoot(ctx, privKey, leaf, caCerts, outRoot, rel, password, EncoderFor(encName))
}

// parseAndMatch parses an already-read cert chain and private key and verifies
// that the leaf certificate's public key corresponds to the private key,
// returning the leaf, the remaining chain (the CA certificates, if any) and the
// key. It is the front half of PairInRoot and performs no file I/O.
func parseAndMatch(certPEM, keyPEM []byte) (leaf *x509.Certificate, caCerts []*x509.Certificate, privKey crypto.PrivateKey, err error) {
	chain, err := parseCertChain(certPEM)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse cert chain: %w", err)
	}
	leaf = chain[0]
	if len(chain) > 1 {
		caCerts = chain[1:]
	}
	privKey, err = parsePrivateKey(keyPEM)
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
		return nil, nil, nil, leafKeyMismatchError(chain, signer)
	}
	return leaf, caCerts, privKey, nil
}

// leafKeyMismatchError builds the leaf/key mismatch error. When a LATER
// certificate in the chain does match the private key, the chain was
// concatenated with the leaf last (a CA bundle pasted root-first is the common
// cause), so the error names that instead of leaving the operator to inspect a
// key file that is in fact correct. The base sentence is kept as the prefix so
// existing log matching is unaffected.
func leafKeyMismatchError(chain []*x509.Certificate, signer crypto.Signer) error {
	const base = "leaf certificate public key does not match the private key"
	for i, c := range chain[1:] {
		matcher, ok := c.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
		if ok && matcher.Equal(signer.Public()) {
			return fmt.Errorf(
				"%s; certificate %d of %d (subject %q) does match, so the chain is ordered leaf-last: concatenate it leaf-first",
				base, i+2, len(chain), c.Subject.String())
		}
	}
	return errors.New(base)
}
