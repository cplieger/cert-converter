package convert

import (
	"context"
	"crypto"
	"os"
)

// PairInRoot resolves an already-read cert chain and private key into an
// identity, chain and key, then writes the PFX under outRoot, so a symlink
// planted under the output directory cannot redirect the private-key-bearing PFX
// outside the mounted volume. rel is resolved relative to outRoot. The caller
// reads the PEM bytes once (see process's scanWalk.readPair, which reads them
// through the confined *os.Root); PairInRoot performs no file reads. The encoder
// profile is named with the app-owned EncoderType and resolved here, so the
// go-pkcs12 vendor type stays confined to this package.
//
// It is a thin adapter over Analyse: Analyse owns every decision about WHICH
// certificate and key form the pair, and this function owns only the encode and
// the confined write. The returned observations are non-fatal findings about the
// input (a reordered bundle, a multi-key file, excluded certificates) that the
// caller should log; they are returned even when the write fails, because they
// describe the input rather than the outcome.
func PairInRoot(ctx context.Context, certPEM, keyPEM []byte, outRoot *os.Root, rel, password string, encName EncoderType) ([]Observation, error) {
	analysis, err := Analyse(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	err = toPFXInRoot(ctx, analysis.Key, analysis.Leaf, analysis.Chain, outRoot, rel, password, encoderFor(encName))
	return analysis.Observations, err
}

// maxSubjectLogLen bounds the certificate-controlled subject interpolated into a
// diagnostic. The subject is parsed out of a PEM file the app does not control
// and is capped only by MaxFileSize (10 MB), so an unbounded interpolation puts a
// multi-megabyte line into the logs of every scan that retries the pair.
const maxSubjectLogLen = 256

// boundSubject truncates a certificate subject to maxSubjectLogLen bytes for a
// log-bound diagnostic, dropping the partial rune the cut may leave behind so
// the %q form stays readable. It is a named alias for the package's shared
// boundLogText rule.
func boundSubject(subject string) string {
	return boundLogText(subject, maxSubjectLogLen)
}

// publicKeyMatches reports whether pub is the public half of signer's private
// key. supported is false when pub's type does not provide the
// Equal(crypto.PublicKey) bool method every crypto/x509 public key type
// implements, in which case matched carries no meaning and the caller must treat
// the key type as unverifiable rather than as a mismatch.
func publicKeyMatches(pub crypto.PublicKey, signer crypto.Signer) (matched, supported bool) {
	matcher, ok := pub.(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return false, false
	}
	return matcher.Equal(signer.Public()), true
}
