// Package layout owns cert-converter's naming contract: a certificate is
// <stem>.crt, its private key is the sibling <stem>.key, and the bundle
// converted from the pair is <stem>.pfx.
package layout

import "strings"

// File extensions of the naming contract.
const (
	// certExt is the extension of an input certificate chain, PEM-encoded.
	certExt = ".crt"
	// keyExt is the extension of the sibling private key, PEM-encoded.
	keyExt = ".key"
	// pfxExt is the extension of the converted PKCS#12 bundle.
	pfxExt = ".pfx"
)

// IsCert reports whether name is an input certificate — the entries a scan
// converts from.
func IsCert(name string) bool {
	return strings.HasSuffix(name, certExt)
}

// IsRelevant reports whether name participates in conversion at all, as either
// half of a pair.
func IsRelevant(name string) bool {
	return IsCert(name) || strings.HasSuffix(name, keyExt)
}

// IsOutput reports whether name is a converted bundle.
func IsOutput(name string) bool {
	return strings.HasSuffix(name, pfxExt)
}

// CertForOutput is the REVERSE of OutputFor: the certificate path that would have
// produced this bundle.
func CertForOutput(pfxPath string) string {
	return strings.TrimSuffix(pfxPath, pfxExt) + certExt
}

// KeyFor returns the sibling private-key path for a certificate path.
func KeyFor(certPath string) string {
	return stem(certPath) + keyExt
}

// OutputFor returns the PKCS#12 output path for a certificate path.
func OutputFor(certPath string) string {
	return stem(certPath) + pfxExt
}

// stem returns certPath without its certificate extension: the shared prefix
// from which both sibling names are derived.
func stem(certPath string) string {
	return strings.TrimSuffix(certPath, certExt)
}
