// Package layout owns cert-converter's naming contract: a certificate is
// <stem>.crt, its private key is the sibling <stem>.key, and the bundle
// converted from the pair is <stem>.pfx.
//
// It is a package rather than a helper inside internal/process because two
// packages need the same rule for different reasons: internal/process derives
// sibling and output paths while walking the input tree, and internal/watch
// decides whether a filesystem event is worth a rescan at all. Encoding the rule
// in either one would force the wrong dependency direction (watch importing
// process, or process importing watch) and the alternative — a copy in each —
// is what this package replaces: the two copies had already drifted in scope,
// with process distinguishing "is a certificate" from "is a certificate or key"
// while watch collapsed both into one predicate.
//
// Every function here is pure and depends on nothing outside the standard
// library, so the contract can be tested as a whole without a filesystem.
package layout

import "strings"

// File extensions of the naming contract. They are exported so a caller that
// must name an extension in a log line or an error uses the same spelling the
// predicates match on, rather than a second literal that can drift.
const (
	// CertExt is the extension of an input certificate chain, PEM-encoded.
	CertExt = ".crt"
	// KeyExt is the extension of the sibling private key, PEM-encoded.
	KeyExt = ".key"
	// PFXExt is the extension of the converted PKCS#12 bundle.
	PFXExt = ".pfx"
)

// IsCert reports whether name is an input certificate — the entries a scan
// converts from. A private key alone is never a conversion trigger: it is
// reached through its certificate's stem, so a walk that acted on keys too would
// convert every pair twice.
func IsCert(name string) bool {
	return strings.HasSuffix(name, CertExt)
}

// IsRelevant reports whether name participates in conversion at all, as either
// half of a pair. It is deliberately wider than IsCert: a key changing on its
// own (a rotation that writes the key before the certificate) must still trigger
// a rescan, even though the scan itself is driven by certificates.
func IsRelevant(name string) bool {
	return IsCert(name) || strings.HasSuffix(name, KeyExt)
}

// IsOutput reports whether name is a converted bundle.
func IsOutput(name string) bool {
	return strings.HasSuffix(name, PFXExt)
}

// CertForOutput is the REVERSE of OutputFor: the certificate path that would have
// produced this bundle.
//
// It lives here so both directions of the contract have one home. A caller
// reconciling the output tree against the input tree needs the reverse mapping,
// and deriving it locally with its own TrimSuffix is exactly the drift this
// package exists to prevent — the forward and reverse rules could then disagree
// about a name and a live bundle would read as an orphan.
//
// The argument must satisfy IsOutput; the same precondition reasoning as KeyFor
// applies.
func CertForOutput(pfxPath string) string {
	return strings.TrimSuffix(pfxPath, PFXExt) + CertExt
}

// KeyFor returns the sibling private-key path for a certificate path.
//
// The argument must satisfy IsCert; callers reach this only after a walk or an
// event classifier has established that. Passing a non-certificate path returns
// the input with KeyExt appended rather than an error, because there is no
// production path that can do so and an error return would put an impossible
// branch in every call site.
func KeyFor(certPath string) string {
	return stem(certPath) + KeyExt
}

// OutputFor returns the PKCS#12 output path for a certificate path. It preserves
// any directory prefix, so the output tree mirrors the input tree's shape rather
// than flattening it. The same precondition as KeyFor applies.
func OutputFor(certPath string) string {
	return stem(certPath) + PFXExt
}

// stem returns certPath without its certificate extension: the shared prefix
// from which both sibling names are derived. Unexported because every caller
// wants one of the derived names, never the stem itself, and keeping it internal
// means the three names can only ever be derived one way.
func stem(certPath string) string {
	return strings.TrimSuffix(certPath, CertExt)
}
