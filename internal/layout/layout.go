// Package layout owns cert-converter's naming contract: a source is either a
// PEM pair (<stem>.crt with its sibling <stem>.key) or a PKCS#12 bundle
// (<stem>.pfx or <stem>.p12), and each enabled output format derives its
// artifact names from the same stem — <stem>.pfx for PFX, <stem>.crt and
// <stem>.key for PEM.
package layout

import (
	"path"
	"slices"
	"strings"

	"github.com/cplieger/cert-converter/internal/outputpolicy"
)

// File extensions of the naming contract.
const (
	// certExt is the extension of a certificate chain, PEM-encoded: an input
	// source, and the certificate half of the PEM output format.
	certExt = ".crt"
	// keyExt is the extension of the sibling private key, PEM-encoded.
	keyExt = ".key"
	// pfxExt is the extension of a PKCS#12 bundle: the PFX output format, and an
	// input source.
	pfxExt = ".pfx"
	// p12Ext is the alternate bundle extension accepted on the input side only;
	// outputs always use pfxExt.
	p12Ext = ".p12"
)

// IsCert reports whether name is a PEM certificate — the certificate half of an
// input pair.
func IsCert(name string) bool {
	return strings.HasSuffix(name, certExt)
}

// IsBundle reports whether name is a PKCS#12 bundle source.
func IsBundle(name string) bool {
	return strings.HasSuffix(name, pfxExt) || strings.HasSuffix(name, p12Ext)
}

// IsSource reports whether name is something a scan converts FROM: a
// certificate or a bundle.
func IsSource(name string) bool {
	return IsCert(name) || IsBundle(name)
}

// IsKey reports whether name is a PEM private key — the key half of an input
// pair, and the PEM output format's key artifact.
func IsKey(name string) bool {
	return strings.HasSuffix(name, keyExt)
}

// KeyStem returns a key path without its extension: the stem its pair
// certificate and artifacts share.
func KeyStem(keyPath string) string {
	return strings.TrimSuffix(keyPath, keyExt)
}

// IsRelevant reports whether name participates in conversion at all: either
// half of a pair, or a bundle.
func IsRelevant(name string) bool {
	return IsSource(name) || IsKey(name)
}

// SourceStem returns rel without its source extension: the shared prefix every
// sibling and artifact name is derived from.
func SourceStem(rel string) string {
	for _, ext := range [...]string{certExt, pfxExt, p12Ext} {
		if stem, ok := strings.CutSuffix(rel, ext); ok {
			return stem
		}
	}
	return rel
}

// KeyFor returns the sibling private-key path for a certificate path.
func KeyFor(certPath string) string {
	return strings.TrimSuffix(certPath, certExt) + keyExt
}

// CertFor returns the pair-certificate path for a stem — the sibling whose
// presence gives a pair precedence over a bundle with the same stem.
func CertFor(stem string) string {
	return stem + certExt
}

// PFXOutFor returns the PKCS#12 artifact name for an output stem.
func PFXOutFor(stem string) string { return stem + pfxExt }

// CertOutFor returns the PEM format's certificate artifact name.
func CertOutFor(stem string) string { return stem + certExt }

// KeyOutFor returns the PEM format's private-key artifact name.
func KeyOutFor(stem string) string { return stem + keyExt }

// FlatStem maps a source stem into the flat output namespace: the stem's own
// directory name plus its base, everything above dropped. Idempotent: a stem
// already in the flat namespace maps to itself.
func FlatStem(stem string) string {
	if stem == "" {
		return ""
	}
	if withoutSlash, ok := strings.CutSuffix(stem, "/"); ok {
		return path.Base(withoutSlash) + "/"
	}
	dir := path.Dir(stem)
	if dir == "." {
		return path.Base(stem)
	}
	return path.Join(path.Base(dir), path.Base(stem))
}

// FlatProducible reports whether an output-relative path is one the flat
// layout can produce at all: FlatStem keeps at most one directory level, so
// anything nested deeper was laid out by the mirror layout.
func FlatProducible(outRel string) bool {
	return strings.Count(outRel, "/") <= 1
}

// IsOutputShape reports whether name is an artifact the CONFIGURED formats
// produce — the own-shape predicate behind every orphan decision, scoped to the
// enabled set so a format switched off leaves its old artifacts untouched.
func IsOutputShape(name string, f outputpolicy.Formats) bool {
	if f.PFX && strings.HasSuffix(name, pfxExt) {
		return true
	}
	return f.PEM && (strings.HasSuffix(name, certExt) || strings.HasSuffix(name, keyExt))
}

// OutputStem returns an artifact path without its artifact extension.
func OutputStem(outRel string) string {
	for _, ext := range [...]string{pfxExt, certExt, keyExt} {
		if stem, ok := strings.CutSuffix(outRel, ext); ok {
			return stem
		}
	}
	return outRel
}

// SourceCandidates returns every input path that would, under the mirror
// layout, produce artifacts at this stem — the reap re-check set.
func SourceCandidates(stem string) []string {
	return []string{stem + certExt, stem + pfxExt, stem + p12Ext}
}

// ShadowingSiblings returns the sibling source paths that outrank rel when both
// exist: the PEM pair's certificate for any bundle, and the .pfx spelling for a
// .p12 one. Precedence keeps two sources from producing one artifact set.
func ShadowingSiblings(rel string) []string {
	stem := SourceStem(rel)
	shadows := []string{CertFor(stem)}
	if strings.HasSuffix(rel, p12Ext) {
		shadows = append(shadows, stem+pfxExt)
	}
	return shadows
}

// ArtifactsFor returns the artifact names the enabled formats derive from one
// output stem, in the domain's order.
func ArtifactsFor(outStem string, f outputpolicy.Formats) []string {
	artifacts := make([]string, 0, 3)
	if f.PFX {
		artifacts = append(artifacts, PFXOutFor(outStem))
	}
	if f.PEM {
		artifacts = append(artifacts, CertOutFor(outStem), KeyOutFor(outStem))
	}
	return artifacts
}

// ExcludeSet is the set of input paths the operator has declared are not this
// app's to convert. A member is a root-relative path naming either one file or
// one directory; a directory covers everything beneath it.
//
// An excluded path is NOT the same as an absent one, and not the same as an
// unreadable one. The scan still enumerates it and still registers the
// artifacts it would produce, so orphan reconciliation keeps protecting those
// artifacts; only the conversion is skipped. That is what stops a mistyped
// exclusion from turning into a deletion, since nothing else guards a partial
// exclusion the way the empty-tree veto guards a wrong mount.
type ExcludeSet struct {
	paths []string
}

// NewExcludeSet builds the set from already-validated root-relative paths
// (internal/config owns the validation and its diagnostics). Entries are
// cleaned and sorted so the startup record and every match are deterministic.
func NewExcludeSet(paths []string) ExcludeSet {
	if len(paths) == 0 {
		return ExcludeSet{}
	}
	cleaned := make([]string, 0, len(paths))
	for _, p := range paths {
		normalized := path.Clean(p)
		if normalized == "" || normalized == "." || slices.Contains(cleaned, normalized) {
			continue
		}
		cleaned = append(cleaned, normalized)
	}
	slices.Sort(cleaned)
	return ExcludeSet{paths: cleaned}
}

// Empty reports whether the set excludes nothing, so a caller can skip the
// per-entry work entirely.
func (e ExcludeSet) Empty() bool { return len(e.paths) == 0 }

// Excludes reports whether rel is excluded: it matches a member exactly, or it
// sits beneath a member directory.
func (e ExcludeSet) Excludes(rel string) bool {
	target := path.Clean(rel)
	for _, p := range e.paths {
		if target == p || strings.HasPrefix(target, p+"/") {
			return true
		}
	}
	return false
}

// Paths returns the cleaned members, for the composition root's startup record.
func (e ExcludeSet) Paths() []string { return slices.Clone(e.paths) }
