package convert

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// timeNow is the clock the renewed-certificate tie-break consults. It is a
// package var solely so tests can pin a scan time; nothing else in this package
// reads the clock, and every other part of Analyse is a pure function of its
// input bytes.
var timeNow = time.Now

// ObservationKind classifies a non-fatal fact Analyse noticed about its input.
//
// Observations exist because "is this input usable?" and "was this input what
// the operator intended?" are different questions. Folding them into one error
// return left an odd-but-convertible input only two possible fates: rejected, or
// silently accepted with no record. A misordered chain is the canonical case —
// it converts correctly, and the operator should still hear about it.
type ObservationKind string

// The observations Analyse can emit. Each names a condition that is legal and
// convertible but worth an operator's attention.
const (
	// ObsLeafNotFirst reports that the end-entity certificate was not the first
	// block in the input. Common cause: a CA bundle pasted root-first.
	ObsLeafNotFirst ObservationKind = "leaf-not-first"
	// ObsMultipleKeys reports that the key file held more than one distinct key,
	// which happens mid-rotation when a new key is appended to the old one.
	ObsMultipleKeys ObservationKind = "multiple-keys"
	// ObsDuplicateCerts reports byte-identical certificates in the input, a
	// copy-paste artefact rather than an error.
	ObsDuplicateCerts ObservationKind = "duplicate-certs"
	// ObsExtraCertsExcluded reports certificates that are not ancestors of the
	// selected identity and were therefore kept out of the bundle.
	ObsExtraCertsExcluded ObservationKind = "extra-certs-excluded"
	// ObsRenewedCertTie reports that one key matched several certificates and
	// names which was selected.
	ObsRenewedCertTie ObservationKind = "renewed-cert-tie"
	// ObsCAAsIdentity reports that the selected identity asserts IsCA. Legal (a
	// self-signed CA can serve as an identity) but unusual enough to surface.
	ObsCAAsIdentity ObservationKind = "ca-as-identity"
	// ObsChainUnverified reports that no issuer for the selected identity could be
	// established from the bundle, so the remaining certificates were included
	// as-is rather than dropped.
	ObsChainUnverified ObservationKind = "chain-unverified"
	// ObsIdentityNotYetValid reports a selected identity whose NotBefore is in
	// the future. Conversion still proceeds; consumers will reject it.
	ObsIdentityNotYetValid ObservationKind = "identity-not-yet-valid"
	// ObsIdentityExpired reports a selected identity past its NotAfter.
	// Conversion still proceeds: migrating an expired certificate is legitimate.
	ObsIdentityExpired ObservationKind = "identity-expired"
)

// Observation is one non-fatal finding about the input. Detail is already bounded
// for logging, so a caller may emit it directly without re-truncating
// certificate-controlled text.
type Observation struct {
	Kind   ObservationKind
	Detail string
}

// Analysis is the resolved result of reading a certificate bundle and a key
// file: which certificate is the identity, which private key belongs to it,
// which certificates form its chain and in what order, and which were left out.
type Analysis struct {
	// Leaf is the end-entity certificate the PFX is built around.
	Leaf *x509.Certificate
	// Chain holds Leaf's ancestors, ordered nearest-parent-first. PKCS#12 stores
	// an ordered SEQUENCE of bags and decoders read it positionally (go-pkcs12's
	// own decoder assumes the first certificate is the leaf), so this order is a
	// contract rather than an implementation detail.
	Chain []*x509.Certificate
	// Key is the private half of Leaf.
	Key crypto.PrivateKey
	// Extra holds certificates that parsed but are not ancestors of Leaf. They
	// are deliberately excluded from the bundle: embedding an unrelated CA
	// pollutes the trust chain the consumer sees.
	Extra []*x509.Certificate
	// Observations are non-fatal findings, in the order discovered.
	Observations []Observation
}

// Analyse resolves a certificate bundle and a key file into the identity, chain
// and key a PKCS#12 bundle needs. It performs no I/O.
//
// Identity selection is key-first and structural, never positional. The private
// key is matched against every certificate in the bundle, and the certificate it
// matches is the identity wherever it appeared in the file. That is what makes
// misordered input and multi-key input resolvable rather than merely tolerated:
// the key is evidence, so there is nothing left to guess.
//
// Deliberate non-goal: validity periods are never a gate. This package converts,
// it does not validate. An expired certificate still converts (an operator
// migrating one is a legitimate case); validity is consulted only to break a tie
// between certificates that share a key, and an out-of-window identity produces
// an observation, not an error.
//
// Invariant: whichever certificate is selected, its public key provably matches
// the returned private key, so the bundle is internally consistent by
// construction.
func Analyse(certPEM, keyPEM []byte) (Analysis, error) {
	certs, err := parseCertChain(certPEM)
	if err != nil {
		return Analysis{}, fmt.Errorf("parse cert chain: %w", err)
	}
	keys, err := parsePrivateKeys(keyPEM)
	if err != nil {
		return Analysis{}, fmt.Errorf("parse private key: %w", err)
	}

	// One clock read for the whole analysis. Ranking and the validity
	// observations must agree with each other, and a comparator that re-reads
	// the time can stop being transitive mid-reduction.
	now := timeNow()

	var obs []Observation

	certs, dupCerts := dedupeCerts(certs)
	if dupCerts > 0 {
		obs = append(obs, Observation{
			Kind:   ObsDuplicateCerts,
			Detail: fmt.Sprintf("%d duplicate certificate block(s) ignored", dupCerts),
		})
	}

	signers, nonSigners := splitSigners(keys)
	if len(signers) == 0 {
		return Analysis{}, unusableKeyError(nonSigners)
	}
	signers = dedupeSigners(signers)
	if len(signers) > 1 {
		obs = append(obs, Observation{
			Kind:   ObsMultipleKeys,
			Detail: fmt.Sprintf("%d distinct private key(s) in the key file", len(signers)),
		})
	}

	g := newCertGraph(certs, now)

	identity, tieObs, err := g.selectIdentity(signers)
	if err != nil {
		return Analysis{}, err
	}
	obs = append(obs, tieObs...)

	leaf := certs[identity.cert]

	// Role check. A certificate that signed another certificate in this bundle
	// is an issuer, not an end-entity certificate, and emitting it as the
	// identity would produce a bundle no consumer can use as a server identity.
	// This is the case a positional "leaf = certs[0]" rule cannot see.
	if g.isIssuer(identity.cert) {
		return Analysis{}, fmt.Errorf(
			"the private key matches %q, which is an issuer of another certificate in this bundle, not an end-entity certificate; if you meant to export that CA itself, remove the certificates it issued from the bundle",
			boundSubject(leaf.Subject.String()))
	}
	if leaf.BasicConstraintsValid && leaf.IsCA {
		obs = append(obs, Observation{
			Kind:   ObsCAAsIdentity,
			Detail: fmt.Sprintf("selected identity %q asserts IsCA", boundSubject(leaf.Subject.String())),
		})
	}

	if identity.cert != 0 {
		obs = append(obs, Observation{
			Kind: ObsLeafNotFirst,
			Detail: fmt.Sprintf("the end-entity certificate is block %d of %d, not the first; the bundle was reordered leaf-first",
				identity.cert+1, len(certs)),
		})
	}
	obs = append(obs, validityObservations(leaf, now)...)

	chain, extra, chainObs := g.assembleChain(identity.cert, leaf)
	obs = append(obs, chainObs...)

	return Analysis{
		Leaf:         leaf,
		Chain:        chain,
		Key:          signers[identity.key],
		Extra:        extra,
		Observations: obs,
	}, nil
}

// identityMatch names one (key, certificate) pair whose public halves agree, by
// index into the deduped key and certificate slices.
type identityMatch struct {
	key  int
	cert int
}

// certGraph holds the certificates plus the issuance relationships derived from
// them, in TWO sets of differing strength, plus how far each certificate is from
// a self-signed root present in the bundle.
type certGraph struct {
	now   time.Time
	certs []*x509.Certificate
	// verifiedParents[i]: indices whose signature over certs[i] VERIFIED. The
	// strong signal, used for the issuer role rejection — a hard failure, so it
	// must rest on proof rather than resemblance.
	verifiedParents [][]int
	// candidateParents[i]: indices that are plausibly issuers of certs[i], by key
	// identifier or by issuer/subject name, whether or not a signature could be
	// verified. The inclusive signal, used to assemble the emitted chain, where
	// over-including costs one stray certificate and under-including silently
	// breaks path building at the consumer.
	//
	// The sets diverge for causes unrelated to the chain being wrong: Go refuses
	// to verify a SHA-1 signature at all (no x509sha1 GODEBUG remains in
	// go1.26), and RFC 5280 permits issuer and subject names to be encoded
	// differently in ways a byte comparison rejects. Treating "could not prove
	// related" as "proved unrelated" is what dropped genuine CA certificates the
	// previous positional code shipped.
	candidateParents [][]int
	children         [][]int
	issuer           []bool
	distToRoot       []int
}

// newCertGraph derives both issuance edge sets.
//
// Signature verification via x509.CheckSignatureFrom is CRYPTOGRAPHIC PARENT
// EVIDENCE WITH LIMITED CA GATING, not path validation. Go documents it as
// performing "very limited checks" and explicitly not being a full path verifier.
// It does NOT check validity periods, path length, name constraints, EKU nesting,
// unhandled critical extensions, or revocation; a certificate whose KeyUsage is
// zero passes its CertSign check; and a v1/v2 certificate with no
// basic-constraints extension is not rejected by its IsCA check. Identity role is
// therefore enforced separately, by Analyse's own issuer check, and that check
// reads only the verified set.
func newCertGraph(certs []*x509.Certificate, now time.Time) *certGraph {
	g := &certGraph{
		now:              now,
		certs:            certs,
		verifiedParents:  make([][]int, len(certs)),
		candidateParents: make([][]int, len(certs)),
		children:         make([][]int, len(certs)),
		issuer:           make([]bool, len(certs)),
		distToRoot:       make([]int, len(certs)),
	}
	for child := range certs {
		for parent := range certs {
			if child == parent || !g.plausibleIssuer(child, parent) {
				continue
			}
			g.candidateParents[child] = append(g.candidateParents[child], parent)
			g.children[parent] = append(g.children[parent], child)
			if certs[child].CheckSignatureFrom(certs[parent]) == nil {
				g.verifiedParents[child] = append(g.verifiedParents[child], parent)
				g.issuer[parent] = true
			}
		}
	}
	g.computeDistances()
	return g
}

// plausibleIssuer reports whether certs[parent] could be the issuer of
// certs[child], on the evidence available without cryptography.
//
// Two independent signals, either sufficient. Issuer/subject name chaining is the
// ordinary one. A key-identifier match (RFC 5280's Authority Key Identifier
// against the candidate's Subject Key Identifier) is the one that survives a
// permitted name-encoding difference, and it is a byte comparison rather than a
// signature check, so it is algorithm-agnostic and keeps working for algorithms
// Go declines to verify.
//
// The key-reuse exclusion is not cosmetic. Two DISTINCT self-signed certificates
// sharing a subject AND a public key — a regenerated self-signed certificate left
// beside the one it replaces, which `openssl req -x509` produces with
// basicConstraints CA:TRUE by default — each verify against the other, so a naive
// rule records a mutual issuance edge, both then look like issuers, and the role
// check rejects the identity outright. Key reuse is not issuance: a certificate
// cannot have issued another certificate carrying its own key.
func (g *certGraph) plausibleIssuer(child, parent int) bool {
	c, p := g.certs[child], g.certs[parent]
	if bytes.Equal(c.RawSubject, p.RawSubject) && samePublicKey(c.PublicKey, p.PublicKey) {
		return false
	}
	if len(c.AuthorityKeyId) > 0 && len(p.SubjectKeyId) > 0 &&
		bytes.Equal(c.AuthorityKeyId, p.SubjectKeyId) {
		return true
	}
	return bytes.Equal(c.RawIssuer, p.RawSubject)
}

// isIssuer reports whether certs[i] verifiably signed another certificate here.
func (g *certGraph) isIssuer(i int) bool { return g.issuer[i] }

// isSelfSigned reports whether certs[i] is its own issuer, which is what makes it
// a root rather than a link.
//
// It verifies the signature with the certificate's OWN public key rather than
// calling CheckSignatureFrom(self). That distinction is load-bearing:
// CheckSignatureFrom rejects any v3 certificate acting as a parent when
// BasicConstraintsValid is false (crypto/x509), and a plain self-signed server
// certificate — the shape `openssl req -x509` produces without CA flags, and the
// shape most test fixtures use — sets no basic constraints at all. Routing through
// CheckSignatureFrom therefore reported every non-CA self-signed certificate as
// NOT self-signed, which both lost it as a root for the distance walk and made
// the additive-only chain fallback fire on inputs whose empty chain was correct.
//
// CA-ness is irrelevant to the question asked here: a self-signed end-entity
// certificate is still self-signed.
func (g *certGraph) isSelfSigned(i int) bool {
	c := g.certs[i]
	if !bytes.Equal(c.RawSubject, c.RawIssuer) {
		return false
	}
	return c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

// computeDistances fills distToRoot with the fewest parent hops from each
// certificate to a self-signed certificate in this bundle, or -1 when none is
// reachable.
//
// It is a multi-source breadth-first walk DOWNWARD from every root over the
// children edges. The obvious alternative — a memoised depth-first walk upward
// with an on-path cycle guard — is subtly wrong, and both adversarial reviews
// reproduced the failure: the guard's -1 gets memoised for a node that was merely
// FORBIDDEN on the current path, not genuinely unreachable, so a bundle
// containing a cross-certification loop yields distances that depend on the order
// certificates appeared in the file. Cycles are real: RFC 4158 describes mesh
// PKIs with bidirectional cross-certification, and RFC 5280 permits several
// certificates for one CA name. BFS from the roots has no path state to leak, so
// it is cycle-safe and order-independent by construction.
func (g *certGraph) computeDistances() {
	for i := range g.certs {
		g.distToRoot[i] = -1
	}
	queue := make([]int, 0, len(g.certs))
	for i := range g.certs {
		if g.isSelfSigned(i) {
			g.distToRoot[i] = 0
			queue = append(queue, i)
		}
	}
	for head := 0; head < len(queue); head++ {
		cur := queue[head]
		for _, child := range g.children[cur] {
			if g.distToRoot[child] != -1 {
				continue // already reached by an equal-or-shorter route
			}
			g.distToRoot[child] = g.distToRoot[cur] + 1
			queue = append(queue, child)
		}
	}
}

// selectIdentity resolves which certificate and key form the identity, matching
// every key against every certificate rather than against a positional guess.
func (g *certGraph) selectIdentity(signers []crypto.Signer) (identityMatch, []Observation, error) {
	matches, firstUnverifiable := g.collectMatches(signers)
	switch len(matches) {
	case 0:
		return identityMatch{}, nil, g.noMatchError(len(signers), firstUnverifiable)
	case 1:
		return matches[0], nil, nil
	default:
		return g.resolveAmbiguousMatches(matches)
	}
}

// collectMatches pairs every key with every certificate whose public half it
// owns. firstUnverifiable is the index of the first certificate whose public key
// type crypto/x509 could not parse, or -1: that is a different failure from a
// mismatch, and the operator needs to hear the algorithm is unsupported rather
// than that the key is wrong.
func (g *certGraph) collectMatches(signers []crypto.Signer) (matches []identityMatch, firstUnverifiable int) {
	firstUnverifiable = -1
	for ki, s := range signers {
		for ci, c := range g.certs {
			matched, supported := publicKeyMatches(c.PublicKey, s)
			if !supported {
				if firstUnverifiable == -1 {
					firstUnverifiable = ci
				}
				continue
			}
			if matched {
				matches = append(matches, identityMatch{key: ki, cert: ci})
			}
		}
	}
	return matches, firstUnverifiable
}

// noMatchError explains that no certificate here belongs to any supplied key,
// naming an unverifiable key algorithm ahead of a plain mismatch because it is
// the more specific diagnosis.
func (g *certGraph) noMatchError(keyCount, firstUnverifiable int) error {
	if firstUnverifiable >= 0 {
		c := g.certs[firstUnverifiable]
		return fmt.Errorf(
			"certificate %q has a public key of type %T that cannot be verified against the private key",
			boundSubject(c.Subject.String()), c.PublicKey)
	}
	return fmt.Errorf(
		"none of the %d private key block(s) matches any of the %d certificate(s) in the chain",
		keyCount, len(g.certs))
}

// resolveAmbiguousMatches rules on more than one (key, certificate) match.
//
// Distinct keys matching distinct certificates means the input carries several
// identities, which cannot be expressed as one PFX. One key matching several
// certificates is a renewed certificate reusing its key: prefer one that is
// usable now, then the newest. Ranking purely on NotBefore would prefer a
// future-dated renewal over a currently valid certificate, producing a bundle no
// consumer will accept yet.
func (g *certGraph) resolveAmbiguousMatches(matches []identityMatch) (identityMatch, []Observation, error) {
	firstKey := matches[0].key
	for _, m := range matches[1:] {
		if m.key != firstKey {
			return identityMatch{}, nil, fmt.Errorf(
				"the input contains %d distinct certificate/key identities; this app converts one certificate/key pair per output",
				countDistinctKeys(matches))
		}
	}

	best := matches[0]
	for _, m := range matches[1:] {
		if g.betterIdentity(m.cert, best.cert) {
			best = m
		}
	}
	return best, []Observation{{
		Kind: ObsRenewedCertTie,
		Detail: fmt.Sprintf("one private key matches %d certificates; selected %q (NotBefore %s)",
			len(matches), boundSubject(g.certs[best.cert].Subject.String()),
			g.certs[best.cert].NotBefore.UTC().Format(time.RFC3339)),
	}}, nil
}

// betterIdentity ranks two certificates that share a private key: valid at scan
// time first, then the later NotBefore, then a byte comparison of the full
// certificate DER.
//
// The final key is the whole DER, not the subject. A renewal shares its
// predecessor's subject by definition, so a subject comparison is always 0 for
// exactly the inputs this comparator exists to rank; and NotBefore is
// second-granular, so two certificates minted in the same second tie there too.
// With both keys inert the fold degenerated to "first block in the file wins" —
// order-dependence in the one function whose headline claim is order invariance.
// Both adversarial reviews reproduced it. DER is a total order over distinct
// certificates, so ties are now impossible.
func (g *certGraph) betterIdentity(a, b int) bool {
	va, vb := validAt(g.certs[a], g.now), validAt(g.certs[b], g.now)
	if va != vb {
		return va
	}
	if !g.certs[a].NotBefore.Equal(g.certs[b].NotBefore) {
		return g.certs[a].NotBefore.After(g.certs[b].NotBefore)
	}
	return bytes.Compare(g.certs[a].Raw, g.certs[b].Raw) < 0
}

// pathFrom returns the chain from start upward, nearest parent first, as indices.
// The first element is start itself.
//
// At a branch point (a cross-signed certificate has more than one issuer here)
// the choice is deterministic: prefer a parent from which a self-signed root in
// this bundle is reachable, then the shorter route to that root, then the later
// NotAfter, then a byte comparison of the subject. One path is emitted rather
// than every ancestor, because a consumer reading the bag sequence positionally
// should see one coherent chain; alternatives land in Extra.
func (g *certGraph) pathFrom(start int) []int {
	path := []int{start}
	onPath := make([]bool, len(g.certs))
	onPath[start] = true
	for cur := start; ; {
		best := -1
		for _, p := range g.candidateParents[cur] {
			if onPath[p] {
				continue
			}
			if best == -1 || g.betterParent(p, best) {
				best = p
			}
		}
		if best == -1 {
			return path
		}
		path = append(path, best)
		onPath[best] = true
		cur = best
	}
}

// betterParent ranks two candidate issuers at a branch point.
//
// The final key is the full DER. A subject comparison would be useless here by
// construction: every candidate reached this point by matching the child's
// RawIssuer against its own RawSubject, so all candidates at one branch have
// identical subjects. RFC 5280 permits a CA to hold several certificates under
// one name, so real branches with equal distance and equal NotAfter exist, and
// with an inert final key the choice fell back to file order.
func (g *certGraph) betterParent(a, b int) bool {
	// Validity first. An expired issuer breaks the chain at the consumer no matter
	// how short its route to a root is, so ranking reachability or path length
	// ahead of validity could emit an unusable chain while a usable one sat in the
	// same input. That ordering was an oversight, not a decision.
	va, vb := validAt(g.certs[a], g.now), validAt(g.certs[b], g.now)
	if va != vb {
		return va
	}
	ra, rb := g.distToRoot[a] >= 0, g.distToRoot[b] >= 0
	if ra != rb {
		return ra
	}
	if ra && g.distToRoot[a] != g.distToRoot[b] {
		return g.distToRoot[a] < g.distToRoot[b]
	}
	if !g.certs[a].NotAfter.Equal(g.certs[b].NotAfter) {
		return g.certs[a].NotAfter.After(g.certs[b].NotAfter)
	}
	return bytes.Compare(g.certs[a].Raw, g.certs[b].Raw) < 0
}

// outsidePath returns the certificates not on path, in input order.
func (g *certGraph) outsidePath(path []int) []*x509.Certificate {
	on := make([]bool, len(g.certs))
	for _, i := range path {
		on[i] = true
	}
	var extra []*x509.Certificate
	for i, c := range g.certs {
		if !on[i] {
			extra = append(extra, c)
		}
	}
	return extra
}

// samePublicKey reports whether two certificate public keys are the same key.
// Used to tell KEY REUSE apart from issuance: a certificate holding the same
// public key as another cannot have issued it.
func samePublicKey(a, b crypto.PublicKey) bool {
	matcher, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return false
	}
	return matcher.Equal(b)
}

// assembleChain builds the emitted chain for the selected identity, the
// certificates deliberately left out of it, and the observations describing
// either outcome.
//
// The additive-only fallback lives here: if NO issuer for the identity could be
// established even on the inclusive edge signal, the remaining certificates are
// KEPT rather than dropped. The previous positional code shipped everything after
// the first block, and silently removing a CA a working deployment relied on is
// far worse than carrying one it did not need, so exclusion is reserved for
// certificates positively shown to sit off the chain.
//
// A SELF-SIGNED identity is excluded from the fallback: it has no issuer by
// construction, so an empty chain there is proof rather than a failure to prove,
// and anything else in the bundle genuinely is unrelated.
func (g *certGraph) assembleChain(identityCert int, leaf *x509.Certificate) (chain, extra []*x509.Certificate, obs []Observation) {
	path := g.pathFrom(identityCert)
	chain = make([]*x509.Certificate, 0, len(path)-1)
	for _, i := range path[1:] {
		chain = append(chain, g.certs[i])
	}
	extra = g.outsidePath(path)

	if len(chain) == 0 && len(extra) > 0 && !g.isSelfSigned(identityCert) {
		return extra, nil, []Observation{{
			Kind: ObsChainUnverified,
			Detail: fmt.Sprintf("no issuer of %q could be established from the bundle; the other %d certificate(s) were kept rather than dropped",
				boundSubject(leaf.Subject.String()), len(extra)),
		}}
	}

	if len(extra) > 0 {
		obs = append(obs, Observation{
			Kind: ObsExtraCertsExcluded,
			Detail: fmt.Sprintf("%d certificate(s) are not part of %q's chain and were excluded: %s",
				len(extra), boundSubject(leaf.Subject.String()), subjectsForLog(extra)),
		})
	}
	return chain, extra, obs
}

// validAt reports whether c is inside its validity window at now.
func validAt(c *x509.Certificate, now time.Time) bool {
	return !now.Before(c.NotBefore) && !now.After(c.NotAfter)
}

// validityObservations reports an identity outside its validity window. Never an
// error: conversion of an expired certificate is a supported migration case.
func validityObservations(leaf *x509.Certificate, now time.Time) []Observation {
	switch {
	case now.Before(leaf.NotBefore):
		return []Observation{{
			Kind: ObsIdentityNotYetValid,
			Detail: fmt.Sprintf("selected identity is not valid until %s",
				leaf.NotBefore.UTC().Format(time.RFC3339)),
		}}
	case now.After(leaf.NotAfter):
		return []Observation{{
			Kind: ObsIdentityExpired,
			Detail: fmt.Sprintf("selected identity expired at %s",
				leaf.NotAfter.UTC().Format(time.RFC3339)),
		}}
	}
	return nil
}

// dedupeCerts removes byte-identical certificates, keeping input order, and
// reports how many were dropped. A repeated certificate is a copy-paste artefact
// that would otherwise create a spurious self-edge candidate in the graph.
func dedupeCerts(certs []*x509.Certificate) (kept []*x509.Certificate, dropped int) {
	kept = make([]*x509.Certificate, 0, len(certs))
	for _, c := range certs {
		dup := false
		for _, k := range kept {
			if bytes.Equal(k.Raw, c.Raw) {
				dup = true
				break
			}
		}
		if dup {
			dropped++
			continue
		}
		kept = append(kept, c)
	}
	return kept, dropped
}

// splitSigners partitions parsed keys into those usable for identity matching
// and those whose type cannot be compared against a certificate's public key.
// Only a crypto.Signer exposes the public half, so a non-signer key can never be
// matched to a certificate.
func splitSigners(keys []crypto.PrivateKey) (signers []crypto.Signer, nonSigners []crypto.PrivateKey) {
	for _, k := range keys {
		if s, ok := k.(crypto.Signer); ok {
			signers = append(signers, s)
			continue
		}
		nonSigners = append(nonSigners, k)
	}
	return signers, nonSigners
}

// dedupeSigners removes keys with an identical public half, keeping input order.
// Two blocks holding the same key are one key.
func dedupeSigners(signers []crypto.Signer) []crypto.Signer {
	out := make([]crypto.Signer, 0, len(signers))
	for _, s := range signers {
		dup := false
		for _, kept := range out {
			if matched, supported := publicKeyMatches(kept.Public(), s); supported && matched {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, s)
		}
	}
	return out
}

// unusableKeyError explains that no parsed key can be matched to a certificate.
func unusableKeyError(nonSigners []crypto.PrivateKey) error {
	if len(nonSigners) == 1 {
		return fmt.Errorf("private key type %T does not implement crypto.Signer, so it cannot be matched against a certificate", nonSigners[0])
	}
	return errors.New("no parsed private key implements crypto.Signer, so none can be matched against a certificate")
}

// countDistinctKeys counts how many distinct key indices appear in matches.
func countDistinctKeys(matches []identityMatch) int {
	seen := make(map[int]struct{}, len(matches))
	for _, m := range matches {
		seen[m.key] = struct{}{}
	}
	return len(seen)
}

// subjectsForLog renders certificate subjects for a diagnostic, each bounded,
// capped in count so a bundle full of extras cannot produce an unbounded line.
func subjectsForLog(certs []*x509.Certificate) string {
	const maxNamed = 3
	var b bytes.Buffer
	for i, c := range certs {
		if i == maxNamed {
			fmt.Fprintf(&b, " and %d more", len(certs)-maxNamed)
			break
		}
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%q", boundSubject(c.Subject.String()))
	}
	return b.String()
}
