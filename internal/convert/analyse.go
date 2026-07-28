package convert

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"slices"
	"time"
)

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
	// ObsChainUnverified reports that no issuer of the certificate the discovered
	// path ended on could be established from the bundle, so the remaining
	// issuer-eligible certificates were included as-is rather than dropped.
	ObsChainUnverified ObservationKind = "chain-unverified"
	// ObsIdentityNotYetValid reports a selected identity whose NotBefore is in
	// the future. Conversion still proceeds; consumers will reject it.
	ObsIdentityNotYetValid ObservationKind = "identity-not-yet-valid"
	// ObsIdentityExpired reports a selected identity past its NotAfter.
	// Conversion still proceeds: migrating an expired certificate is legitimate.
	ObsIdentityExpired ObservationKind = "identity-expired"
	// ObsChainCertOutOfWindow reports a certificate in the EMITTED chain that is
	// outside its own validity window. Conversion still proceeds (validity is never
	// a gate here), but the bundle will fail path validation at the consumer and no
	// other signal names which link is at fault.
	ObsChainCertOutOfWindow ObservationKind = "chain-cert-out-of-window"
	// ObsUnrelatedBlocksSkipped reports PEM blocks in the CERTIFICATE file that are
	// neither a certificate nor a private key — an OpenSSL "TRUSTED CERTIFICATE",
	// the legacy "X509 CERTIFICATE" alias, a stray CERTIFICATE REQUEST — and were
	// therefore not part of the bundle. A private-key block is deliberately not
	// reported: a combined cert+key file is a supported input.
	ObsUnrelatedBlocksSkipped ObservationKind = "unrelated-blocks-skipped"
	// ObsUnusableKeyBlocksSkipped reports key blocks in the KEY file that yielded no
	// usable key — unparseable DER, armour encoding/pem could not decode, or
	// ciphertext — while another block did yield one, so conversion continued. The
	// canonical cause is a rotation that appended a damaged or encrypted key next to
	// the old one: the old key still matches today, and the only other signal is the
	// "no certificate matches any key" failure a later renewal produces.
	ObsUnusableKeyBlocksSkipped ObservationKind = "unusable-key-blocks-skipped"
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
// Its representation is deliberately opaque: the only thing a consumer outside
// this package needs from it is Observations, and everything else (the
// certificates, the private key, the chain order) is codec material whose shape
// is this package's business. Keeping the fields unexported is also what makes
// Analyse's invariant hold — no caller can swap the leaf, reorder the chain or
// null the key and hand the result back to Encode or CheckCurrency.
type Analysis struct {
	// leaf is the end-entity certificate the PFX is built around.
	leaf *x509.Certificate
	// chain holds leaf's ancestors, ordered nearest-parent-first. PKCS#12 stores
	// an ordered SEQUENCE of bags and decoders read it positionally (go-pkcs12's
	// own decoder assumes the first certificate is the leaf), so this order is a
	// contract rather than an implementation detail.
	//
	// One exception, always accompanied by ObsChainUnverified: when the issuer of
	// the certificate the discovered path ended on could not be established from
	// the bundle, chain carries the certificates whose ancestry IS established
	// first and the remaining issuer-eligible ones in INPUT order after them (a
	// certificate canIssueCertificates disqualifies is excluded instead, and
	// reported by ObsExtraCertsExcluded). There is no ancestry to order the
	// remainder by, and carrying a CA a deployment may rely on beats
	// truncating the chain at the last provable link.
	chain []*x509.Certificate
	// key is the private half of leaf. Typed crypto.Signer rather than
	// crypto.PrivateKey because that is what parsePrivateKeys already proved it is:
	// every admitted key type exposes a public half, which is the invariant identity
	// matching and the currency read-back both rest on.
	key crypto.Signer
	// extra holds certificates that parsed but are not ancestors of leaf. They
	// are deliberately excluded from the bundle: embedding an unrelated CA
	// pollutes the trust chain the consumer sees.
	extra []*x509.Certificate
	// observations are non-fatal findings, in the order discovered.
	observations []Observation
}

// Observations returns the non-fatal findings about the input, in the order
// discovered. The slice is a copy, so a caller may keep, sort or filter it
// without disturbing the analysis it came from.
//
// This is the whole of Analysis's exported surface, because it is the whole of
// what a consumer outside this package does with an Analysis: report what was
// noticed, then hand the value back to Encode or CheckCurrency unchanged.
func (a *Analysis) Observations() []Observation {
	return slices.Clone(a.observations)
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
//
// This is the package's only production clock read, and it happens once for the
// whole analysis: ranking and the validity observations must agree with each
// other, and a comparator that re-reads the time can stop being transitive
// mid-reduction. Everything past this line is a pure function of the input plus
// that one instant, which is what lets analyseAt reproduce a validity or
// tie-break decision at an exact moment instead of near it.
func Analyse(certPEM, keyPEM []byte) (Analysis, error) {
	return analyseAt(certPEM, keyPEM, time.Now())
}

// analyseAt is Analyse with the scan instant supplied rather than read, so the
// validity boundaries and the renewed-certificate tie-break are decidable at an
// exact time. Unexported on purpose: no caller outside this package has a reason
// to analyse a bundle at anything other than now, and widening the exported
// surface to hand one in would invite exactly that.
func analyseAt(certPEM, keyPEM []byte, now time.Time) (Analysis, error) {
	in, err := prepareAnalysisInput(certPEM, keyPEM)
	if err != nil {
		return Analysis{}, err
	}
	certs, obs := in.certs, in.observations

	g, err := newCertGraph(certs, now)
	if err != nil {
		return Analysis{}, err
	}

	identity, tieObs, err := g.selectIdentity(in.signers, in.keyIssues)
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
				in.certAt[identity.cert]+1, len(certs)+in.duplicateCerts),
		})
	}
	obs = append(obs, validityObservations(leaf, now)...)

	chain, extra, chainObs := g.assembleChain(identity.cert, leaf)
	obs = append(obs, chainObs...)
	obs = append(obs, chainValidityObservations(chain, now)...)

	return Analysis{
		leaf:         leaf,
		chain:        chain,
		key:          in.signers[identity.key],
		extra:        extra,
		observations: obs,
	}, nil
}

// analysisInput is the parsed, deduplicated bundle analyseAt reasons over, plus
// the observations that describe what parsing had to leave out. It exists so the
// input phase and the graph phase are separately readable: everything here is a
// pure function of the PEM bytes, with no reference to the scan instant.
type analysisInput struct {
	// certs are the certificates in input order with duplicates removed, and
	// certAt maps each one back to its block index in the original file.
	certs  []*x509.Certificate
	certAt []int
	// signers are the distinct usable private keys, and keyIssues the key blocks
	// that yielded none.
	signers      []crypto.Signer
	observations []Observation
	keyIssues    keyDefects
	// duplicateCerts is how many blocks dedupeCerts removed, which the
	// leaf-not-first observation needs to name the original block count.
	duplicateCerts int
}

// prepareAnalysisInput parses both PEM files, drops the duplicates, and reports
// everything the operator has to be told about the input itself: unrelated blocks,
// duplicate certificates, more than one key, and key blocks that yielded no key.
//
// Observation order is part of the contract and matches the order the defects are
// discovered in the file, so it is fixed here rather than assembled by the caller.
func prepareAnalysisInput(certPEM, keyPEM []byte) (analysisInput, error) {
	certs, unrelatedBlocks, err := parseCertChain(certPEM)
	if err != nil {
		return analysisInput{}, fmt.Errorf("parse cert chain: %w", err)
	}
	keys, keyIssues, err := parsePrivateKeys(keyPEM)
	if err != nil {
		return analysisInput{}, fmt.Errorf("parse private key: %w", err)
	}

	var obs []Observation

	if unrelatedBlocks.count > 0 {
		obs = append(obs, Observation{
			Kind: ObsUnrelatedBlocksSkipped,
			Detail: fmt.Sprintf("%d PEM block(s) in the certificate file are neither a certificate nor a private key and were left out of the bundle (first %q)",
				unrelatedBlocks.count, unrelatedBlocks.firstTypeForLog()),
		})
	}

	certs, certAt, dupCerts := dedupeCerts(certs)
	if dupCerts > 0 {
		obs = append(obs, Observation{
			Kind:   ObsDuplicateCerts,
			Detail: fmt.Sprintf("%d duplicate certificate block(s) ignored", dupCerts),
		})
	}

	signers := dedupeSigners(keys)
	if len(signers) > 1 {
		obs = append(obs, Observation{
			Kind:   ObsMultipleKeys,
			Detail: fmt.Sprintf("%d distinct private key(s) in the key file", len(signers)),
		})
	}

	// Reported whether or not identity selection goes on to succeed. When it fails,
	// noMatchError names the same blocks in its own sentence; when it succeeds
	// because an OLDER key still matches, this observation is the only signal that
	// the appended one is damaged, and without it the operator first hears about it
	// as a conversion failure at the next renewal.
	if defects := keyIssues.details(); defects != "" {
		obs = append(obs, Observation{
			Kind:   ObsUnusableKeyBlocksSkipped,
			Detail: "the key file holds block(s) that yielded no key: " + defects,
		})
	}

	return analysisInput{
		certs:          certs,
		certAt:         certAt,
		signers:        signers,
		observations:   obs,
		keyIssues:      keyIssues,
		duplicateCerts: dupCerts,
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
	// verified memoises signature checks, keyed by (child, parent). Checks are made
	// per CANDIDATE EDGE, never for all pairs: an eager all-pairs pass cost O(n^2)
	// real signature verifications on the scan goroutine, while the plausible-issuer
	// filter leaves only the edges that could matter. Three places ask — the
	// verified-distance walk, chain assembly at the few candidates of one hop, and
	// the role check on the selected identity's candidate children — and the memo
	// means an edge is verified at most once for all of them.
	verified map[[2]int]bool
	// selfSigned memoises the self-signature check per certificate, for the same
	// reason verified memoises edges: it is a real signature verification whose cost
	// the input file dictates, and three places ask — the root set, every hop of
	// pathFrom, and assembleChain's self-signed carve-out.
	selfSigned map[int]bool
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
	// related" as "proved unrelated" drops genuine CA certificates.
	candidateParents [][]int
	children         [][]int
	// distToRoot[i]: fewest parent hops from certs[i] to a self-signed certificate
	// in this bundle over the INCLUSIVE candidate edges, or -1 when none is
	// reachable. Kept for the documented SHA-1 and name-encoding fallback, where no
	// signature can be checked at all.
	distToRoot []int
	// verifiedDistToRoot[i]: the same distance measured over VERIFIED edges only,
	// or -1 when no root is reachable by signatures alone.
	//
	// The inclusive measure cannot tell a parent with a real route to a root apart
	// from one whose route depends on an unverifiable hop: two intermediates sharing
	// a subject and a key, one continuing to an included root that actually signed
	// it and one naming an impostor root of the same name holding a DIFFERENT key,
	// score identically. Ranking on the inclusive measure alone therefore emitted a
	// chain whose selected intermediate did not verify under the root beside it,
	// while the fully verified alternative sat in the same input.
	verifiedDistToRoot []int
}

// maxVerifiableKeyBits bounds the public-key size this app will run a signature
// verification against. crypto/x509 accepts an RSA modulus of any size (go1.26
// enforces only a 1024-bit floor) and crypto/rsa then pays a full modexp with it
// whenever the signature length matches, so the cost of one candidate edge is
// dictated by the FILE, not by the certificate count maxChainCerts bounds: a
// 131072-bit modulus costs 184ms per verification and a 1-Mbit one 11.9s, against
// 69us for RSA-2048. 16384 is far above anything issued (Let's Encrypt tops out at
// RSA-4096) and keeps one verification in the low milliseconds for a conventional
// public exponent; maxVerifiablePublicExponent bounds the other half of that cost.
//
// A certificate this bundle names as the issuer of another one is REFUSED when it
// exceeds the ceiling, rather than carried as an unverified candidate edge; see
// oversizedIssuerError for why degrading silently was the worse outcome.
const maxVerifiableKeyBits = 16384

// maxVerifiablePublicExponent bounds the RSA public exponent this app will run a
// signature verification against. maxVerifiableKeyBits bounds only the modulus,
// which fixes the cost of ONE modular multiplication; crypto/rsa raises the
// signature to the power of the exponent the FILE supplies, so the NUMBER of
// squarings is dictated by the exponent's bit length. crypto/x509 accepts any
// positive exponent asn1 fits in an int, and crypto/rsa stops only at even values
// and at 2^31-1. Measured on go1.26.5: one verification at the modulus ceiling
// costs 4.7ms with the conventional 65537 and 14.3ms with 2^31-1, and one Analyse
// pays up to maxChainCerts^2/2 of them. Real keys use 3, 17 or 65537 (RFC 8017
// recommends 65537), so 2^24 is far above anything issued.
const maxVerifiablePublicExponent = 1 << 24

// verifiableKey reports whether pub is small enough to verify against. Only RSA is
// unbounded: x509 parses ECDSA keys on named curves only, Ed25519 is fixed-size,
// and x509 refuses DSA verification outright (DSAWithSHA1/256 are Unsupported).
func verifiableKey(pub crypto.PublicKey) bool {
	return unverifiableKeyReason(pub) == ""
}

// unverifiableKeyReason describes why a signature is too expensive to check
// against pub, or "" when it is not. Both ceilings live here so the guard and the
// refusal that reports it cannot drift.
func unverifiableKeyReason(pub crypto.PublicKey) string {
	k, ok := pub.(*rsa.PublicKey)
	if !ok {
		return ""
	}
	switch {
	case k.N == nil:
		return "holds an RSA key with no modulus, which no signature can be checked against"
	case rsaModulusBits(pub) > maxVerifiableKeyBits:
		return fmt.Sprintf("holds a %d-bit RSA key, above the %d-bit modulus ceiling this app will verify a signature against",
			rsaModulusBits(pub), maxVerifiableKeyBits)
	case k.E > maxVerifiablePublicExponent:
		return fmt.Sprintf("holds an RSA key with public exponent %d, above the %d exponent ceiling this app will verify a signature against",
			k.E, maxVerifiablePublicExponent)
	}
	return ""
}

// rsaModulusBits reports the size of pub's RSA modulus, and 0 for any other key
// type (or for the RSA key x509 left without a modulus, whose BitLen would panic
// on the nil big.Int — ParseCertificate cannot produce one, since it rejects a
// non-positive modulus outright).
//
// It answers nothing about verifiability: verifiableKey owns that decision, and
// this exists only so the refusal can NAME the size an operator would otherwise
// have to pull out of the file with openssl.
func rsaModulusBits(pub crypto.PublicKey) int {
	k, ok := pub.(*rsa.PublicKey)
	if !ok || k.N == nil {
		return 0
	}
	return k.N.BitLen()
}

// newCertGraph derives both issuance edge sets, or refuses the bundle outright
// when a candidate issuer's key is one no signature can be checked against.
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
//
// The refusal is decided on the candidate edges alone, before either distance walk
// runs, so a bundle this app will not reason about costs it no signature
// verifications at all.
func newCertGraph(certs []*x509.Certificate, now time.Time) (*certGraph, error) {
	g := &certGraph{
		now:              now,
		certs:            certs,
		candidateParents: make([][]int, len(certs)),
		children:         make([][]int, len(certs)),
		verified:         make(map[[2]int]bool),
		selfSigned:       make(map[int]bool, len(certs)),
	}
	for child := range certs {
		for parent := range certs {
			if child == parent || !g.plausibleIssuer(child, parent) {
				continue
			}
			g.candidateParents[child] = append(g.candidateParents[child], parent)
			g.children[parent] = append(g.children[parent], child)
		}
	}
	if err := g.oversizedIssuerError(); err != nil {
		return nil, err
	}
	g.computeDistances()
	return g, nil
}

// oversizedIssuerError refuses a bundle in which a certificate named as the
// issuer of another one here holds a key no signature can be checked against —
// which is an RSA modulus above maxVerifiableKeyBits, or a public exponent above
// maxVerifiablePublicExponent — naming which limit was crossed.
// It reports nil for every other bundle, and reads unverifiableKeyReason (the
// predicate verifiableKey answers) rather than re-deriving either ceiling, so the
// refusal is exactly the guard's negation and the two cannot drift.
//
// The alternative is to carry such an edge as merely UNVERIFIED, which is what
// the SHA-1 and name-encoding cases do — and that is safe only because nothing
// competes with them. Here something does: a same-subject certificate holding an
// ordinary key satisfies the identical name match, so BOTH candidate edges are
// unverified, and betterParent then ranks them on validity, route to a root and
// NotAfter — keys an impostor wins (the ceiling denies the oversized certificate
// the root status the impostor's self-signature gets, and a longer NotAfter or the
// DER tie-break settles the rest). The bundle would convert to a PFX whose chain
// no consumer can verify.
//
// Refusing costs nothing real: no CA issues RSA above 16384 bits, so an
// over-ceiling issuer standing beside a same-subject decoy is an attack shape
// rather than a configuration. No verification is attempted either way, which is
// the point of the ceiling; only the outcome changes, from a silent wrong chain to
// a named refusal.
func (g *certGraph) oversizedIssuerError() error {
	for i, c := range g.certs {
		// A certificate this bundle names as nobody's issuer is never a parent in a
		// signature check, so its size decides nothing: it can only be excluded, or
		// kept by the additive fallback, and both say so out loud.
		reason := unverifiableKeyReason(c.PublicKey)
		if len(g.children[i]) == 0 || reason == "" {
			continue
		}
		return fmt.Errorf(
			"certificate %q is named as the issuer of another certificate in this bundle and %s; no signature can be checked against it, so its place in the chain could only be guessed; remove it from the bundle",
			boundSubject(c.Subject.String()), reason)
	}
	return nil
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
// Neither signal is consulted for a candidate the certificate's own extensions
// positively disqualify from signing certificates: relationship evidence says two
// certificates LOOK related, while canIssueCertificates says this one cannot be
// anybody's issuer whatever the names line up to. Without that gate a same-named
// certificate asserting CA:false is recorded as an edge and can be emitted as
// chain material, which makes downstream path validation reject the PFX.
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
	if !canIssueCertificates(p) {
		return false
	}
	if bytes.Equal(c.RawSubject, p.RawSubject) && samePublicKey(c.PublicKey, p.PublicKey) {
		return false
	}
	if len(c.AuthorityKeyId) > 0 && len(p.SubjectKeyId) > 0 &&
		bytes.Equal(c.AuthorityKeyId, p.SubjectKeyId) {
		return true
	}
	return bytes.Equal(c.RawIssuer, p.RawSubject)
}

// canIssueCertificates reports whether c's own extensions leave it able to issue
// certificates, mirroring the eligibility crypto/x509 applies to a parent without
// doing any signature work.
//
// Three disqualifications, each of them positive proof rather than absent evidence:
// a v3 certificate carrying no Basic Constraints at all (RFC 5280 4.2.1.9 says such
// a key MUST NOT verify certificate signatures, which is why CheckSignatureFrom
// refuses it as a parent), one whose Basic Constraints say CA:false, and one whose
// stated KeyUsage omits KeyCertSign. An absent KeyUsage (the zero value) states
// nothing, so it disqualifies nothing.
//
// This answers only whether c may be somebody's PARENT. Whether c is SELF-SIGNED is a
// different question, and isSelfSigned deliberately answers it without this gate: a
// self-signed certificate with no basic constraints is still a root here, even though
// it can issue nothing else.
func canIssueCertificates(c *x509.Certificate) bool {
	if c.Version == 3 && !c.BasicConstraintsValid {
		return false
	}
	if c.BasicConstraintsValid && !c.IsCA {
		return false
	}
	return c.KeyUsage == 0 || c.KeyUsage&x509.KeyUsageCertSign != 0
}

// verifies reports whether certs[parent]'s signature over certs[child] checks out,
// memoised. This is the STRONG signal: a candidate edge only says the two names or
// key identifiers line up, which an impostor sharing a subject can also satisfy.
//
// A parent whose RSA key exceeds either verification ceiling is never verified: that
// modexp is the cost the ceiling exists to refuse. No candidate parent reaches
// here in that state, because newCertGraph refuses such a bundle before either
// distance walk runs — an edge that can never be proven, standing beside a
// same-subject certificate that can, is how an impostor wins a branch. The guard
// stays as the backstop that keeps the expensive call unreachable whatever asks.
func (g *certGraph) verifies(child, parent int) bool {
	key := [2]int{child, parent}
	if got, ok := g.verified[key]; ok {
		return got
	}
	got := verifiableKey(g.certs[parent].PublicKey) &&
		g.certs[child].CheckSignatureFrom(g.certs[parent]) == nil
	g.verified[key] = got
	return got
}

// isIssuer reports whether certs[i] VERIFIABLY signed another certificate here.
//
// Only a verified signature counts. A name match alone would reject an identity
// because some unrelated certificate happens to claim it as issuer, which an
// attacker or a careless paste could arrange.
func (g *certGraph) isIssuer(i int) bool {
	for _, child := range g.children[i] {
		if g.verifies(child, i) {
			return true
		}
	}
	return false
}

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
//
// A certificate whose own RSA key exceeds either verification ceiling is reported as
// not self-signed — unverified rather than disproven — for the same cost reason
// verifies applies the ceiling. After newCertGraph's refusal that answer is only
// reachable for a certificate this bundle names as nobody's issuer, so it decides
// only two harmless things: such a stray is no root for the distance walk, and if
// it is the IDENTITY itself its empty chain counts as a failure to prove rather
// than proof, so the additive fallback keeps the rest of the bundle and says so.
func (g *certGraph) isSelfSigned(i int) bool {
	if got, ok := g.selfSigned[i]; ok {
		return got
	}
	got := g.checkSelfSigned(i)
	g.selfSigned[i] = got
	return got
}

// checkSelfSigned is isSelfSigned without the memo: the actual signature check.
func (g *certGraph) checkSelfSigned(i int) bool {
	c := g.certs[i]
	if !bytes.Equal(c.RawSubject, c.RawIssuer) {
		return false
	}
	if !verifiableKey(c.PublicKey) {
		return false
	}
	return c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

// computeDistances fills both distance maps: distToRoot over the inclusive
// candidate edges, and verifiedDistToRoot over the verified edges only.
//
// Both are multi-source breadth-first walks DOWNWARD from every root over the
// children edges. The obvious alternative — a memoised depth-first walk upward
// with an on-path cycle guard — is subtly wrong: the guard's -1 gets memoised
// for a node that was merely FORBIDDEN on the current path, not genuinely
// unreachable, so a bundle
// containing a cross-certification loop yields distances that depend on the order
// certificates appeared in the file. Cycles are real: RFC 4158 describes mesh
// PKIs with bidirectional cross-certification, and RFC 5280 permits several
// certificates for one CA name. BFS from the roots has no path state to leak, so
// it is cycle-safe and order-independent by construction.
//
// The verified walk costs at most one signature check per CANDIDATE edge, all
// memoised in g.verified and reused by chain assembly and the role check. That is
// far below all pairs for an ordinary bundle, but it is not a smaller bound in
// principle: plausibleIssuer accepts on an issuer/subject name match alone, so a
// bundle whose certificates all share one issuer name still yields O(n^2) edges,
// and this walk pays for them eagerly.
func (g *certGraph) computeDistances() {
	// One self-signature check per certificate, shared by both walks: the root set
	// is the same for either edge predicate, and isSelfSigned is a real signature
	// verification.
	var roots []int
	for i := range g.certs {
		if g.isSelfSigned(i) {
			roots = append(roots, i)
		}
	}
	g.distToRoot = g.distancesFromRoots(roots, nil)
	g.verifiedDistToRoot = g.distancesFromRoots(roots, g.verifies)
}

// distancesFromRoots runs the root-down BFS from roots, traversing only the child
// edges edgeOK accepts. A nil edgeOK accepts every candidate edge.
func (g *certGraph) distancesFromRoots(roots []int, edgeOK func(child, parent int) bool) []int {
	dist := make([]int, len(g.certs))
	for i := range dist {
		dist[i] = -1
	}
	queue := make([]int, 0, len(g.certs))
	for _, i := range roots {
		dist[i] = 0
		queue = append(queue, i)
	}
	for head := 0; head < len(queue); head++ {
		cur := queue[head]
		for _, child := range g.children[cur] {
			if dist[child] != -1 {
				continue // already reached by an equal-or-shorter route
			}
			if edgeOK != nil && !edgeOK(child, cur) {
				continue // this hop is not evidence of the route being asked about
			}
			dist[child] = dist[cur] + 1
			queue = append(queue, child)
		}
	}
	return dist
}

// selectIdentity resolves which certificate and key form the identity, matching
// every key against every certificate rather than against a positional guess.
func (g *certGraph) selectIdentity(signers []crypto.Signer, keyIssues keyDefects) (identityMatch, []Observation, error) {
	matches, firstUnverifiable := g.collectMatches(signers)
	switch len(matches) {
	case 0:
		return identityMatch{}, nil, g.noMatchError(len(signers), firstUnverifiable, keyIssues)
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
// the more specific diagnosis. On a plain mismatch the key blocks that yielded
// no key at all are named after the base sentence (keyDefects.suffix), because
// the count in that sentence is of USABLE keys: a mid-rotation key file whose
// appended block is damaged otherwise reads as "the key does not match the
// certificate" with no hint that half the file was unreadable.
func (g *certGraph) noMatchError(keyCount, firstUnverifiable int, keyIssues keyDefects) error {
	if firstUnverifiable >= 0 {
		c := g.certs[firstUnverifiable]
		if c.PublicKey == nil {
			// crypto/x509 parses a certificate whose SubjectPublicKeyInfo algorithm OID it
			// does not recognise and leaves PublicKey nil (parser.go's
			// UnknownPublicKeyAlgorithm branch), so %T would render "<nil>" here - the one
			// case where naming the algorithm matters most is the one where there is no
			// type to name. Say what happened instead.
			return fmt.Errorf(
				"certificate %q uses a public key algorithm crypto/x509 does not recognise, so it cannot be verified against the private key; re-issue it with an RSA, ECDSA or Ed25519 key",
				boundSubject(c.Subject.String()))
		}
		return fmt.Errorf(
			"certificate %q has a public key of type %T that cannot be verified against the private key",
			boundSubject(c.Subject.String()), c.PublicKey)
	}
	return fmt.Errorf(
		"none of the %d private key block(s) matches any of the %d certificate(s) in the chain%s",
		keyCount, len(g.certs), keyIssues.suffix())
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
// With both keys inert the fold degenerates to "first block in the file wins" —
// order-dependence in the one function whose headline claim is order invariance.
// DER is a total order over distinct certificates, so ties are impossible.
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
// the choice is deterministic: prefer a parent that is currently valid, then one
// with a route to a self-signed root in this bundle that verifies by signature at
// every hop, then the shorter such route, then the inclusive route, then the later
// NotAfter, then a byte comparison of the certificate DER. One path is emitted
// rather than every ancestor, because a consumer reading the bag sequence
// positionally should see one coherent chain; alternatives land in Extra.
func (g *certGraph) pathFrom(start int) []int {
	path := []int{start}
	onPath := make([]bool, len(g.certs))
	onPath[start] = true
	for cur := start; ; {
		// A self-signed certificate has no issuer BY CONSTRUCTION, so the walk must
		// end here. Without this the unverified-candidate fallback in bestParent can
		// attach a same-subject stranger (a regenerated self-signed certificate
		// holding a DIFFERENT key) as the identity's issuer, which assembleChain's
		// own self-signed carve-out is written to prevent but never sees, because it
		// only fires on an EMPTY chain.
		if g.isSelfSigned(cur) {
			return path
		}
		best := g.bestParent(cur, onPath)
		if best == -1 {
			return path
		}
		path = append(path, best)
		onPath[best] = true
		cur = best
	}
}

// bestParent picks the next hop from cur, or -1 when the chain ends here.
//
// Edge STRENGTH outranks every other ranking key. A candidate edge is only a name
// or key-identifier match, which a same-subject certificate holding a different key
// also satisfies; ranking such an impostor above the certificate that actually
// signed this one would emit a chain a consumer cannot verify. So verified parents
// are considered alone whenever any exists, and unverified candidates only when
// none does — which is the SHA-1 and name-encoding case the inclusive set exists
// for.
func (g *certGraph) bestParent(cur int, onPath []bool) int {
	for _, verifiedOnly := range []bool{true, false} {
		best := -1
		for _, p := range g.candidateParents[cur] {
			if onPath[p] || g.verifies(cur, p) != verifiedOnly {
				continue
			}
			if best == -1 || g.betterParent(p, best) {
				best = p
			}
		}
		if best != -1 {
			return best
		}
	}
	return -1
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
	// same input.
	va, vb := validAt(g.certs[a], g.now), validAt(g.certs[b], g.now)
	if va != vb {
		return va
	}
	// Then route STRENGTH, ahead of the inclusive measure, for the same reason edge
	// strength outranks everything in bestParent: a candidate whose route to a root
	// is only a chain of NAME matches may be an impostor's, and preferring it over a
	// candidate that verifies all the way to an included root emits a chain the
	// consumer cannot validate. The inclusive ranking below is consulted only when
	// neither candidate has a fully verified route — the SHA-1 and name-encoding
	// case, where no signature can be checked at all.
	vra, vrb := g.verifiedDistToRoot[a] >= 0, g.verifiedDistToRoot[b] >= 0
	if vra != vrb {
		return vra
	}
	if vra && g.verifiedDistToRoot[a] != g.verifiedDistToRoot[b] {
		return g.verifiedDistToRoot[a] < g.verifiedDistToRoot[b]
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

// publicKeyMatches reports whether pub is the public half of signer's private
// key. supported is false when pub's type does not provide the
// Equal(crypto.PublicKey) bool method every crypto/x509 public key type
// implements, in which case matched carries no meaning and the caller must treat
// the key type as unverifiable rather than as a mismatch.
func publicKeyMatches(pub crypto.PublicKey, signer crypto.Signer) (matched, supported bool) {
	return equalPublicKeys(pub, signer.Public())
}

// equalPublicKeys is the single home of the comparison rule publicKeyMatches
// and samePublicKey share: every public key type crypto/x509 parses exposes
// Equal(crypto.PublicKey) bool, and a type that does not is unverifiable rather
// than unequal. supported reports which of the two it was, so a caller that
// must distinguish them can, and one that need not can ignore it.
func equalPublicKeys(a, b crypto.PublicKey) (matched, supported bool) {
	matcher, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return false, false
	}
	return matcher.Equal(b), true
}

// samePublicKey reports whether two certificate public keys are the same key.
// Used to tell KEY REUSE apart from issuance: a certificate holding the same
// public key as another cannot have issued it.
func samePublicKey(a, b crypto.PublicKey) bool {
	matched, _ := equalPublicKeys(a, b)
	return matched
}

// partitionIssuerEligible splits certificates into the ones that could still be
// somebody's issuer and the ones their own extensions disqualify, preserving input
// order in both halves. It is what keeps the additive chain fallback from emitting
// a certificate that provably cannot sign certificates as chain material.
func partitionIssuerEligible(certs []*x509.Certificate) (eligible, disqualified []*x509.Certificate) {
	for _, c := range certs {
		if canIssueCertificates(c) {
			eligible = append(eligible, c)
			continue
		}
		disqualified = append(disqualified, c)
	}
	return eligible, disqualified
}

// assembleChain builds the emitted chain for the selected identity, the
// certificates deliberately left out of it, and the observations describing
// either outcome.
//
// The additive-only fallback lives here: whenever the discovered path stops at a
// certificate that is not PROVEN self-signed — no issuer of the identity could be
// established at all, or none of the certificate the path ended on — the remaining
// certificates are KEPT rather than dropped: silently removing a CA a working
// deployment relied on is far worse than carrying one it did not need, so exclusion
// is reserved for certificates positively shown to sit off the chain.
//
// A SELF-SIGNED identity is excluded from the fallback: it has no issuer by
// construction, so an empty chain there is proof rather than a failure to prove,
// and anything else in the bundle genuinely is unrelated.
//
// The fallback is not indiscriminate: a certificate canIssueCertificates
// disqualifies is not a possible issuer of anything, so keeping it would emit
// chain material downstream path validation rejects. Those are excluded and named,
// while every certificate whose relationship is merely unproven is kept.
func (g *certGraph) assembleChain(identityCert int, leaf *x509.Certificate) (chain, extra []*x509.Certificate, obs []Observation) {
	path := g.pathFrom(identityCert)
	chain = make([]*x509.Certificate, 0, len(path)-1)
	for _, i := range path[1:] {
		chain = append(chain, g.certs[i])
	}
	extra = g.outsidePath(path)

	// The discovered path ends where relationship evidence ran out. If that terminus
	// is not PROVEN self-signed, the chain above it is unfinished, whether the path
	// stopped at the identity itself or three links up, so the additive fallback
	// applies to both: a permitted name-encoding difference in the middle of a
	// bundle must not silently truncate the chain either.
	terminal := path[len(path)-1]
	if len(extra) > 0 && !g.isSelfSigned(terminal) {
		kept, disqualified := partitionIssuerEligible(extra)
		chain = append(chain, kept...)
		disposition := fmt.Sprintf("the remaining %d certificate(s) were kept rather than dropped", len(kept))
		if len(kept) == 0 {
			disposition = "nothing in the bundle could be kept as chain material"
		}
		fallbackObs := []Observation{{
			Kind: ObsChainUnverified,
			Detail: fmt.Sprintf("no issuer of %q could be established from the bundle; %s",
				boundSubject(g.certs[terminal].Subject.String()), disposition),
		}}
		if len(disqualified) > 0 {
			fallbackObs = append(fallbackObs, Observation{
				Kind: ObsExtraCertsExcluded,
				Detail: fmt.Sprintf("%d certificate(s) cannot issue certificates, so they are no issuer of %q and were excluded: %s",
					len(disqualified), boundSubject(leaf.Subject.String()), subjectsForLog(disqualified)),
			})
		}
		return chain, disqualified, fallbackObs
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

// chainValidityObservations reports certificates in the EMITTED chain that are
// outside their validity window at now. Never an error, for the same reason an
// out-of-window identity is not: this package converts, it does not validate.
//
// It is reported because betterParent already ranks a currently valid issuer
// ahead of an expired one, so an out-of-window certificate reaching the emitted
// chain means no valid alternative existed in the bundle. That is precisely the
// case where the operator has to act, and it is the one the leaf-only
// validityObservations cannot see.
func chainValidityObservations(chain []*x509.Certificate, now time.Time) []Observation {
	var obs []Observation
	for i, c := range chain {
		if validAt(c, now) {
			continue
		}
		obs = append(obs, Observation{
			Kind: ObsChainCertOutOfWindow,
			Detail: fmt.Sprintf(
				"chain certificate %d of %d, %q, is outside its validity window (NotBefore %s, NotAfter %s)",
				i+1, len(chain), boundSubject(c.Subject.String()),
				c.NotBefore.UTC().Format(time.RFC3339), c.NotAfter.UTC().Format(time.RFC3339)),
		})
	}
	return obs
}

// dedupeCerts removes byte-identical certificates, keeping input order, and
// reports how many were dropped plus, for each kept certificate, its ORIGINAL
// index in the input slice. A repeated certificate is a copy-paste artefact
// that would otherwise create a spurious self-edge candidate in the graph. The
// kept-at mapping is what lets an observation name the block number an operator
// will find in their file rather than a post-dedupe position.
func dedupeCerts(certs []*x509.Certificate) (kept []*x509.Certificate, keptAt []int, dropped int) {
	kept = make([]*x509.Certificate, 0, len(certs))
	keptAt = make([]int, 0, len(certs))
	for i, c := range certs {
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
		keptAt = append(keptAt, i)
	}
	return kept, keptAt, dropped
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
