package convert

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"
	"time"
)

// ObservationKind classifies a non-fatal fact Analyse noticed about its input.
type ObservationKind string

// The observations Analyse can emit.
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
	// ObsCAAsIdentity reports that the selected identity asserts IsCA.
	ObsCAAsIdentity ObservationKind = "ca-as-identity"
	// ObsChainUnverified reports that the discovered path ended without an issuer it
	// could still place — either none could be established from the bundle, or the
	// only proven one is already on the path — WHILE certificates were left over
	// that it could not place.
	ObsChainUnverified ObservationKind = "chain-unverified"
	// ObsChainTrustAnchorAbsent reports that no self-signed trust anchor is in the
	// bundle, with nothing left over: every parsed certificate is on the emitted
	// path, which either simply stops below an anchor or closed a
	// cross-certification cycle.
	ObsChainTrustAnchorAbsent ObservationKind = "chain-trust-anchor-absent"
	// ObsChainAnchorUnverifiable reports that the chain terminates at a certificate
	// that names ITSELF as its own issuer while this app could not verify that
	// self-signature: a corrupt or re-signed certificate, a signature algorithm
	// crypto/x509 refuses (MD5, DSA), or a key above the verification ceilings.
	ObsChainAnchorUnverifiable ObservationKind = "chain-anchor-unverifiable"
	// ObsIdentityNotYetValid reports a selected identity whose NotBefore is in
	// the future. Conversion still proceeds; consumers will reject it.
	ObsIdentityNotYetValid ObservationKind = "identity-not-yet-valid"
	// ObsIdentityExpired reports a selected identity past its NotAfter.
	ObsIdentityExpired ObservationKind = "identity-expired"
	// ObsChainCertOutOfWindow reports a certificate in the EMITTED chain that is
	// outside its own validity window.
	ObsChainCertOutOfWindow ObservationKind = "chain-cert-out-of-window"
	// ObsChainCertCannotIssue reports a certificate in the EMITTED chain whose own
	// extensions leave it unable to issue certificates under RFC 5280 4.2.1.9 (no
	// basic constraints on a v3 certificate, CA:false, or a stated keyUsage without
	// keyCertSign).
	ObsChainCertCannotIssue ObservationKind = "chain-cert-cannot-issue"
	// ObsUnrelatedBlocksSkipped reports PEM blocks in the CERTIFICATE file that are
	// neither a certificate nor an expected key companion — an OpenSSL "TRUSTED
	// CERTIFICATE", the legacy "X509 CERTIFICATE" alias, a stray CERTIFICATE
	// REQUEST — and were therefore not part of the bundle.
	ObsUnrelatedBlocksSkipped ObservationKind = "unrelated-blocks-skipped"
	// ObsUnusableKeyBlocksSkipped reports PEM blocks in the KEY file that yielded no
	// usable key — unparseable DER, armour encoding/pem could not decode, ciphertext,
	// or a label that names neither a key format this app reads nor an expected
	// companion of the key — while another block did yield one, so conversion
	// continued.
	ObsUnusableKeyBlocksSkipped ObservationKind = "unusable-key-blocks-skipped"
	// ObsIssuerMatchIgnored reports that a supplied key also matched a certificate
	// that verifiably issued another certificate in this bundle.
	ObsIssuerMatchIgnored ObservationKind = "issuer-match-ignored"
	// ObsChainEdgeUnprovenIssuer reports a certificate in the EMITTED chain that is
	// there because its subject matches the issuer name (or the authority key
	// identifier) of the certificate below it, while NO signature proves it issued
	// that certificate.
	ObsChainEdgeUnprovenIssuer ObservationKind = "chain-edge-unproven-issuer"
)

// ObservationClass is how loudly an observation of a given kind deserves to be
// reported.
type ObservationClass string

const (
	// ObservationClassQuiet is a benign artefact of how the input file was assembled,
	// with no bearing on the bundle produced. Worth recording, not worth surfacing.
	ObservationClassQuiet ObservationClass = "quiet"
	// ObservationClassInfo is a true fact about the input the operator has nothing to
	// act on — the expected shape of a supported input — reported so it is not
	// invisible, and deliberately not as a problem.
	ObservationClassInfo ObservationClass = "informational"
	// ObservationClassWarning names something the operator probably did not intend, or
	// that a consumer of the bundle will reject.
	ObservationClassWarning ObservationClass = "warning"
)

// Class reports how loudly an observation of this kind deserves to be reported.
func (k ObservationKind) Class() ObservationClass {
	switch k {
	case ObsDuplicateCerts:
		return ObservationClassQuiet
	case ObsChainTrustAnchorAbsent:
		return ObservationClassInfo
	case ObsLeafNotFirst, ObsMultipleKeys, ObsExtraCertsExcluded, ObsRenewedCertTie,
		ObsCAAsIdentity, ObsChainUnverified, ObsChainAnchorUnverifiable,
		ObsIdentityNotYetValid, ObsIdentityExpired,
		ObsChainCertOutOfWindow, ObsChainCertCannotIssue, ObsUnrelatedBlocksSkipped,
		ObsUnusableKeyBlocksSkipped, ObsIssuerMatchIgnored,
		ObsChainEdgeUnprovenIssuer:
		return ObservationClassWarning
	}
	// Unreachable while the switch above is exhaustive, which the test enforces.
	return ObservationClassWarning
}

// Observation is one non-fatal finding about the input.
type Observation struct {
	Kind   ObservationKind
	Detail string
}

// Analysis is the resolved result of reading a certificate bundle and a key
// file: which certificate is the identity, which private key belongs to it,
// which certificates form its chain and in what order, and which were left out.
type Analysis struct {
	// leaf is the end-entity certificate the PFX is built around.
	leaf *x509.Certificate
	// chain holds leaf's ancestors, ordered nearest-parent-first.
	chain []*x509.Certificate
	// key is the private half of leaf.
	key crypto.Signer
	// extra holds the certificates that parsed and were deliberately excluded from the
	// bundle: embedding an unrelated CA pollutes the trust chain the consumer sees.
	extra []*x509.Certificate
	// observations are non-fatal findings, in the order discovered.
	observations []Observation
}

// Observations returns the non-fatal findings about the input, in the order
// discovered.
func (a Analysis) Observations() []Observation { //nolint:gocritic // hugeParam: the value shape is what removes the nil arm.
	return slices.Clone(a.observations)
}

// Analyse resolves a certificate bundle and a key file into the identity, chain
// and key a PKCS#12 bundle needs.
func Analyse(ctx context.Context, certPEM, keyPEM []byte) (Analysis, error) {
	return analyseAt(ctx, certPEM, keyPEM, time.Now())
}

// analyseAt is Analyse with the scan instant supplied rather than read, so the
// validity boundaries and the renewed-certificate tie-break are decidable at an
// exact time.
func analyseAt(ctx context.Context, certPEM, keyPEM []byte, now time.Time) (Analysis, error) {
	in, err := prepareAnalysisInput(certPEM, keyPEM)
	if err != nil {
		return Analysis{}, err
	}
	certs, obs := in.certs, in.observations

	// A cancellation read after each phase that can pay a verification.
	g := newCertGraph(ctx, certs, now)
	if g.cancelErr != nil {
		return Analysis{}, fmt.Errorf("analyse cancelled: %w", g.cancelErr)
	}

	identity, tieObs, err := g.selectIdentity(in.signers, in.keyIssues, in.certIssues)
	if g.cancelErr != nil {
		return Analysis{}, fmt.Errorf("analyse cancelled: %w", g.cancelErr)
	}
	if err != nil {
		return Analysis{}, err
	}
	obs = append(obs, tieObs...)

	// Asked once the identity is known, because whether an unverifiable issuer is
	// load-bearing is a property of the SELECTED path's hops, not of the graph.
	path := g.pathFrom(identity.cert)
	if g.cancelErr != nil {
		return Analysis{}, fmt.Errorf("analyse cancelled: %w", g.cancelErr)
	}
	if err := g.oversizedIssuerError(path); err != nil {
		return Analysis{}, errors.New(appendCertIssues(
			err.Error()+in.keyIssues.suffix(), in.certIssues))
	}

	leaf := certs[identity.cert]

	// Role check.
	if g.isIssuer(identity.cert) {
		return Analysis{}, errors.New(appendCertIssues(fmt.Sprintf(
			"the private key matches %q, which is an issuer of another certificate in this bundle, not an end-entity certificate; if you meant to export that CA itself, remove the certificates it issued from the bundle%s",
			subjectForLog(leaf), in.keyIssues.suffix()), in.certIssues))
	}
	if leaf.BasicConstraintsValid && leaf.IsCA {
		obs = append(obs, Observation{
			Kind:   ObsCAAsIdentity,
			Detail: fmt.Sprintf("selected identity %q asserts IsCA", subjectForLog(leaf)),
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

	chain, extra, chainObs := g.assembleChain(path)
	obs = append(obs, chainObs...)
	obs = append(obs, chainValidityObservations(chain, now)...)
	obs = append(obs, chainIssuerEligibilityObservations(chain)...)

	a := Analysis{
		leaf:         leaf,
		chain:        chain,
		key:          in.signers[identity.key],
		extra:        extra,
		observations: obs,
	}
	return a, nil
}

// analysisInput is the parsed, deduplicated bundle analyseAt reasons over, plus
// the observations that describe what parsing had to leave out.
type analysisInput struct {
	// certs are the certificates in input order with duplicates removed, and
	// certAt maps each one back to its index among the file's CERTIFICATE
	// blocks, duplicates included.
	certs  []*x509.Certificate
	certAt []int
	// signers are the distinct usable private keys, and keyIssues the key blocks
	// that yielded none.
	signers      []crypto.Signer
	observations []Observation
	// certIssues are the certificate-file PEM blocks that were neither a
	// certificate nor an expected key companion.
	certIssues skippedBlocks
	keyIssues  keyDefects
	// duplicateCerts is how many blocks dedupeCerts removed, which the
	// leaf-not-first observation needs to name the original block count.
	duplicateCerts int
}

// prepareAnalysisInput parses both PEM files, drops the duplicates, and reports
// everything the operator has to be told about the input itself: unrelated blocks,
// duplicate certificates, more than one key, and key blocks that yielded no key.
func prepareAnalysisInput(certPEM, keyPEM []byte) (analysisInput, error) {
	certs, unrelatedBlocks, err := parseCertChain(certPEM)
	if err != nil {
		return analysisInput{}, fmt.Errorf("parse cert chain: %w", err)
	}
	keys, keyIssues, err := parsePrivateKeys(keyPEM)
	if err != nil {
		// The certificate-file evidence is folded in here for the reason
		// appendCertIssues documents: this refusal happens BEFORE analysisInput
		// exists, so neither ObsUnrelatedBlocksSkipped nor the identity-selection
		// refusals can report those blocks, and the operator would have to repair
		// the key before hearing that a certificate-shaped block was left out too.
		return analysisInput{}, fmt.Errorf("parse private key: %w%s", err, certIssuesSuffix(unrelatedBlocks))
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

	// Reported whether or not identity selection goes on to succeed.
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
		certIssues:     unrelatedBlocks,
		duplicateCerts: dupCerts,
	}, nil
}

// identityMatch names one (key, certificate) pair whose public halves agree, by
// index into the deduped key and certificate slices.
type identityMatch struct {
	key  int
	cert int
}

// certGraph holds the certificates plus everything this bundle can say about which
// of them issued which, derived once and shared by every consumer, plus how far each
// certificate is from a self-signed root present in the bundle.
type certGraph struct {
	// ctx is the analysis's cancellation signal, consulted only where a signature
	// verification is about to be paid for: maxVerifiableKeyBits and
	// maxVerifiablePublicExponent bound ONE verification to milliseconds, and one
	// analysis pays up to maxChainCerts^2 of them, so this is the granularity at
	// which the work is actually interruptible.
	ctx context.Context
	// cancelErr latches the first cancellation seen, so a partially built graph is
	// never mistaken for a complete one: analyseAt refuses to trust any verdict
	// derived from it, including an error verdict.
	cancelErr error
	now       time.Time
	certs     []*x509.Certificate
	// evidence holds the cheap facts for every ORDERED pair, flattened row-major by
	// child (edge indexes it).
	evidence []issuanceEvidence
	// proof memoises the cryptographic fact "certs[parent]'s public key verifies
	// certs[child]'s signature", keyed by (child, parent) and computed LAZILY,
	// because it is the only fact in the model whose cost the FILE dictates rather
	// than the certificate count: one verification runs from 69us at RSA-2048 to
	// milliseconds at the maxVerifiableKeyBits / maxVerifiablePublicExponent
	// ceilings, and one analysis can ask about maxChainCerts^2 pairs.
	proof map[[2]int]bool
	// selfSigned memoises the self-signature check per certificate, for the same
	// reason proof memoises edges: it is a real signature verification whose cost
	// the input file dictates, and three places ask — the root set, every hop of
	// pathFrom, and assembleChain's self-signed carve-out.
	selfSigned map[int]bool
	// canonicalSubjects[i] / canonicalIssuers[i] memoise the CANONICALISED raw subject
	// and issuer names, for the same reason proof memoises a signature: the decode is
	// O(name size) work the FILE dictates, and the linkage classifier asks for the
	// subject and the issuer of every certificate against every other one.
	canonicalSubjects []canonicalDN
	canonicalIssuers  []canonicalDN
	// candidateParents[i]: indices that could be issuers of certs[i] — linked to it
	// by key identifier or by name (byte-identical DER, or semantically equal after
	// an ASN.1 decode) and not excluded as key reuse, and either RFC-eligible to
	// issue or proven to have signed this child.
	candidateParents [][]int
	children         [][]int
	// distToRoot[i]: fewest parent hops from certs[i] to a self-signed certificate
	// in this bundle over the INCLUSIVE candidate edges, or -1 when none is
	// reachable.
	distToRoot []int
	// provenDistToRoot[i]: the same distance measured over PROVEN edges only,
	// or -1 when no root is reachable by signatures alone.
	provenDistToRoot []int
}

// issuanceEvidence is what this bundle can cheaply say about one ordered pair, "did
// certs[parent] issue certs[child]", as separate facts rather than one verdict.
type issuanceEvidence struct {
	// nameLinked reports that child's issuer name IS parent's subject name, at
	// either fidelity nameLink accepts: byte-identical DER, or semantically equal
	// after an ASN.1 decode (the RFC 5280 permitted-encoding case a byte comparison
	// cannot see).
	nameLinked bool
	// keyID reports RFC 5280's Authority Key Identifier on the child matching the
	// Subject Key Identifier on the parent.
	keyID bool
	// keyReuse reports that child and parent hold the SAME public key under the same
	// subject name — a regenerated self-signed certificate left beside the one it
	// replaces, which `openssl req -x509` produces with CA:TRUE by default.
	keyReuse bool
	// eligible reports whether parent's OWN extensions leave it able to issue
	// certificates under RFC 5280 4.2.1.9.
	eligible bool
}

// nameOrKeyIDLink reports whether a name or key-identifier relation ties the pair
// together at all, BEFORE the key-reuse exclusion.
func (e issuanceEvidence) nameOrKeyIDLink() bool {
	return e.nameLinked || e.keyID
}

// linked reports whether anything in this bundle ties the two certificates together
// at all.
func (e issuanceEvidence) linked() bool {
	return !e.keyReuse && e.nameOrKeyIDLink()
}

// maxVerifiableKeyBits bounds the public-key size this app will run a signature
// verification against.
const maxVerifiableKeyBits = 16384

// maxVerifiablePublicExponent bounds the RSA public exponent this app will run a
// signature verification against.
const maxVerifiablePublicExponent = 1 << 24

// verifiableKey reports whether pub is small enough to verify against.
func verifiableKey(pub crypto.PublicKey) bool {
	return unverifiableKeyReason(pub) == ""
}

// unverifiableKeyReason describes why a signature is too expensive to check
// against pub, or "" when it is not.
func unverifiableKeyReason(pub crypto.PublicKey) string {
	k, ok := pub.(*rsa.PublicKey)
	if !ok {
		return ""
	}
	switch {
	case k.N.BitLen() > maxVerifiableKeyBits:
		return fmt.Sprintf("holds a %d-bit RSA key, above the %d-bit modulus ceiling this app will verify a signature against",
			k.N.BitLen(), maxVerifiableKeyBits)
	case k.E > maxVerifiablePublicExponent:
		return fmt.Sprintf("holds an RSA key with public exponent %d, above the %d exponent ceiling this app will verify a signature against",
			k.E, maxVerifiablePublicExponent)
	}
	return ""
}

// unverifiableAnchorReason explains why a self-issued certificate's own signature
// could not be verified here, naming the two facts that are knowable from the
// certificate itself: this app's verification ceilings, and the signature
// algorithm. It replaces a diagnostic that listed three candidates and chose
// between none of them.
func unverifiableAnchorReason(c *x509.Certificate) string {
	if reason := unverifiableKeyReason(c.PublicKey); reason != "" {
		return "it " + reason + ", so no signature was checked against it at all"
	}
	return fmt.Sprintf("it is signed with %s, so either crypto/x509 refuses that algorithm or the certificate has been corrupted or re-signed since it was issued",
		signatureAlgorithmForLog(c))
}

// signatureAlgorithmForLog names a certificate's signature algorithm for a
// diagnostic. crypto/x509 renders an algorithm it does not implement as the bare
// number "0", which names nothing an operator can act on, so such an algorithm is
// named by the object identifier crypto/x509 retains in RawSignatureAlgorithm
// instead — the field that exists for exactly this case, where the code knows an
// algorithm is unrecognised and previously could not say which.
func signatureAlgorithmForLog(c *x509.Certificate) string {
	if c.SignatureAlgorithm != x509.UnknownSignatureAlgorithm {
		return c.SignatureAlgorithm.String()
	}
	oid, ok := signatureAlgorithmOID(c.RawSignatureAlgorithm)
	if !ok {
		return "an algorithm crypto/x509 does not implement"
	}
	return "the unimplemented algorithm " + oid.String()
}

// signatureAlgorithmOID reads the algorithm out of a certificate's DER
// AlgorithmIdentifier, refusing an identifier above maxOIDBytes for the reason
// oversizedKeyAlgorithmOIDError refuses one at the same ceiling: the value is
// certificate-controlled and asn1 allocates one int per encoded byte. The rendered
// result is therefore bounded without a text cap — an object identifier renders as
// dotted decimal arcs, and asn1 rejects an arc too large for an int.
func signatureAlgorithmOID(der []byte) (asn1.ObjectIdentifier, bool) {
	algorithm, _, ok := asn1ElementWithTag(der, asn1.TagSequence)
	if !ok {
		return nil, false
	}
	raw, _, ok := asn1ElementWithTag(algorithm.Bytes, asn1.TagOID)
	if !ok || raw.IsCompound || len(raw.Bytes) > maxOIDBytes {
		return nil, false
	}
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(raw.FullBytes, &oid); err != nil {
		return nil, false
	}
	return oid, true
}

// newCertGraph derives the evidence for every pair and the candidate edge set that
// follows from it.
func newCertGraph(ctx context.Context, certs []*x509.Certificate, now time.Time) *certGraph {
	g := &certGraph{
		ctx:               ctx,
		now:               now,
		certs:             certs,
		evidence:          make([]issuanceEvidence, len(certs)*len(certs)),
		candidateParents:  make([][]int, len(certs)),
		children:          make([][]int, len(certs)),
		proof:             make(map[[2]int]bool),
		selfSigned:        make(map[int]bool, len(certs)),
		canonicalSubjects: make([]canonicalDN, len(certs)),
		canonicalIssuers:  make([]canonicalDN, len(certs)),
	}
	g.fillEvidence()
	for child := range certs {
		for parent := range certs {
			if child == parent || !g.candidateEdge(child, parent) {
				continue
			}
			g.candidateParents[child] = append(g.candidateParents[child], parent)
			g.children[parent] = append(g.children[parent], child)
		}
	}
	g.computeDistances()
	return g
}

// fillEvidence computes the cheap facts for every ordered pair.
func (g *certGraph) fillEvidence() {
	eligible := make([]bool, len(g.certs))
	for i, c := range g.certs {
		eligible[i] = canIssueCertificates(c)
	}
	for child := range g.certs {
		for parent := range g.certs {
			if child == parent {
				continue
			}
			e := issuanceEvidence{
				nameLinked: g.nameLink(child, parent),
				keyID:      g.keyIDLink(child, parent),
				eligible:   eligible[parent],
			}
			// Only a pair something already links can be excluded as key reuse, and
			// the exclusion costs a public-key comparison, so it is asked last.
			if e.nameOrKeyIDLink() {
				e.keyReuse = g.sameNameSameKey(child, parent)
			}
			g.evidence[child*len(g.certs)+parent] = e
		}
	}
}

// edge returns the evidence for the ordered pair (child, parent).
func (g *certGraph) edge(child, parent int) issuanceEvidence {
	return g.evidence[child*len(g.certs)+parent]
}

// nameLink reports whether certs[child]'s issuer name IS certs[parent]'s subject
// name, preferring the byte comparison so an ordinary bundle never pays a decode. A
// byte-identical DER and a name that is only semantically equal both answer true;
// the RFC 5280 permitted-encoding difference is not a different answer.
func (g *certGraph) nameLink(child, parent int) bool {
	if bytes.Equal(g.certs[child].RawIssuer, g.certs[parent].RawSubject) {
		return true
	}
	childIssuer, issuerOK := g.issuerName(child)
	parentSubject, subjectOK := g.subjectName(parent)
	return sameCanonicalName(childIssuer, issuerOK, parentSubject, subjectOK)
}

// keyIDLink reports RFC 5280's Authority Key Identifier on the child matching the
// Subject Key Identifier on the parent.
func (g *certGraph) keyIDLink(child, parent int) bool {
	c, p := g.certs[child], g.certs[parent]
	return len(c.AuthorityKeyId) > 0 && len(p.SubjectKeyId) > 0 &&
		bytes.Equal(c.AuthorityKeyId, p.SubjectKeyId)
}

// sameNameSameKey reports the key-reuse exclusion issuanceEvidence.keyReuse records:
// the two certificates hold the same public key under the same subject name.
func (g *certGraph) sameNameSameKey(child, parent int) bool {
	c, p := g.certs[child], g.certs[parent]
	if !bytes.Equal(c.RawSubject, p.RawSubject) {
		childSubject, childOK := g.subjectName(child)
		parentSubject, parentOK := g.subjectName(parent)
		if !sameCanonicalName(childSubject, childOK, parentSubject, parentOK) {
			return false
		}
	}
	return samePublicKey(c.PublicKey, p.PublicKey)
}

// candidateEdge decides whether certs[parent] belongs in certs[child]'s candidate
// parent set: the pair has to be linked, and the parent has to be either eligible to
// issue certificates or proven to have signed this child.
func (g *certGraph) candidateEdge(child, parent int) bool {
	e := g.edge(child, parent)
	if !e.linked() {
		return false
	}
	return e.eligible || g.proven(child, parent)
}

// oversizedIssuerError refuses a bundle whose SELECTED chain has to GUESS a hop while
// a certificate named as that hop's issuer holds a key no signature can be checked
// against — an RSA modulus above maxVerifiableKeyBits, or a public exponent above
// maxVerifiablePublicExponent — naming which limit was crossed.
func (g *certGraph) oversizedIssuerError(path []int) error {
	for hop := 0; hop+1 < len(path); hop++ {
		child, selected := path[hop], path[hop+1]
		// The hop is established, so nothing competed for it: an unverifiable
		// namesake standing beside a proven parent can only be excluded, which
		// assembleChain's own observations report.
		if g.proven(child, selected) {
			continue
		}
		if err := g.unverifiableIssuerRival(child); err != nil {
			return err
		}
	}
	return nil
}

// unverifiableIssuerRival names the first certificate this bundle links as
// certs[child]'s issuer whose key no signature can be checked against, or nil when
// there is none.
func (g *certGraph) unverifiableIssuerRival(child int) error {
	for rival, c := range g.certs {
		if rival == child || !g.edge(child, rival).linked() {
			continue
		}
		reason := unverifiableKeyReason(c.PublicKey)
		if reason == "" {
			continue
		}
		return fmt.Errorf(
			"certificate %q is named as the issuer of another certificate in this bundle and %s; no signature can be checked against it, so its place in the chain could only be guessed; remove it from the bundle",
			subjectForLog(c), reason)
	}
	return nil
}

// proven reports whether certs[parent]'s public key produced certs[child]'s
// signature: the model's one CRYPTOGRAPHIC fact, and the only expensive one, so it is
// computed lazily and memoised.
func (g *certGraph) proven(child, parent int) bool {
	key := [2]int{child, parent}
	if got, ok := g.proof[key]; ok {
		return got
	}
	got := false
	c, p := g.certs[child], g.certs[parent]
	if verifiableKey(p.PublicKey) {
		if !g.verifiable() {
			// Not memoised: a cancelled pair is the ABSENCE of an answer, and
			// recording false would make any later read of this pair a silent
			// negative rather than a missing one.
			return false
		}
		got = p.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
	}
	g.proof[key] = got
	return got
}

// verifiable reports whether this analysis may still pay for a signature
// verification, latching the first cancellation it sees.
func (g *certGraph) verifiable() bool {
	if g.cancelErr != nil {
		return false
	}
	if err := g.ctx.Err(); err != nil {
		g.cancelErr = err
		return false
	}
	return true
}

// canIssueCertificates reports whether c's own extensions leave it able to issue
// certificates, mirroring the eligibility crypto/x509 applies to a parent without
// doing any signature work.
func canIssueCertificates(c *x509.Certificate) bool {
	return issuerIneligibilityReason(c) == ""
}

// issuerIneligibilityReason names why c's own extensions disqualify it from issuing
// certificates, or "" when they do not.
func issuerIneligibilityReason(c *x509.Certificate) string {
	switch {
	case c.Version == 3 && !c.BasicConstraintsValid:
		return "carries no basicConstraints extension, which RFC 5280 4.2.1.9 requires of a v3 certificate whose key verifies certificate signatures"
	case c.BasicConstraintsValid && !c.IsCA:
		return "asserts basicConstraints CA:false"
	case c.KeyUsage != 0 && c.KeyUsage&x509.KeyUsageCertSign == 0:
		return "states a keyUsage that omits keyCertSign"
	}
	return ""
}

// isIssuer reports whether certs[i] provably signed another certificate here.
func (g *certGraph) isIssuer(i int) bool {
	for _, child := range g.children[i] {
		if g.proven(child, i) {
			return true
		}
	}
	return false
}

// canonicalName ASN.1-decodes a raw DER distinguished name and re-encodes the decoded
// sequence, so semantic name equality is a byte comparison of two canonical forms
// rather than a reflect.DeepEqual walk over two decoded trees.
func canonicalName(raw []byte) ([]byte, bool) {
	// A name that cannot be read as an RDNSequence, or that carries trailing
	// bytes, is undecodable: it matches nothing rather than everything.
	var seq pkix.RDNSequence
	if rest, err := asn1.Unmarshal(raw, &seq); err != nil || len(rest) != 0 {
		return nil, false
	}
	canonical, err := asn1.Marshal(seq)
	if err != nil {
		return nil, false
	}
	return canonical, true
}

// sameCanonicalName reports whether two names are the same name.
func sameCanonicalName(a []byte, aOK bool, b []byte, bOK bool) bool {
	return aOK && bOK && bytes.Equal(a, b)
}

// canonicalDN is one memoised raw-name canonicalisation: the canonical DER of the
// decoded sequence, whether it could be produced, and whether it has been attempted
// at all (a name that cannot be read is a legitimate result worth caching, so "not
// yet asked" needs its own flag).
type canonicalDN struct {
	canonical []byte
	ok        bool
	cached    bool
}

// subjectName is canonicalName over certs[i]'s raw subject, memoised.
func (g *certGraph) subjectName(i int) ([]byte, bool) {
	if !g.canonicalSubjects[i].cached {
		canonical, ok := canonicalName(g.certs[i].RawSubject)
		g.canonicalSubjects[i] = canonicalDN{canonical: canonical, ok: ok, cached: true}
	}
	return g.canonicalSubjects[i].canonical, g.canonicalSubjects[i].ok
}

// issuerName is canonicalName over certs[i]'s raw issuer, memoised.
func (g *certGraph) issuerName(i int) ([]byte, bool) {
	if !g.canonicalIssuers[i].cached {
		canonical, ok := canonicalName(g.certs[i].RawIssuer)
		g.canonicalIssuers[i] = canonicalDN{canonical: canonical, ok: ok, cached: true}
	}
	return g.canonicalIssuers[i].canonical, g.canonicalIssuers[i].ok
}

// isSelfSigned reports whether certs[i] is its own issuer, which is what makes it
// a root rather than a link.
func (g *certGraph) isSelfSigned(i int) bool {
	if got, ok := g.selfSigned[i]; ok {
		return got
	}
	got := g.checkSelfSigned(i)
	if g.cancelErr != nil {
		// Same rule as proven's memo: a cancelled check produced no answer, so
		// nothing is recorded for i.
		return false
	}
	g.selfSigned[i] = got
	return got
}

// selfIssuedByName reports whether certs[i] names itself as its own issuer, at
// either name fidelity, WITHOUT asking whether the self-signature verifies.
func (g *certGraph) selfIssuedByName(i int) bool {
	c := g.certs[i]
	if bytes.Equal(c.RawSubject, c.RawIssuer) {
		return true
	}
	subject, subjectOK := g.subjectName(i)
	issuer, issuerOK := g.issuerName(i)
	return sameCanonicalName(subject, subjectOK, issuer, issuerOK)
}

// checkSelfSigned is isSelfSigned without the memo: the actual signature check.
func (g *certGraph) checkSelfSigned(i int) bool {
	c := g.certs[i]
	if !g.selfIssuedByName(i) {
		return false
	}
	if !verifiableKey(c.PublicKey) || !g.verifiable() {
		return false
	}
	return c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

// computeDistances fills both distance maps: distToRoot over the inclusive
// candidate edges, and provenDistToRoot over the proven edges only.
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
	g.provenDistToRoot = g.distancesFromRoots(roots, g.proven)
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
func (g *certGraph) selectIdentity(signers []crypto.Signer, keyIssues keyDefects, certIssues skippedBlocks) (identityMatch, []Observation, error) {
	matches, issuerObs := g.dropIssuerMatches(g.collectMatches(signers))
	switch len(matches) {
	case 0:
		return identityMatch{}, nil, g.noMatchError(len(signers), keyIssues, certIssues)
	case 1:
		return matches[0], issuerObs, nil
	default:
		best, obs, err := g.resolveAmbiguousMatches(matches, keyIssues, certIssues)
		if err != nil {
			return identityMatch{}, nil, err
		}
		return best, append(issuerObs, obs...), nil
	}
}

// dropIssuerMatches removes the matches whose certificate verifiably issued another
// certificate in this bundle, whenever at least one match did not, and reports the
// ones it dropped.
func (g *certGraph) dropIssuerMatches(matches []identityMatch) (kept []identityMatch, obs []Observation) {
	kept = make([]identityMatch, 0, len(matches))
	var dropped []identityMatch
	for _, m := range matches {
		if g.isIssuer(m.cert) {
			dropped = append(dropped, m)
			continue
		}
		kept = append(kept, m)
	}
	if len(kept) == 0 {
		return matches, nil
	}
	if len(dropped) > 0 {
		obs = append(obs, Observation{
			Kind: ObsIssuerMatchIgnored,
			Detail: fmt.Sprintf("%d certificate(s) matching a supplied key issued another certificate in this bundle, so they are no end-entity identity and were passed over: %s",
				len(dropped), subjectsForLog(g.certsOf(dropped))),
		})
	}
	return kept, obs
}

// certsOf resolves the certificates a set of matches selected, for a diagnostic
// that names them.
func (g *certGraph) certsOf(matches []identityMatch) []*x509.Certificate {
	certs := make([]*x509.Certificate, 0, len(matches))
	for _, m := range matches {
		certs = append(certs, g.certs[m.cert])
	}
	return certs
}

// collectMatches pairs every key with every certificate whose public half it
// owns.
func (g *certGraph) collectMatches(signers []crypto.Signer) []identityMatch {
	var matches []identityMatch
	for ki, s := range signers {
		for ci, c := range g.certs {
			if matched, supported := equalPublicKeys(c.PublicKey, s.Public()); supported && matched {
				matches = append(matches, identityMatch{key: ki, cert: ci})
			}
		}
	}
	return matches
}

// noMatchError explains that no certificate here belongs to any supplied key,
// naming an unverifiable key algorithm ahead of a plain mismatch when it is the
// only explanation left — every certificate uncomparable — and otherwise carrying
// it as a trailing clause on the mismatch sentence.
func (g *certGraph) noMatchError(usableKeys int, keyIssues keyDefects, certIssues skippedBlocks) error {
	uncomparable, firstUnverifiable := 0, -1
	for i, c := range g.certs {
		if !comparableCertKey(c.PublicKey) {
			uncomparable++
			if firstUnverifiable == -1 {
				firstUnverifiable = i
			}
		}
	}
	// The specific diagnosis is right only when an uncomparable certificate is the
	// ONLY explanation left.
	if firstUnverifiable >= 0 && uncomparable == len(g.certs) {
		c := g.certs[firstUnverifiable]
		var msg string
		if c.PublicKey == nil {
			// crypto/x509 parses a certificate whose SubjectPublicKeyInfo algorithm OID it
			// does not recognise and leaves PublicKey nil (parser.go's
			// UnknownPublicKeyAlgorithm branch), so %T would render "<nil>" here - the one
			// case where naming the algorithm matters most is the one where there is no
			// type to name. Say what happened instead.
			msg = fmt.Sprintf(
				"certificate %q uses a public key algorithm crypto/x509 does not recognise, so it cannot be verified against the private key; re-issue it with an RSA, ECDSA, Ed25519 or ML-DSA key",
				subjectForLog(c))
		} else {
			msg = fmt.Sprintf(
				"certificate %q has a public key of type %T that cannot be verified against the private key",
				subjectForLog(c), c.PublicKey)
		}
		// The uncomparable count only covers PARSED certificate blocks, so "the
		// unsupported key is the only explanation left" does not rule out a
		// certificate-shaped block that was skipped (a link relabelled TRUSTED
		// CERTIFICATE) or a damaged key block keyDefects already recorded.
		return errors.New(appendCertIssues(msg+keyIssues.suffix(), certIssues))
	}
	msg := fmt.Sprintf(
		"none of the %d distinct private key(s) in the key file matches any of the %d certificate(s) in the chain%s",
		usableKeys, len(g.certs), keyIssues.suffix())
	if firstUnverifiable >= 0 {
		// Same split as the all-uncomparable branch above, for the same reason: a nil
		// PublicKey is a key crypto/x509 could not READ, while a parsed key of an
		// unsupported type (a *dsa.PublicKey) was read fine and is merely not
		// comparable.
		if c := g.certs[firstUnverifiable]; c.PublicKey == nil {
			msg += fmt.Sprintf("; certificate %q holds a public key crypto/x509 could not read, so it was compared against no key",
				subjectForLog(c))
		} else {
			msg += fmt.Sprintf("; certificate %q has a public key of type %T that cannot be compared against the supplied private key, so it was compared against no key",
				subjectForLog(c), c.PublicKey)
		}
	}
	return errors.New(appendCertIssues(msg, certIssues))
}

// appendCertIssues attaches the certificate-file blocks that were neither a
// certificate nor a private key to a refusal sentence, and is shared by every
// refusal identity selection can return - every arm of noMatchError, the
// issuer-role refusal and the distinct-identities refusal - so no diagnosis can
// drop the clause: the observation that otherwise reports those blocks
// (ObsUnrelatedBlocksSkipped) is only reachable when the analysis SUCCEEDS.
func appendCertIssues(msg string, certIssues skippedBlocks) string {
	return msg + certIssuesSuffix(certIssues)
}

// certIssuesSuffix is the clause itself, shared with the pre-analysis key-parse
// refusal in prepareAnalysisInput so both wordings stay identical.
func certIssuesSuffix(certIssues skippedBlocks) string {
	if certIssues.count == 0 {
		return ""
	}
	return fmt.Sprintf("; the certificate file also holds %d block(s) that are neither a certificate nor a private key and were left out of the bundle (first %q)",
		certIssues.count, certIssues.firstTypeForLog())
}

// resolveAmbiguousMatches rules on more than one (key, certificate) match.
func (g *certGraph) resolveAmbiguousMatches(matches []identityMatch, keyIssues keyDefects, certIssues skippedBlocks) (identityMatch, []Observation, error) {
	if distinct := countDistinctKeys(matches); distinct > 1 {
		return identityMatch{}, nil, errors.New(appendCertIssues(fmt.Sprintf(
			"the input contains %d distinct certificate/key identities; this app converts one certificate/key pair per output (%s)%s",
			distinct, subjectsForLog(g.certsOf(matches)), keyIssues.suffix()), certIssues))
	}

	best := matches[0]
	for _, m := range matches[1:] {
		if g.betterIdentity(m.cert, best.cert) {
			best = m
		}
	}
	return best, []Observation{{
		Kind: ObsRenewedCertTie,
		Detail: fmt.Sprintf("one private key matches %d certificate(s) eligible as the identity; selected %q (NotBefore %s)",
			len(matches), subjectForLog(g.certs[best.cert]),
			g.certs[best.cert].NotBefore.UTC().Format(time.RFC3339)),
	}}, nil
}

// betterIdentity ranks two certificates that share a private key: valid at scan
// time first, then the later NotBefore, then a byte comparison of the full
// certificate DER.
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
func (g *certGraph) pathFrom(start int) []int {
	path := []int{start}
	onPath := make([]bool, len(g.certs))
	onPath[start] = true
	for cur := start; ; {
		// A self-signed certificate has no issuer BY CONSTRUCTION, so the walk must
		// end here.
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

// provenIssuerOnPath returns a certificate already on path whose signature over
// certs[terminal] is proven, or -1. bestParent excludes such a parent only because a
// certificate may not appear twice, so a diagnostic that reported its evidence as
// absent would state the opposite of what the walk proved.
func (g *certGraph) provenIssuerOnPath(terminal int, path []int) int {
	for _, p := range g.candidateParents[terminal] {
		if p != terminal && slices.Contains(path, p) && g.proven(terminal, p) {
			return p
		}
	}
	return -1
}

// bestParent picks the next hop from cur, or -1 when the chain ends here.
func (g *certGraph) bestParent(cur int, onPath []bool) int {
	for _, provenOnly := range []bool{true, false} {
		best := -1
		for _, p := range g.candidateParents[cur] {
			if onPath[p] || g.proven(cur, p) != provenOnly {
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
func (g *certGraph) betterParent(a, b int) bool {
	// Validity first.
	va, vb := validAt(g.certs[a], g.now), validAt(g.certs[b], g.now)
	if va != vb {
		return va
	}
	// Then route STRENGTH, ahead of the inclusive measure, for the same reason edge
	// strength outranks everything in bestParent: a candidate whose route to a root
	// is only a chain of NAME matches may be an impostor's, and preferring it over a
	// candidate whose route is proven all the way to an included root emits a chain
	// the consumer cannot validate.
	vra, vrb := g.provenDistToRoot[a] >= 0, g.provenDistToRoot[b] >= 0
	if vra != vrb {
		return vra
	}
	if vra && g.provenDistToRoot[a] != g.provenDistToRoot[b] {
		return g.provenDistToRoot[a] < g.provenDistToRoot[b]
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

// equalPublicKeys is the single home of the comparison rule every caller shares:
// every public key type crypto/x509 parses exposes Equal(crypto.PublicKey) bool,
// and a type that does not is unverifiable rather than unequal.
func equalPublicKeys(a, b crypto.PublicKey) (matched, supported bool) {
	matcher, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return false, false
	}
	return matcher.Equal(b), true
}

// samePublicKey reports whether two certificate public keys are the same key.
func samePublicKey(a, b crypto.PublicKey) bool {
	matched, _ := equalPublicKeys(a, b)
	return matched
}

// comparableCertKey reports whether a certificate's public key can be compared
// against a private key's public half at all.
func comparableCertKey(pub crypto.PublicKey) bool {
	_, supported := equalPublicKeys(pub, pub)
	return supported
}

// partitionIssuerEligible splits certificates into the ones that could still be
// somebody's issuer and the ones their own extensions disqualify, preserving input
// order in both halves.
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

// assembleChain builds the emitted chain for the identity at path[0] — the walked
// path is handed in, so it is the same slice oversizedIssuerError judged — the
// certificates deliberately left out of it, and the observations describing
// either outcome.
func (g *certGraph) assembleChain(path []int) (chain, extra []*x509.Certificate, obs []Observation) {
	leaf := g.certs[path[0]]
	chain = make([]*x509.Certificate, 0, len(path)-1)
	for _, i := range path[1:] {
		chain = append(chain, g.certs[i])
	}
	extra = g.outsidePath(path)

	// The discovered path ends where relationship evidence ran out.
	obs = append(obs, g.unprovenPathObservations(path)...)

	// Whether the terminus is proven self-signed and whether any certificate is left
	// over are independent facts, so the diagnostic is NOT gated on leftovers: a lone
	// CA-signed leaf, or a proven leaf/intermediate pair whose root is absent, has an
	// unfinished chain with nothing to append, and reporting nothing at all made
	// exactly that case silent.
	terminal := path[len(path)-1]
	if !g.isSelfSigned(terminal) {
		kept, disqualified := partitionIssuerEligible(extra)
		chain = append(chain, kept...)
		fallbackObs := []Observation{
			g.terminusObservation(terminal, g.provenIssuerOnPath(terminal, path), extra, kept, len(chain)),
		}
		if len(disqualified) > 0 {
			fallbackObs = append(fallbackObs, Observation{
				Kind: ObsExtraCertsExcluded,
				Detail: fmt.Sprintf("%d certificate(s) cannot issue certificates, so they are no issuer of %q and were excluded: %s",
					len(disqualified), subjectForLog(g.certs[terminal]), subjectsForLog(disqualified)),
			})
		}
		return chain, disqualified, append(obs, fallbackObs...)
	}

	if len(extra) > 0 {
		obs = append(obs, Observation{
			Kind: ObsExtraCertsExcluded,
			Detail: fmt.Sprintf("%d certificate(s) are not part of %q's chain and were excluded: %s",
				len(extra), subjectForLog(leaf), subjectsForLog(extra)),
		})
	}
	return chain, extra, obs
}

// terminusObservation states what became of a chain whose terminus is not proven
// self-signed. provenOnPath is the index of a certificate already on the emitted path
// that provably signed the terminus, or -1: with one, the walk stopped on a
// cross-certification cycle rather than on absent evidence.
func (g *certGraph) terminusObservation(terminal, provenOnPath int, extra, kept []*x509.Certificate, chainLen int) Observation {
	subject := subjectForLog(g.certs[terminal])
	leftovers := ""
	switch {
	case len(kept) > 0:
		leftovers = fmt.Sprintf("; %d of the remaining %d certificate(s) were kept rather than dropped and are in the bundle: %s",
			len(kept), len(extra), subjectsForLog(kept))
	case len(extra) > 0:
		leftovers = "; none of the remaining certificate(s) could be kept as chain material"
	}
	// A terminus that names ITSELF as its own issuer has its anchor right here, so
	// what is missing is the proof rather than the certificate, and neither
	// absent-anchor kind states that.
	if g.selfIssuedByName(terminal) {
		return Observation{
			Kind: ObsChainAnchorUnverifiable,
			Detail: fmt.Sprintf("the chain ends at %q, which names itself as its own issuer, but its self-signature could not be verified here (%s): a consumer that validates the chain will reject this anchor%s",
				subject, unverifiableAnchorReason(g.certs[terminal]), leftovers),
		}
	}
	if len(extra) == 0 {
		if provenOnPath >= 0 {
			return Observation{
				Kind: ObsChainTrustAnchorAbsent,
				Detail: fmt.Sprintf("the chain ends at %q, whose issuer %q is already in this chain: the two cross-certify each other, so the walk stopped rather than place a certificate twice, and no self-signed trust anchor is in the bundle",
					subject, subjectForLog(g.certs[provenOnPath])),
			}
		}
		completeness := "every certificate supplied is in the bundle, so nothing was left out"
		if chainLen == 0 {
			completeness = "the bundle holds the identity alone and no chain certificates at all, so a consumer that does not already hold the issuer cannot build a path; supply the full chain (Caddy/certbot fullchain.pem) if that was intended"
		}
		return Observation{
			Kind: ObsChainTrustAnchorAbsent,
			Detail: fmt.Sprintf("the chain ends at %q, whose issuer is not in the bundle; %s",
				subject, completeness),
		}
	}
	if provenOnPath >= 0 {
		return Observation{
			Kind: ObsChainUnverified,
			Detail: fmt.Sprintf("the only proven issuer of %q, %q, is already in this chain (the two cross-certify), so the walk stopped there%s",
				subject, subjectForLog(g.certs[provenOnPath]), leftovers),
		}
	}
	return Observation{
		Kind: ObsChainUnverified,
		Detail: fmt.Sprintf("no issuer of %q could be established from the bundle%s",
			subject, leftovers),
	}
}

// validAt reports whether c is inside its validity window at now.
func validAt(c *x509.Certificate, now time.Time) bool {
	return !now.Before(c.NotBefore) && !now.After(c.NotAfter)
}

// validityObservations reports an identity outside its validity window.
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
// outside their validity window at now.
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
				i+1, len(chain), subjectForLog(c),
				c.NotBefore.UTC().Format(time.RFC3339), c.NotAfter.UTC().Format(time.RFC3339)),
		})
	}
	return obs
}

// unprovenPathObservations reports every hop of the discovered path whose issuance
// this bundle could not prove by signature.
func (g *certGraph) unprovenPathObservations(path []int) []Observation {
	var obs []Observation
	for i := 1; i < len(path); i++ {
		child, parent := path[i-1], path[i]
		if g.proven(child, parent) {
			continue
		}
		// Say which evidence put the hop there.
		linkage := "matches the issuer name of"
		if !g.edge(child, parent).nameLinked {
			linkage = "carries the subject key identifier named as the authority key identifier of"
		}
		obs = append(obs, Observation{
			Kind: ObsChainEdgeUnprovenIssuer,
			Detail: fmt.Sprintf(
				"chain certificate %d, %q, %s %q but no signature here proves it issued that certificate; it was included because no certificate the chain walk could still place proved it signed that certificate, so a consumer may be unable to verify the chain",
				i, subjectForLog(g.certs[parent]), linkage,
				subjectForLog(g.certs[child])),
		})
	}
	return obs
}

// chainIssuerEligibilityObservations reports certificates in the EMITTED chain
// that RFC 5280 4.2.1.9 disqualifies from issuing certificates, without removing
// them.
func chainIssuerEligibilityObservations(chain []*x509.Certificate) []Observation {
	var obs []Observation
	for i, c := range chain {
		reason := issuerIneligibilityReason(c)
		if reason == "" {
			continue
		}
		obs = append(obs, Observation{
			Kind: ObsChainCertCannotIssue,
			Detail: fmt.Sprintf(
				"chain certificate %d of %d, %q, %s; it is included in the bundle because it is part of the chain established here, but a strict consumer will reject the chain until that CA is re-issued",
				i+1, len(chain), subjectForLog(c), reason),
		})
	}
	return obs
}

// dedupeCerts removes byte-identical certificates, keeping input order, and
// reports how many were dropped plus, for each kept certificate, its ORIGINAL
// index in the input slice.
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
func dedupeSigners(signers []crypto.Signer) []crypto.Signer {
	out := make([]crypto.Signer, 0, len(signers))
	for _, s := range signers {
		dup := false
		for _, kept := range out {
			if samePublicKey(kept.Public(), s.Public()) {
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
		fmt.Fprintf(&b, "%q", subjectForLog(c))
	}
	return b.String()
}
