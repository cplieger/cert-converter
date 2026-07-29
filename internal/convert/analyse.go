package convert

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"reflect"
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
	// ObsChainCertCannotIssue reports a certificate in the EMITTED chain whose own
	// extensions leave it unable to issue certificates under RFC 5280 4.2.1.9 (no
	// basic constraints on a v3 certificate, CA:false, or a stated keyUsage without
	// keyCertSign). It is reported rather than acted on: this app converts formats
	// and holds no trust store, PKCS#12 CA bags are a bag of certificates rather
	// than a validated path (RFC 7292 imposes no path-validation semantics on them),
	// and a certificate that demonstrably SIGNED the one below it is chain material
	// whatever its extensions claim. So the certificate is carried and the operator
	// is told its CA is non-compliant and that a strict path validator will reject
	// the chain — the thing they have to act on with their PKI, not something this
	// converter can fix by dropping content.
	ObsChainCertCannotIssue ObservationKind = "chain-cert-cannot-issue"
	// ObsUnrelatedBlocksSkipped reports PEM blocks in the CERTIFICATE file that are
	// neither a certificate nor a private key — an OpenSSL "TRUSTED CERTIFICATE",
	// the legacy "X509 CERTIFICATE" alias, a stray CERTIFICATE REQUEST — and were
	// therefore not part of the bundle. Two labels are deliberately not reported: a
	// private-key block (a combined cert+key file is a supported input) and, in a
	// file that also holds the EC private key it describes, EC PARAMETERS (the
	// combined `openssl ecparam -genkey` bundle); isExpectedCertFilePassenger owns
	// that set. EC PARAMETERS with no EC key beside it IS reported: nothing then
	// establishes it as a companion, and it really was left out of the bundle.
	ObsUnrelatedBlocksSkipped ObservationKind = "unrelated-blocks-skipped"
	// ObsUnusableKeyBlocksSkipped reports PEM blocks in the KEY file that yielded no
	// usable key — unparseable DER, armour encoding/pem could not decode, ciphertext,
	// or a label naming no key format this app reads — while another block did yield
	// one, so conversion continued. The canonical cause is a rotation that appended a
	// damaged or encrypted key next to the old one: the old key still matches today,
	// and the only other signal is the "no certificate matches any key" failure a
	// later renewal produces.
	ObsUnusableKeyBlocksSkipped ObservationKind = "unusable-key-blocks-skipped"
	// ObsIssuerMatchIgnored reports that a supplied key also matched a certificate
	// that verifiably issued another certificate in this bundle. Such a certificate
	// is no end-entity identity, so the end-entity certificate that also matched was
	// selected and this one passed over. The canonical causes are one key reused for
	// both a CA and the leaf it signed, and a key file holding the leaf's key and the
	// CA's key together.
	ObsIssuerMatchIgnored ObservationKind = "issuer-match-ignored"
	// ObsKeyReusedAcrossCerts reports that one private key in the key file serves
	// several certificates in this input, at least one of which issued another
	// certificate here: the operator has a single key acting as both a CA key and an
	// end-entity key. Legal, and the bundle converts, but a single key compromise
	// then affects both certificates and neither can be retired without the other,
	// which is a fact about their PKI worth acting on.
	//
	// It is emitted ALONGSIDE ObsIssuerMatchIgnored and states a different fact: that
	// one names a match this app set aside for identity selection, this one names the
	// key reuse itself. Nothing else reports it — dropping the issuer match collapses
	// the candidate set to one, so the ambiguity report that used to mention the
	// second certificate is never reached. It is deliberately NOT ObsRenewedCertTie:
	// a CA is not a renewal of the leaf it signed, and that kind's name would say so.
	ObsKeyReusedAcrossCerts ObservationKind = "key-reused-across-certs"
	// ObsChainEdgeUnprovenIssuer reports a certificate in the EMITTED chain that is
	// there because its subject matches the issuer name (or the authority key
	// identifier) of the certificate below it, while NO signature proves it issued
	// that certificate. bestParent selects such a parent only when no proven
	// candidate exists — an algorithm crypto/x509 refuses, a key above the
	// verification ceilings, a public key crypto/x509 left nil (a legacy DSA
	// certificate parses that way, so proven is false for every hop touching it), or
	// a bundle carrying a same-named certificate while the real signer is absent —
	// and nothing said so whenever the path still ended at a self-signed certificate
	// or consumed every certificate in the bundle: ObsChainUnverified fires only for
	// a terminus that is not proven self-signed WITH certificates left over. The
	// bundle still converts (this package holds no trust store), but a PKCS#12 CA bag
	// a consumer imports into a trust store is the wrong place for an unproven link
	// to be silent.
	ObsChainEdgeUnprovenIssuer ObservationKind = "chain-edge-unproven-issuer"
)

// Noise reports whether an observation of this kind is a benign artefact of how the
// input file was assembled rather than something the operator probably did not intend.
// It lives beside the constants because the distinction is a property of the KIND, known
// where the kinds are minted; how loudly a caller reports each class stays the caller's
// choice.
func (k ObservationKind) Noise() bool {
	return k == ObsDuplicateCerts
}

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

	identity, tieObs, err := g.selectIdentity(in.signers, in.keyIssues, in.certIssues)
	if err != nil {
		return Analysis{}, err
	}
	obs = append(obs, tieObs...)

	leaf := certs[identity.cert]

	// Role check. A certificate that signed another certificate in this bundle
	// is an issuer, not an end-entity certificate, and emitting it as the
	// identity would produce a bundle no consumer can use as a server identity.
	// This is the case a positional "leaf = certs[0]" rule cannot see.
	//
	// It names the key-file defects too: a key file holding the CA's key plus a
	// damaged or encrypted appended leaf key parses only the CA key, which matches
	// the CA, so the operator lands here and is told to remove certificates from a
	// bundle that is fine while the unreadable key block goes unmentioned.
	if g.isIssuer(identity.cert) {
		return Analysis{}, fmt.Errorf(
			"the private key matches %q, which is an issuer of another certificate in this bundle, not an end-entity certificate; if you meant to export that CA itself, remove the certificates it issued from the bundle%s",
			boundSubject(leaf.Subject.String()), in.keyIssues.suffix())
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

	chain, extra, chainObs := g.assembleChain(identity.cert)
	obs = append(obs, chainObs...)
	obs = append(obs, chainValidityObservations(chain, now)...)
	obs = append(obs, chainIssuerEligibilityObservations(chain)...)

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
	// certIssues are the certificate-file PEM blocks that were neither a
	// certificate nor an expected key companion. Carried alongside keyIssues
	// rather than only as an observation, because the observations are dropped
	// when identity selection fails, and that is exactly when a certificate-shaped
	// block left out of the bundle is the likely cause of the mismatch.
	certIssues skippedBlocks
	keyIssues  keyDefects
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
//
// "Did certs[parent] issue certs[child]" is deliberately NOT a boolean here. It is
// four independent facts per ordered pair (issuanceEvidence): how the names line up
// and with what fidelity, whether the key identifiers line up, whether parent's key
// provably produced child's signature, and whether parent's own extensions permit it
// to issue certificates at all. One boolean forces every consumer to accept some
// other consumer's choice of which evidence counts, which is exactly how a second
// issuance predicate once grew beside this graph: the app could PROVE a CA issued the
// leaf while selecting the identity and still fail to place that proven edge in the
// ordered chain, falling back to an unordered additive tail instead.
//
// With the facts separate, each consumer asks the question it actually has: chain
// assembly and ranking want the strongest PROVEN path (a proven edge outranks a
// merely linked one), identity role selection wants cryptographic proof alone, and
// the diagnostics want eligibility plus the reason a link is weak — which are two
// different operator messages, "the name matched but the signature did not verify"
// (a possible impostor, reported by ObsChainUnverified) and "the signature verified
// but the CA is not RFC-eligible" (a non-compliant CA, reported by
// ObsChainCertCannotIssue), and nothing here may merge them.
//
// This is a LAYOUT and DIAGNOSTICS structure, not a certificate-path validator. The
// app holds no trust store and validates nothing for security: the graph decides
// which certificates enter the PKCS#12 bag sequence and in what order, and what the
// operator is told about them. A proven edge here does not mean the chain is
// trusted, and trust semantics must not be added to it.
type certGraph struct {
	now   time.Time
	certs []*x509.Certificate
	// evidence holds the cheap facts for every ORDERED pair, flattened row-major by
	// child (edge indexes it). Filled eagerly by newCertGraph, because every fact in
	// it is a byte, OID or decoded-name comparison over data already in memory. The
	// one expensive fact — the signature — is deliberately not in here; see proof.
	evidence []issuanceEvidence
	// proof memoises the cryptographic fact "certs[parent]'s public key verifies
	// certs[child]'s signature", keyed by (child, parent) and computed LAZILY,
	// because it is the only fact in the model whose cost the FILE dictates rather
	// than the certificate count: one verification runs from 69us at RSA-2048 to
	// milliseconds at the maxVerifiableKeyBits / maxVerifiablePublicExponent
	// ceilings, and one analysis can ask about maxChainCerts^2 pairs.
	//
	// Two rules bound it, both enforced by proven: a pair with no name or key
	// linkage at all is NEVER verified (nothing links it, so no consumer's question
	// turns on its signature), and every answer is memoised, so candidate
	// construction, the proven-distance walk, chain assembly and the identity role
	// check together pay at most one verification per pair.
	proof map[[2]int]bool
	// selfSigned memoises the self-signature check per certificate, for the same
	// reason verified memoises edges: it is a real signature verification whose cost
	// the input file dictates, and three places ask — the root set, every hop of
	// pathFrom, and assembleChain's self-signed carve-out.
	selfSigned map[int]bool
	// decodedSubjects[i] / decodedIssuers[i] memoise the ASN.1-decoded raw subject
	// and issuer names, for the same reason proof memoises a signature: the decode is
	// O(name size) work the FILE dictates, and the linkage classifier asks for the
	// subject and the issuer of every certificate against every other one. This is
	// the ONE decoded-name cache in the package; semantic name equality is computed
	// here, once per certificate, and stored as a fact on the edge. Measured on a
	// 64-block, 8.87 MB bundle inside both existing caps: 12.4s of a 15.2s Analyse
	// went on repeated decodes, against 97ms to parse all 64 blocks once.
	decodedSubjects []decodedDN
	decodedIssuers  []decodedDN
	// candidateParents[i]: indices that could be issuers of certs[i] — linked to it
	// by key identifier or by name (byte-identical DER, or semantically equal after
	// an ASN.1 decode) and not excluded as key reuse, and either RFC-eligible to
	// issue or proven to have signed this child. The inclusive signal, used to
	// assemble the emitted chain, where over-including costs one stray certificate
	// and under-including silently breaks path building at the consumer.
	//
	// It is wider than the PROVEN set for causes unrelated to the chain being wrong:
	// crypto/x509 refuses some signature algorithms outright (MD5, DSA), a key above
	// the verification ceilings is never verified, and a bundle can carry a
	// same-named certificate while the real signer is absent. Treating "could not
	// prove related" as "proved unrelated" drops genuine CA certificates.
	candidateParents [][]int
	children         [][]int
	// distToRoot[i]: fewest parent hops from certs[i] to a self-signed certificate
	// in this bundle over the INCLUSIVE candidate edges, or -1 when none is
	// reachable. Kept for the bundles where no signature can be checked at all — a
	// refused algorithm, an over-ceiling key, an absent real signer.
	distToRoot []int
	// provenDistToRoot[i]: the same distance measured over PROVEN edges only,
	// or -1 when no root is reachable by signatures alone.
	//
	// The inclusive measure cannot tell a parent with a real route to a root apart
	// from one whose route depends on an unprovable hop: two intermediates sharing
	// a subject and a key, one continuing to an included root that actually signed
	// it and one naming an impostor root of the same name holding a DIFFERENT key,
	// score identically. Ranking on the inclusive measure alone therefore emitted a
	// chain whose selected intermediate did not verify under the root beside it,
	// while the fully proven alternative sat in the same input.
	provenDistToRoot []int
	// proofChecks counts the signature verifications proven actually paid for.
	// Nothing in production reads it: the lazy cost model above is otherwise
	// unobservable, and an eager regression there is a performance defect no
	// assertion about Analyse's result can catch. Self-signature checks are not
	// counted — those are per certificate, one each, bounded by selfSigned. It sits
	// last because it is the struct's only non-pointer word (govet fieldalignment).
	proofChecks int
}

// nameLinkage says how a child's issuer name relates to a candidate parent's subject
// name, and with what fidelity. The fidelity is kept rather than collapsed to a
// boolean because the two cases are reached by different work and mean different
// things to a reader: an exact match is a byte comparison and the ordinary shape of a
// well-formed bundle, while a semantic match is an ASN.1 decode of both names and the
// RFC 5280 permitted-encoding case (a leaf naming its issuer as a UTF8String where
// the CA's subject uses the canonical encoding) that a byte comparison cannot see.
type nameLinkage uint8

const (
	// nameLinkNone means the two names are not the same name.
	nameLinkNone nameLinkage = iota
	// nameLinkSemantic means the decoded names are equal but their DER differs.
	nameLinkSemantic
	// nameLinkExact means the raw DER of the two names is byte-identical.
	nameLinkExact
)

// issuanceEvidence is what this bundle can cheaply say about one ordered pair, "did
// certs[parent] issue certs[child]", as separate facts rather than one verdict. The
// fourth fact, the signature, is not here: it is the expensive one, so it is asked
// lazily through certGraph.proven and only for a pair this record already links.
//
// Each field is a fact about the certificates, never a decision about them. Who is a
// candidate parent, who is an issuer, and what the operator is told are decisions,
// and they are made by the consumers that hold those questions.
type issuanceEvidence struct {
	// name is how child's issuer name relates to parent's subject name.
	name nameLinkage
	// keyID reports RFC 5280's Authority Key Identifier on the child matching the
	// Subject Key Identifier on the parent. A byte comparison rather than a
	// signature check, so it is algorithm-agnostic and survives a permitted
	// name-encoding difference.
	keyID bool
	// keyReuse reports that child and parent hold the SAME public key under the same
	// subject name — a regenerated self-signed certificate left beside the one it
	// replaces, which `openssl req -x509` produces with CA:TRUE by default. Each
	// verifies against the other, so a naive rule records a mutual issuance edge,
	// both then look like issuers, and the identity role check rejects the bundle
	// outright. Key reuse is not issuance: a certificate cannot have issued another
	// certificate carrying its own key. It is computed only for a pair that is
	// otherwise linked, because there is nothing to exclude otherwise.
	keyReuse bool
	// eligible reports whether parent's OWN extensions leave it able to issue
	// certificates under RFC 5280 4.2.1.9. It is POLICY — what a strict path
	// validator will accept — never a fact about what happened, which is why it can
	// never on its own remove a certificate a signature puts in the chain.
	eligible bool
}

// linked reports whether anything in this bundle ties the two certificates together
// at all. It is the gate on the expensive fact: a pair with no name and no key-id
// relationship has nothing for a signature to confirm, so proven never verifies one.
func (e issuanceEvidence) linked() bool {
	return !e.keyReuse && (e.name != nameLinkNone || e.keyID)
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
//
// The private-key parser reads the same ceiling (convert.go oversizedRSAKeyError)
// for the mirror-image reason on the other half of the pair: x509's own parsers pay
// RSA precomputation on file-supplied integers before they can reject a key, so a
// key above the ceiling stalls the scan goroutine to produce a bundle whose
// signatures this app would refuse to check anyway. One constant, so the two halves
// of the pair cannot disagree about what this app will read.
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

// newCertGraph derives the evidence for every pair and the candidate edge set that
// follows from it, or refuses the bundle outright when a candidate issuer's key is
// one no signature can be checked against.
//
// Two passes, in this order for a cost reason. The first fills issuanceEvidence for
// every ordered pair from byte, OID and decoded-name comparisons alone — no
// signature work, and one name decode per certificate however many pairs read it.
// The second turns that into candidate edges, and it is the only place the expensive
// fact is reached for during construction: a pair the evidence links whose parent is
// NOT RFC-eligible is admitted only when it demonstrably signed the child, which is
// the one case where the cheap answer would discard a real signer.
//
// Cryptographic proof here (certGraph.proven) is the raw question "did parent's key
// produce child's signature", NOT path validation and not RFC 5280 parent policy.
// Eligibility is a separate fact, so a consumer that wants both asks for both, and
// nothing has to accept the other's bundle of the two. It does NOT check validity
// periods, path length, name constraints, EKU nesting, unhandled critical extensions
// or revocation; identity role is enforced separately by Analyse's own issuer check.
//
// The refusal is decided on the candidate edges alone, before either distance walk
// runs, so a bundle this app will not reason about costs it no signature
// verifications at all.
func newCertGraph(certs []*x509.Certificate, now time.Time) (*certGraph, error) {
	g := &certGraph{
		now:              now,
		certs:            certs,
		evidence:         make([]issuanceEvidence, len(certs)*len(certs)),
		candidateParents: make([][]int, len(certs)),
		children:         make([][]int, len(certs)),
		proof:            make(map[[2]int]bool),
		selfSigned:       make(map[int]bool, len(certs)),
		decodedSubjects:  make([]decodedDN, len(certs)),
		decodedIssuers:   make([]decodedDN, len(certs)),
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
	if err := g.oversizedIssuerError(); err != nil {
		return nil, err
	}
	g.computeDistances()
	return g, nil
}

// fillEvidence computes the cheap facts for every ordered pair. Issuer eligibility is
// a property of the PARENT alone, so it is decided once per certificate and copied
// onto that parent's edges rather than re-derived per pair.
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
				name:     g.nameLink(child, parent),
				keyID:    g.keyIDLink(child, parent),
				eligible: eligible[parent],
			}
			// Only a pair something already links can be excluded as key reuse, and
			// the exclusion costs a public-key comparison, so it is asked last.
			if e.name != nameLinkNone || e.keyID {
				e.keyReuse = g.sameNameSameKey(child, parent)
			}
			g.evidence[child*len(g.certs)+parent] = e
		}
	}
}

// edge returns the evidence for the ordered pair (child, parent). A self-pair carries
// the zero value, which links nothing: a certificate is not its own issuer here, and
// self-signature is isSelfSigned's separate question.
func (g *certGraph) edge(child, parent int) issuanceEvidence {
	return g.evidence[child*len(g.certs)+parent]
}

// nameLink classifies certs[child]'s issuer name against certs[parent]'s subject
// name, preferring the byte comparison so an ordinary bundle never pays a decode.
//
// "Semantically equal" is the ASN.1-decoded name, NOT pkix.Name: crypto/x509
// documents pkix.Name as an approximation of a distinguished name and says accurate
// name work must unmarshal RawSubject/RawIssuer. Round-tripping through
// pkix.Name.ToRDNSequence rebuilds the known attributes in a FIXED order, flattens
// multi-entry RDNs and drops non-standard attribute types, so `O=Acme, CN=x` and
// `CN=x, O=Acme` — two different DNs under RFC 5280 — compared equal, and a CA whose
// key had signed a certificate naming that other DN read as its issuer. Decoding the
// raw names instead keeps RDN order, multi-valued grouping and unknown OIDs, while
// still normalising the permitted DirectoryString tag difference because both decode
// to the same Go string.
//
// A name that cannot be decoded matches nothing: an unreadable name is compared
// against no other name rather than against everything.
func (g *certGraph) nameLink(child, parent int) nameLinkage {
	if bytes.Equal(g.certs[child].RawIssuer, g.certs[parent].RawSubject) {
		return nameLinkExact
	}
	childIssuer, issuerOK := g.issuerName(child)
	parentSubject, subjectOK := g.subjectName(parent)
	if sameDecodedName(childIssuer, issuerOK, parentSubject, subjectOK) {
		return nameLinkSemantic
	}
	return nameLinkNone
}

// keyIDLink reports RFC 5280's Authority Key Identifier on the child matching the
// Subject Key Identifier on the parent. Both must be present: two certificates that
// simply carry no key identifiers are not thereby related.
func (g *certGraph) keyIDLink(child, parent int) bool {
	c, p := g.certs[child], g.certs[parent]
	return len(c.AuthorityKeyId) > 0 && len(p.SubjectKeyId) > 0 &&
		bytes.Equal(c.AuthorityKeyId, p.SubjectKeyId)
}

// sameNameSameKey reports the key-reuse exclusion issuanceEvidence.keyReuse records:
// the two certificates hold the same public key under the same subject name. The name
// comparison accepts either fidelity, because a regenerated certificate re-encoding
// its own subject is the same shape of artefact as one repeating it byte for byte.
func (g *certGraph) sameNameSameKey(child, parent int) bool {
	c, p := g.certs[child], g.certs[parent]
	if !bytes.Equal(c.RawSubject, p.RawSubject) {
		childSubject, childOK := g.subjectName(child)
		parentSubject, parentOK := g.subjectName(parent)
		if !sameDecodedName(childSubject, childOK, parentSubject, parentOK) {
			return false
		}
	}
	return samePublicKey(c.PublicKey, p.PublicKey)
}

// candidateEdge decides whether certs[parent] belongs in certs[child]'s candidate
// parent set: the pair has to be linked, and the parent has to be either eligible to
// issue certificates or proven to have signed this child.
//
// The asymmetry is the whole point: eligibility is a POLICY ASSERTION about whether a
// certificate SHOULD have issued anything, while a signature is GROUND TRUTH about
// whether it DID. This app converts formats and holds no trust store, so policy
// informs diagnostics (ObsChainCertCannotIssue names such a certificate wherever it
// lands in the emitted chain) and never silently removes content: a legacy internal
// CA minted without basicConstraints — the shape a bare `openssl req -x509` produces
// — really did sign the leaf, and dropping its edge dropped the only CA bag the
// operator's PFX needed. What the gate still keeps out is a certificate that merely
// LOOKS related: a same-named stranger asserting CA:false signed nothing here, so
// admitting it would emit a chain no consumer can build a path through and no
// evidence supports.
//
// The linkage question is answered before the eligibility one, so a signature is
// checked here only for a pair that is already linked and whose parent is ineligible.
// Every other pair costs comparisons alone.
func (g *certGraph) candidateEdge(child, parent int) bool {
	e := g.edge(child, parent)
	if !e.linked() {
		return false
	}
	return e.eligible || g.proven(child, parent)
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
		// A certificate nothing here names as its issuer — by name at either fidelity,
		// nor by authority key identifier — is never a parent in a signature check, so
		// its size decides nothing: it can only be excluded, or kept by the additive
		// fallback, and both say so out loud. The question is what the bundle NAMES,
		// not what survived candidate construction: see namedAsIssuer.
		reason := unverifiableKeyReason(c.PublicKey)
		if reason == "" || !g.namedAsIssuer(i) {
			continue
		}
		return fmt.Errorf(
			"certificate %q is named as the issuer of another certificate in this bundle and %s; no signature can be checked against it, so its place in the chain could only be guessed; remove it from the bundle",
			boundSubject(c.Subject.String()), reason)
	}
	return nil
}

// namedAsIssuer reports whether any other certificate in this bundle names
// certs[parent] as its issuer — by name at either fidelity, or by authority key
// identifier — whether or not that pair survived candidate construction.
//
// The candidate set is the wrong question for the oversized refusal. A certificate
// whose own extensions disqualify it from issuing enters candidateParents ONLY when
// a signature proves the edge (candidateEdge), and an over-ceiling key can never be
// verified, so keying the refusal on children[] let through exactly the decoy
// substitution it exists to refuse: leaf, its real over-ceiling issuer carrying
// CA:false or no basicConstraints, and a same-subject certificate with an ordinary
// key that then wins the chain unverified.
func (g *certGraph) namedAsIssuer(parent int) bool {
	for child := range g.certs {
		if child != parent && g.edge(child, parent).linked() {
			return true
		}
	}
	return false
}

// proven reports whether certs[parent]'s public key produced certs[child]'s
// signature: the model's one CRYPTOGRAPHIC fact, and the only expensive one, so it is
// computed lazily and memoised.
//
// It is the RAW question, with no issuer-eligibility gate folded in.
// x509.CheckSignatureFrom cannot answer it, because it applies RFC 5280 4.2.1.9 to
// the parent before it looks at any signature, so an eligibility question and a
// signature question asked through it are inseparable — and inseparable is exactly
// what made two consumers disagree about what an issuance edge is. Checking with the
// parent's own public key separates them, as checkSelfSigned already does for the
// self-signature, and a consumer that wants "verified AND RFC-eligible" reads both
// facts. crypto/x509's CheckSignature also accepts SHA-1 where CheckSignatureFrom
// refuses it, so a legacy SHA-1 chain becomes provable rather than merely plausible.
//
// Two bounds, both load-bearing. A pair with no linkage is refused without a
// verification: nothing ties those certificates together, so no consumer's question
// turns on the answer, and verifying anyway would put a file-controlled modexp on
// every one of the maxChainCerts^2 pairs. A parent key above either verification
// ceiling is refused too, which is the cost the ceilings exist to refuse; after
// newCertGraph's oversizedIssuerError that state is only reachable for a certificate
// this bundle names as nobody's issuer.
func (g *certGraph) proven(child, parent int) bool {
	key := [2]int{child, parent}
	if got, ok := g.proof[key]; ok {
		return got
	}
	got := false
	if g.edge(child, parent).linked() {
		c, p := g.certs[child], g.certs[parent]
		if verifiableKey(p.PublicKey) {
			g.proofChecks++
			got = p.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
		}
	}
	g.proof[key] = got
	return got
}

// canIssueCertificates reports whether c's own extensions leave it able to issue
// certificates, mirroring the eligibility crypto/x509 applies to a parent without
// doing any signature work. It is issuerIneligibilityReason's predicate form, so
// the gate and every message that names a disqualification cannot drift.
//
// This answers only whether c may be somebody's PARENT, and only as POLICY: it says
// what a strict path validator will accept, never what happened. Whether c actually
// signed a certificate here is certGraph.proven's question, and a signature outranks
// this answer wherever the two disagree (candidateEdge). Whether c is SELF-SIGNED is a
// third question, and isSelfSigned deliberately answers it without this gate: a
// self-signed certificate with no basic constraints is still a root here, even
// though a strict validator would let it issue nothing else.
func canIssueCertificates(c *x509.Certificate) bool {
	return issuerIneligibilityReason(c) == ""
}

// issuerIneligibilityReason names why c's own extensions disqualify it from issuing
// certificates, or "" when they do not.
//
// Three disqualifications, each of them positive proof rather than absent evidence:
// a v3 certificate carrying no Basic Constraints at all (RFC 5280 4.2.1.9 says such
// a key MUST NOT verify certificate signatures, which is why CheckSignatureFrom
// refuses it as a parent), one whose Basic Constraints say CA:false, and one whose
// stated KeyUsage omits KeyCertSign. An absent KeyUsage (the zero value) states
// nothing, so it disqualifies nothing.
//
// The reason is prose an operator can act on, because the only thing this app does
// with a disqualification is TELL them: the certificate stays in the bundle when a
// signature puts it there, and the fix is in their PKI, not in the conversion.
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
//
// Cryptographic proof is the only evidence that counts, and it is the same proof
// every other consumer reads. A name match alone would reject an identity because
// some unrelated certificate happens to claim it as issuer, which an attacker or a
// careless paste could arrange; conversely, refusing to look past a byte-identical
// name match would miss the issuance this bundle can actually prove — a leaf naming
// its CA through a permitted encoding difference with no key identifiers, where the
// CA then competed with its own leaf for identity, won on NotBefore, and produced a
// PFX whose identity was the CA.
//
// Both of those now come out of one graph: the candidate edges already include the
// semantically-equal-name case and already exclude key reuse, so this reads the same
// edges chain assembly and ranking read, and the two can no longer disagree about
// what an issuance is. RFC eligibility is deliberately NOT consulted: a legacy CA
// with no basicConstraints that demonstrably signed the certificate beside it is an
// issuer of it, whatever a strict validator would say about its extensions.
func (g *certGraph) isIssuer(i int) bool {
	for _, child := range g.children[i] {
		if g.proven(child, i) {
			return true
		}
	}
	return false
}

// decodedName ASN.1-decodes a raw DER distinguished name. The false result means
// the name could not be read as an RDNSequence (or carried trailing bytes), which
// no caller may treat as a match: an undecodable name is compared against nothing.
func decodedName(raw []byte) (pkix.RDNSequence, bool) {
	var seq pkix.RDNSequence
	rest, err := asn1.Unmarshal(raw, &seq)
	if err != nil || len(rest) != 0 {
		return nil, false
	}
	return seq, true
}

// sameDecodedName reports whether two ASN.1-decoded names are the same name. It is
// the single home of the semantic half of the package's name rule: a name that could
// not be decoded matches nothing, and two decodes are equal only as whole
// RDNSequences, so RDN order and multi-valued grouping are preserved.
func sameDecodedName(a pkix.RDNSequence, aOK bool, b pkix.RDNSequence, bOK bool) bool {
	return aOK && bOK && reflect.DeepEqual(a, b)
}

// decodedDN is one memoised raw-name decode: the decoded sequence, whether the
// decode succeeded, and whether it has been attempted at all (a name that cannot
// be decoded is a legitimate result worth caching, so "not yet asked" needs its
// own flag).
type decodedDN struct {
	seq    pkix.RDNSequence
	ok     bool
	cached bool
}

// subjectName is decodedName over certs[i]'s raw subject, memoised.
func (g *certGraph) subjectName(i int) (pkix.RDNSequence, bool) {
	if !g.decodedSubjects[i].cached {
		seq, ok := decodedName(g.certs[i].RawSubject)
		g.decodedSubjects[i] = decodedDN{seq: seq, ok: ok, cached: true}
	}
	return g.decodedSubjects[i].seq, g.decodedSubjects[i].ok
}

// issuerName is decodedName over certs[i]'s raw issuer, memoised.
func (g *certGraph) issuerName(i int) (pkix.RDNSequence, bool) {
	if !g.decodedIssuers[i].cached {
		seq, ok := decodedName(g.certs[i].RawIssuer)
		g.decodedIssuers[i] = decodedDN{seq: seq, ok: ok, cached: true}
	}
	return g.decodedIssuers[i].seq, g.decodedIssuers[i].ok
}

// isSelfSigned reports whether certs[i] is its own issuer, which is what makes it
// a root rather than a link.
//
// It is deliberately not an edge in the evidence model: a self-pair links nothing
// there, because "did this certificate issue itself" is a different question from
// "did A issue B", and the answer feeds only the root set of the distance walks and
// assembleChain's carve-out.
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
// The subject/issuer comparison accepts the same permitted DirectoryString
// difference nameLink accepts: a certificate that re-encodes its own name is
// still self-issued, and reading it as a non-root would fire assembleChain's
// additive fallback on a bundle whose chain is complete.
//
// A certificate whose own RSA key exceeds either verification ceiling is reported as
// not self-signed — unverified rather than disproven — for the same cost reason
// proven applies the ceiling. After newCertGraph's refusal that answer is only
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
		// Same fidelity rule as nameLink: a permitted DirectoryString difference
		// between a certificate's own subject and issuer is still one name, and
		// treating it as two costs the bundle its root.
		subject, subjectOK := g.subjectName(i)
		issuer, issuerOK := g.issuerName(i)
		if !sameDecodedName(subject, subjectOK, issuer, issuerOK) {
			return false
		}
	}
	if !verifiableKey(c.PublicKey) {
		return false
	}
	return c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

// computeDistances fills both distance maps: distToRoot over the inclusive
// candidate edges, and provenDistToRoot over the proven edges only.
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
// The proven walk costs at most one signature check per CANDIDATE edge, all
// memoised in g.proof and reused by chain assembly and the role check. That is
// far below all pairs for an ordinary bundle, but it is not a smaller bound in
// principle: a linked pair needs only a matching name, so a bundle whose
// certificates all share one issuer name still yields O(n^2) edges, and this walk
// pays for them eagerly.
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
	matches, firstUnverifiable := g.collectMatches(signers)
	matches, issuerObs := g.dropIssuerMatches(matches)
	switch len(matches) {
	case 0:
		return identityMatch{}, nil, g.noMatchError(len(signers), firstUnverifiable, keyIssues, certIssues)
	case 1:
		return matches[0], issuerObs, nil
	default:
		best, obs, err := g.resolveAmbiguousMatches(matches, keyIssues)
		if err != nil {
			return identityMatch{}, nil, err
		}
		return best, append(issuerObs, obs...), nil
	}
}

// dropIssuerMatches removes the matches whose certificate verifiably issued another
// certificate in this bundle, whenever at least one match did not, and reports the
// ones it dropped.
//
// The role rule analyseAt enforces AFTER selection - an issuer of another
// certificate here is not an end-entity certificate - has to participate in
// selection as well, or a bundle carrying exactly one usable identity is refused
// whenever an issuer also matches a supplied key. Two reachable shapes: one key
// reused for both a CA and the leaf it signed (the CA wins the renewal ranking on
// its later NotBefore, and the role check then rejects the bundle), and a key file
// holding the leaf's key next to the CA's (counted as two identities, so the
// "one certificate/key pair per output" refusal fires). In both the end-entity
// certificate is unambiguous.
//
// When EVERY match is an issuer the set is returned unchanged, so the "the key
// belongs to an issuer" diagnosis is preserved exactly for the bundle that has no
// end-entity alternative.
//
// It reports TWO facts, because filtering here is what makes the second one
// otherwise unreportable: the matches it set aside (ObsIssuerMatchIgnored), and
// whether any of them shared a private key with a match that survived
// (ObsKeyReusedAcrossCerts). Collapsing the candidate set to one is what keeps
// resolveAmbiguousMatches — the only other place that says "one key matches several
// certificates" — from ever being reached for the shared-key CA/leaf bundle, so
// without the second observation the key reuse is reported nowhere.
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
		obs = append(obs, g.keyReuseObservation(kept, dropped)...)
	}
	return kept, obs
}

// keyReuseObservation reports the certificates dropped as issuers that share a
// private key with one this app kept as an identity candidate, or nothing when the
// key file simply held both keys (a leaf key beside its CA's key is two keys, not
// one key doing two jobs).
//
// The count it names is of certificates the shared key(s) match, which is the fact
// the operator has to act on: a CA key that also belongs to an end-entity
// certificate cannot be rotated or revoked independently of it. The wording says
// nothing about renewal — the dropped certificate is an issuer of the one that
// survived, not an older version of it.
func (g *certGraph) keyReuseObservation(kept, dropped []identityMatch) []Observation {
	sharedKey := func(m identityMatch, others []identityMatch) bool {
		return slices.ContainsFunc(others, func(o identityMatch) bool { return o.key == m.key })
	}
	var reusedIssuers []*x509.Certificate
	for _, d := range dropped {
		if sharedKey(d, kept) {
			reusedIssuers = append(reusedIssuers, g.certs[d.cert])
		}
	}
	if len(reusedIssuers) == 0 {
		return nil
	}
	var alsoMatched int
	for _, k := range kept {
		if sharedKey(k, dropped) {
			alsoMatched++
		}
	}
	return []Observation{{
		Kind: ObsKeyReusedAcrossCerts,
		Detail: fmt.Sprintf("one private key is shared by %d certificate(s) in this input and %d of them issued another certificate here (%s); a key serving both a CA and an end-entity certificate means one key compromise affects both, and neither can be replaced without replacing the other",
			alsoMatched+len(reusedIssuers), len(reusedIssuers), subjectsForLog(reusedIssuers)),
	}}
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
// naming an unverifiable key algorithm ahead of a plain mismatch when it is the
// only explanation left — every certificate uncomparable — and otherwise carrying
// it as a trailing clause on the mismatch sentence. On a plain mismatch the key
// blocks that yielded
// no key at all are named after the base sentence (keyDefects.suffix), because
// the count in that sentence is of USABLE keys: a mid-rotation key file whose
// appended block is damaged otherwise reads as "the key does not match the
// certificate" with no hint that half the file was unreadable. The same sentence
// also names the certificate-file blocks that were neither a certificate nor a
// private key, because the observation that reports them (ObsUnrelatedBlocksSkipped)
// is only reachable when the analysis SUCCEEDS: a chain link relabelled "TRUSTED
// CERTIFICATE" by `openssl x509 -trustout` is a common cause of exactly this
// mismatch, and without the clause nothing anywhere names it.
func (g *certGraph) noMatchError(keyCount, firstUnverifiable int, keyIssues keyDefects, certIssues skippedBlocks) error {
	uncomparable := 0
	for _, c := range g.certs {
		if !comparableCertKey(c.PublicKey) {
			uncomparable++
		}
	}
	// The specific diagnosis is right only when an uncomparable certificate is the
	// ONLY explanation left. With even one comparable certificate present the real
	// cause is a plain mismatch, and returning here dropped both clauses this
	// function exists to attach - so a legacy bundle carrying a DSA root named that
	// root while saying nothing about the mismatch or about a damaged appended key
	// block keyDefects had already recorded.
	if firstUnverifiable >= 0 && uncomparable == len(g.certs) {
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
	msg := fmt.Sprintf(
		"none of the %d private key block(s) matches any of the %d certificate(s) in the chain%s",
		keyCount, len(g.certs), keyIssues.suffix())
	if firstUnverifiable >= 0 {
		// Same split as the all-uncomparable branch above, for the same reason: a nil
		// PublicKey is a key crypto/x509 could not READ, while a parsed key of an
		// unsupported type (a *dsa.PublicKey) was read fine and is merely not
		// comparable. Telling an operator the parser failed when it did not sends them
		// to re-issue a certificate whose encoding is intact.
		if c := g.certs[firstUnverifiable]; c.PublicKey == nil {
			msg += fmt.Sprintf("; certificate %q holds a public key crypto/x509 could not read, so it was compared against no key",
				boundSubject(c.Subject.String()))
		} else {
			msg += fmt.Sprintf("; certificate %q has a public key of type %T that cannot be compared against the supplied private key, so it was compared against no key",
				boundSubject(c.Subject.String()), c.PublicKey)
		}
	}
	if certIssues.count > 0 {
		msg += fmt.Sprintf("; the certificate file also holds %d block(s) that are neither a certificate nor a private key and were left out of the bundle (first %q)",
			certIssues.count, certIssues.firstTypeForLog())
	}
	return errors.New(msg)
}

// resolveAmbiguousMatches rules on more than one (key, certificate) match.
//
// Distinct keys matching distinct certificates means the input carries several
// identities, which cannot be expressed as one PFX. One key matching several
// certificates is a renewed certificate reusing its key: prefer one that is
// usable now, then the newest. Ranking purely on NotBefore would prefer a
// future-dated renewal over a currently valid certificate, producing a bundle no
// consumer will accept yet.
//
// The distinct-identities refusal names the colliding certificates and the key-file
// defects: a combined key file in a multi-certificate bundle otherwise yields a bare
// count with nothing to act on, and a damaged appended key block is a likely cause of
// the collision the count cannot mention.
func (g *certGraph) resolveAmbiguousMatches(matches []identityMatch, keyIssues keyDefects) (identityMatch, []Observation, error) {
	firstKey := matches[0].key
	for _, m := range matches[1:] {
		if m.key != firstKey {
			return identityMatch{}, nil, fmt.Errorf(
				"the input contains %d distinct certificate/key identities; this app converts one certificate/key pair per output (%s)%s",
				countDistinctKeys(matches), subjectsForLog(g.certsOf(matches)), keyIssues.suffix())
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
// with a route to a self-signed root in this bundle proven by signature at
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
// Edge STRENGTH outranks every other ranking key. A candidate edge on its own is
// only a name or key-identifier match, which a same-subject certificate holding a
// different key also satisfies; ranking such an impostor above the certificate that
// actually signed this one would emit a chain a consumer cannot verify. So proven
// parents are considered alone whenever any exists, and merely linked candidates
// only when none does — the case where no signature can be checked at all: a
// refused algorithm, a key above the verification ceilings, or a bundle carrying a
// same-named certificate while the real signer is absent.
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
	// candidate whose route is proven all the way to an included root emits a chain
	// the consumer cannot validate. The inclusive ranking below is consulted only
	// when neither candidate has a fully proven route — the case where no signature
	// can be checked at all.
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

// comparableCertKey reports whether a certificate's public key can be compared
// against a private key's public half at all. crypto/x509 parses a certificate
// whose SubjectPublicKeyInfo algorithm it does not recognise and leaves
// PublicKey nil, and such a certificate is uncomparable rather than unequal.
func comparableCertKey(pub crypto.PublicKey) bool {
	_, supported := equalPublicKeys(pub, pub)
	return supported
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
func (g *certGraph) assembleChain(identityCert int) (chain, extra []*x509.Certificate, obs []Observation) {
	leaf := g.certs[identityCert]
	path := g.pathFrom(identityCert)
	chain = make([]*x509.Certificate, 0, len(path)-1)
	for _, i := range path[1:] {
		chain = append(chain, g.certs[i])
	}
	extra = g.outsidePath(path)

	// The discovered path ends where relationship evidence ran out. If that terminus
	// is not PROVEN self-signed, the chain above it is unfinished, whether the path
	// stopped at the identity itself or three links up, so the additive fallback
	// applies to both: an unprovable edge in the middle of a bundle must not silently
	// truncate the chain either. What can still stop the walk mid-bundle is a
	// signature no signature check can settle — an algorithm crypto/x509 refuses, a
	// key above the verification ceilings, or a real signer that is simply absent
	// while a same-named certificate is present. A permitted name-encoding difference
	// no longer does: the evidence graph proves those edges and the path walk carries
	// them, so this fallback is not reached for them at all.
	obs = append(obs, g.unprovenPathObservations(path)...)

	terminal := path[len(path)-1]
	if len(extra) > 0 && !g.isSelfSigned(terminal) {
		kept, disqualified := partitionIssuerEligible(extra)
		chain = append(chain, kept...)
		disposition := fmt.Sprintf("the remaining %d certificate(s) were kept rather than dropped", len(kept))
		if len(kept) == 0 {
			disposition = "none of the remaining certificate(s) could be kept as chain material"
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
					len(disqualified), boundSubject(g.certs[terminal].Subject.String()), subjectsForLog(disqualified)),
			})
		}
		return chain, disqualified, append(obs, fallbackObs...)
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

// unprovenPathObservations reports every hop of the discovered path whose issuance
// this bundle could not prove by signature. It reads the same memoised proof chain
// assembly and ranking read, so it costs no extra verification: bestParent already
// asked about every hop it selected.
func (g *certGraph) unprovenPathObservations(path []int) []Observation {
	var obs []Observation
	for i := 1; i < len(path); i++ {
		child, parent := path[i-1], path[i]
		if g.proven(child, parent) {
			continue
		}
		// Say which evidence put the hop there. A path edge needs only
		// issuanceEvidence.linked(), and keyIDLink is computed independently of any
		// name comparison, so a hop can rest on the authority key identifier alone -
		// naming the issuer name there sends the operator to the wrong field.
		linkage := "matches the issuer name of"
		if g.edge(child, parent).name == nameLinkNone {
			linkage = "carries the subject key identifier named as the authority key identifier of"
		}
		obs = append(obs, Observation{
			Kind: ObsChainEdgeUnprovenIssuer,
			Detail: fmt.Sprintf(
				"chain certificate %d, %q, %s %q but no signature here proves it issued that certificate; it was included because nothing in this bundle could be proven to have signed that certificate, so a consumer may be unable to verify the chain",
				i, boundSubject(g.certs[parent].Subject.String()), linkage,
				boundSubject(g.certs[child].Subject.String())),
		})
	}
	return obs
}

// chainIssuerEligibilityObservations reports certificates in the EMITTED chain
// that RFC 5280 4.2.1.9 disqualifies from issuing certificates, without removing
// them.
//
// This is the diagnostic half of the split candidateEdge draws: a signature is
// ground truth about what a certificate DID, its extensions are policy about what
// it SHOULD have done, and this app converts formats rather than validating paths,
// so the two disagreeing is the operator's problem to fix in their PKI. Carrying
// the certificate keeps the PFX usable for the lenient consumers this app exists to
// feed (the Synology/Windows import path puts CA bags straight into a store);
// naming it is what keeps that from being silent, because a strict path validator
// WILL reject the chain and nothing else in the output would say why.
//
// It reports only what is IN the chain. A certificate the additive fallback held
// back is already named by ObsExtraCertsExcluded, so the two never describe the
// same certificate twice.
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
				i+1, len(chain), boundSubject(c.Subject.String()), reason),
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
		fmt.Fprintf(&b, "%q", boundSubject(c.Subject.String()))
	}
	return b.String()
}
