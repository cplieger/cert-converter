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
	// path ended on could be established from the bundle WHILE certificates were
	// left over that it could not place. Any of those that are issuer-eligible were
	// then included as-is rather than dropped, so the bundle carries certificates
	// whose relationship to the identity this app could not establish — the fact
	// worth an operator's attention, and why the leftovers are what this kind is
	// gated on.
	//
	// The leftover-free case is ObsChainTrustAnchorAbsent, a different fact at a
	// different level; the two are mutually exclusive by construction.
	//
	// It is the last of three mutually exclusive terminus kinds, decided in this
	// order by terminusObservation: a terminus that names ITSELF as its own issuer
	// is ObsChainAnchorUnverifiable whatever the leftovers (the anchor is present,
	// only its self-signature is unproven); otherwise a leftover-free bundle is
	// ObsChainTrustAnchorAbsent; otherwise this kind. So leftovers separate this
	// kind from ObsChainTrustAnchorAbsent only once the self-issued case is out.
	ObsChainUnverified ObservationKind = "chain-unverified"
	// ObsChainTrustAnchorAbsent reports that the chain terminates at a certificate
	// whose own issuer is not in the bundle, with nothing left over: every parsed
	// certificate is on the emitted path and the path simply stops below a trust
	// anchor.
	//
	// This is the NORMAL shape of the input this app exists to convert. A Caddy/ACME
	// `fullchain.pem` is leaf + intermediate with the root deliberately absent (the
	// consumer is expected to hold it), so the condition recurs on first sight, after
	// every renewal and after every restart, and it names nothing the operator can
	// act on — hence ObservationClassInfo rather than a warning. It is reported at
	// all because an empty or truncated chain is otherwise indistinguishable from a
	// complete one in the output, and an operator who DID mean to ship the full chain
	// has no other signal that the anchor never arrived.
	//
	// It is deliberately NOT ObsChainEdgeUnprovenIssuer: that one reports an emitted
	// chain EDGE resting on unproven linkage (a certificate is in the bundle and this
	// app could not prove it issued the one below it), which is a fact about
	// certificates that are present. This one reports a certificate that is ABSENT,
	// and every edge below it may be fully proven.
	ObsChainTrustAnchorAbsent ObservationKind = "chain-trust-anchor-absent"
	// ObsChainAnchorUnverifiable reports that the chain terminates at a certificate
	// that names ITSELF as its own issuer while this app could not verify that
	// self-signature: a corrupt or re-signed certificate, a signature algorithm
	// crypto/x509 refuses (MD5, DSA), or a key above the verification ceilings.
	//
	// It is deliberately NOT ObsChainTrustAnchorAbsent. That kind says the anchor is
	// ABSENT and is informational because a Caddy/ACME fullchain legitimately omits
	// it; here the anchor is PRESENT and what is missing is the proof, which is input
	// a consumer validating the chain will reject — so it is a warning.
	ObsChainAnchorUnverifiable ObservationKind = "chain-anchor-unverifiable"
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
	// and nothing said so whenever the path still ended at a self-signed certificate:
	// the terminus kinds (ObsChainUnverified, ObsChainTrustAnchorAbsent,
	// ObsChainAnchorUnverifiable) fire only for
	// a terminus that is not proven self-signed, which a path ending at a root never
	// is, and they describe the certificate ABOVE the chain rather than an edge in it.
	// The bundle still converts (this package holds no trust store), but a PKCS#12 CA bag
	// a consumer imports into a trust store is the wrong place for an unproven link
	// to be silent.
	ObsChainEdgeUnprovenIssuer ObservationKind = "chain-edge-unproven-issuer"
)

// ObservationClass is how loudly an observation of a given kind deserves to be
// reported. Three values rather than a boolean, because the kinds fall into three
// genuinely different operator relationships and a two-valued classification forced
// the third into whichever neighbour was less wrong: a benign assembly artefact, a
// fact about the input the operator has no action for, and something they probably
// did not intend.
//
// It classifies the KIND, not a log level: this package knows which of the three a
// kind is (that is a property of the condition, minted where the kinds are minted),
// and the caller maps a class onto its own severity vocabulary. A string type rather
// than an integer so the class is legible in a log line or a test failure without a
// separate formatting method.
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
	// that a consumer of the bundle will reject. This is the default for a new kind:
	// an unclassified condition is louder than it should be rather than silent.
	ObservationClassWarning ObservationClass = "warning"
)

// Class reports how loudly an observation of this kind deserves to be reported. It
// lives beside the constants because the distinction is a property of the KIND, known
// where the kinds are minted; how a caller renders each class stays the caller's
// choice.
//
// Every kind is listed explicitly so that changing one's class is a visible edit to
// this switch rather than a side effect of adding it to a group. The exhaustiveness
// test in this package fails if a declared kind is missing here.
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
		ObsUnusableKeyBlocksSkipped, ObsIssuerMatchIgnored, ObsKeyReusedAcrossCerts,
		ObsChainEdgeUnprovenIssuer:
		return ObservationClassWarning
	}
	// Unreachable while the switch above is exhaustive, which the test enforces. A
	// kind that somehow arrives unclassified is reported loudly, never dropped.
	return ObservationClassWarning
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
//
// Analyse returns a *Analysis and never mutates one afterwards: Encode,
// CheckCurrency and matchesAnalysis all read it and none writes to it, so the
// value is safe to share and to hand back to the codec unchanged. Callers hold the
// pointer rather than a copy because the struct is large enough that copying it
// per call is wasteful (gocritic hugeParam), and because Observations is a pointer
// method — a value return could not be consumed through the type's own only
// exported method without being bound to a variable first.
type Analysis struct {
	// leaf is the end-entity certificate the PFX is built around.
	leaf *x509.Certificate
	// chain holds leaf's ancestors, ordered nearest-parent-first. PKCS#12 stores
	// an ordered SEQUENCE of bags and decoders read it positionally (go-pkcs12's
	// own decoder assumes the first certificate is the leaf), so this order is a
	// contract rather than an implementation detail.
	//
	// One exception, always accompanied by ObsChainUnverified - or by
	// ObsChainAnchorUnverifiable when that terminus names itself as its own issuer: when
	// the issuer of the certificate the discovered path ended on could not be established
	// from
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
	// extra holds the certificates that parsed and were deliberately excluded from the
	// bundle: embedding an unrelated CA pollutes the trust chain the consumer sees. On a
	// proven self-signed terminus that is every certificate off the discovered path; on the
	// additive fallback above it is only the subset canIssueCertificates disqualifies,
	// because the eligible remainder is carried in chain instead.
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
// ctx is the caller's shutdown signal. It is consulted only where a signature
// verification is about to be paid for (certGraph.verifiable), which is the only
// cost in an analysis the input FILE dictates: one analysis can pay up to
// maxChainCerts^2 verifications, each bounded by maxVerifiableKeyBits and
// maxVerifiablePublicExponent to milliseconds but not bounded in number. A
// cancellation abandons the analysis and returns an error wrapping ctx.Err(), so
// errors.Is(err, context.Canceled) holds and the caller classifies it as a
// shutdown rather than a conversion failure. No accepted input's outcome changes:
// with a live context this behaves exactly as it did before.
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
func Analyse(ctx context.Context, certPEM, keyPEM []byte) (*Analysis, error) {
	return analyseAt(ctx, certPEM, keyPEM, time.Now())
}

// analyseAt is Analyse with the scan instant supplied rather than read, so the
// validity boundaries and the renewed-certificate tie-break are decidable at an
// exact time. Unexported on purpose: no caller outside this package has a reason
// to analyse a bundle at anything other than now, and widening the exported
// surface to hand one in would invite exactly that.
//
// ctx carries Analyse's cancellation contract unchanged.
func analyseAt(ctx context.Context, certPEM, keyPEM []byte, now time.Time) (*Analysis, error) {
	in, err := prepareAnalysisInput(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	certs, obs := in.certs, in.observations

	// Three cancellation reads, one after each phase that can pay a verification.
	// A verdict derived from a partially built graph is not merely incomplete, it is
	// WRONG in an operator-visible way: selectIdentity and oversizedIssuerError both
	// return refusals derived from proven, so propagating one built on a cancelled
	// graph would log a bogus "conversion failed" at Error and flip the health
	// marker on a container that was only asked to stop.
	g := newCertGraph(ctx, certs, now)
	if g.cancelErr != nil {
		return nil, fmt.Errorf("analyse cancelled: %w", g.cancelErr)
	}

	identity, tieObs, err := g.selectIdentity(in.signers, in.keyIssues, in.certIssues)
	if g.cancelErr != nil {
		return nil, fmt.Errorf("analyse cancelled: %w", g.cancelErr)
	}
	if err != nil {
		return nil, err
	}
	obs = append(obs, tieObs...)

	// Asked once the identity is known, because whether an unverifiable issuer is
	// load-bearing is a property of the SELECTED path's hops, not of the graph. One walk,
	// shared with assembleChain: the refusal below judges the hops the chain emits, so the
	// two read the same slice rather than two walks that have to agree.
	//
	// The input evidence is folded in for the reason appendCertIssues documents, and
	// it is sharpest here: this refusal fires only when the selected path had to GUESS
	// a hop, and a certificate-shaped block left out of the bundle (a link relabelled
	// "TRUSTED CERTIFICATE") is a leading reason the real signer was not among the
	// parsed certificates. Folded at the call site rather than inside
	// oversizedIssuerError, which reasons over the graph and holds no input record.
	path := g.pathFrom(identity.cert)
	if g.cancelErr != nil {
		return nil, fmt.Errorf("analyse cancelled: %w", g.cancelErr)
	}
	if err := g.oversizedIssuerError(path); err != nil {
		return nil, errors.New(appendCertIssues(
			err.Error()+in.keyIssues.suffix(), in.certIssues))
	}

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
		return nil, errors.New(appendCertIssues(fmt.Sprintf(
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

	if g.cancelErr != nil {
		return nil, fmt.Errorf("analyse cancelled: %w", g.cancelErr)
	}

	return &Analysis{
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
	// reason proof memoises edges: it is a real signature verification whose cost
	// the input file dictates, and three places ask — the root set, every hop of
	// pathFrom, and assembleChain's self-signed carve-out.
	selfSigned map[int]bool
	// canonicalSubjects[i] / canonicalIssuers[i] memoise the CANONICALISED raw subject
	// and issuer names, for the same reason proof memoises a signature: the decode is
	// O(name size) work the FILE dictates, and the linkage classifier asks for the
	// subject and the issuer of every certificate against every other one. This is
	// the ONE decoded-name cache in the package; semantic name equality is computed
	// here, once per certificate, and stored as a fact on the edge. Measured on a
	// 64-block, 8.87 MB bundle inside both existing caps: 12.4s of a 15.2s Analyse
	// went on repeated decodes, against 97ms to parse all 64 blocks once.
	canonicalSubjects []canonicalDN
	canonicalIssuers  []canonicalDN
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

// nameOrKeyIDLink reports whether a name or key-identifier relation ties the pair
// together at all, BEFORE the key-reuse exclusion. It is the single home of that
// conjunction because two sites turn on it and must not diverge: linked() negates
// keyReuse against it, and fillEvidence uses it to decide whether the key-reuse
// comparison is worth paying for. A widened linkage rule reaching only one of the
// two would leave keyReuse uncomputed for a newly-linked pair, so a regenerated
// self-signed certificate beside the one it replaces would record a mutual
// issuance edge - the shape keyReuse exists to exclude.
func (e issuanceEvidence) nameOrKeyIDLink() bool {
	return e.name != nameLinkNone || e.keyID
}

// linked reports whether anything in this bundle ties the two certificates together
// at all. It is the gate on the expensive fact: a pair with no name and no key-id
// relationship has nothing for a signature to confirm, so proven never verifies one.
func (e issuanceEvidence) linked() bool {
	return !e.keyReuse && e.nameOrKeyIDLink()
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
	case k.N.BitLen() > maxVerifiableKeyBits:
		return fmt.Sprintf("holds a %d-bit RSA key, above the %d-bit modulus ceiling this app will verify a signature against",
			k.N.BitLen(), maxVerifiableKeyBits)
	case k.E > maxVerifiablePublicExponent:
		return fmt.Sprintf("holds an RSA key with public exponent %d, above the %d exponent ceiling this app will verify a signature against",
			k.E, maxVerifiablePublicExponent)
	}
	return ""
}

// newCertGraph derives the evidence for every pair and the candidate edge set that
// follows from it.
//
// Two passes, in this order for a cost reason. The first fills issuanceEvidence for
// every ordered pair from byte, OID and decoded-name comparisons alone — no
// signature work, and one name decode per certificate however many pairs read it.
// The second turns that into candidate edges, reaching for the expensive fact only
// where the cheap one would be wrong: a pair the evidence links whose parent is
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
// Construction does NOT refuse a bundle. An over-ceiling issuer key — one no
// signature can be checked against — is refused later, by oversizedIssuerError over
// the hops of the path chain selection actually chose, because a bundle whose selected
// path spends only proven edges does not depend on the unverifiable one and was being
// refused for a key it never reads.
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
			if e.nameOrKeyIDLink() {
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
// A name that cannot be decoded or re-encoded matches nothing: an unreadable name is
// compared against no other name rather than against everything.
func (g *certGraph) nameLink(child, parent int) nameLinkage {
	if bytes.Equal(g.certs[child].RawIssuer, g.certs[parent].RawSubject) {
		return nameLinkExact
	}
	childIssuer, issuerOK := g.issuerName(child)
	parentSubject, subjectOK := g.subjectName(parent)
	if sameCanonicalName(childIssuer, issuerOK, parentSubject, subjectOK) {
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
		if !sameCanonicalName(childSubject, childOK, parentSubject, parentOK) {
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

// oversizedIssuerError refuses a bundle whose SELECTED chain has to GUESS a hop while
// a certificate named as that hop's issuer holds a key no signature can be checked
// against — an RSA modulus above maxVerifiableKeyBits, or a public exponent above
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
// It is asked of the identity's OWN path rather than of the graph, and that scoping is
// the whole correctness argument. The path is HANDED to it — the same slice assembleChain
// is given — rather than walked here, so the hops judged are structurally the hops emitted.
// Whether an unverifiable edge is load-bearing depends
// on where the selected path ENTERS a set of mutually-linked certificates, which only
// the walk knows: in a bundle of leaf -> C proven, C -> P proven and P -> C proven, a
// path entering at C spends the proven C -> P edge and never needs a guess, while a
// path entering at P finds C's only proven parent already onPath and does have to
// guess. A global reachability question cannot separate those two orders, and asking
// it refused the first — a conversion this app performs correctly, with every emitted
// hop proven. So the question is asked of pathFrom's actual hops, which are the hops
// assembleChain emits.
//
// A hop a signature PROVES is skipped whatever else the bundle carries, and a linked
// certificate is only named when the hop it competes for was guessed. Refusing then
// costs nothing real: no CA issues RSA above 16384 bits, so an over-ceiling issuer
// standing beside a same-subject decoy is an attack shape rather than a
// configuration. No verification is attempted either way, which is the point of the
// ceiling; only the outcome changes, from a silent wrong chain to a named refusal.
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
//
// It keys on the NAMING relation (edge().linked(): name at either fidelity, or
// authority key identifier) rather than on candidateParents, because eligibility and
// verifiability interact: a certificate whose own extensions disqualify it from
// issuing enters candidateParents ONLY when a signature proves the edge
// (candidateEdge), and an over-ceiling key can never be proven. So the decoy
// substitution this refusal exists for — a leaf, its real over-ceiling issuer
// carrying CA:false or no basicConstraints, and a same-subject certificate with an
// ordinary key that then wins the guessed hop — leaves the oversized certificate with
// no candidate entry at all. Keying on candidate survival skipped exactly that case.
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
// ceiling is refused too, which is the cost the ceilings exist to refuse. No refusal
// elsewhere makes that branch unreachable: candidateEdge and computeDistances ask it
// while the graph is being BUILT, and oversizedIssuerError runs later still (analyseAt,
// after identity selection) and refuses only a bundle whose SELECTED path had to guess a
// hop beside such a certificate - so a bundle that spends proven edges throughout
// converts with an over-ceiling stray in it, ranked by this same false.
func (g *certGraph) proven(child, parent int) bool {
	key := [2]int{child, parent}
	if got, ok := g.proof[key]; ok {
		return got
	}
	got := false
	if g.edge(child, parent).linked() {
		c, p := g.certs[child], g.certs[parent]
		if verifiableKey(p.PublicKey) {
			if !g.verifiable() {
				// Not memoised: a cancelled pair is the ABSENCE of an answer, and
				// recording false would make any later read of this pair a silent
				// negative rather than a missing one.
				return false
			}
			g.proofChecks++
			got = p.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
		}
	}
	g.proof[key] = got
	return got
}

// verifiable reports whether this analysis may still pay for a signature
// verification, latching the first cancellation it sees. It returns a bool rather
// than an error because every caller is a predicate; analyseAt reads cancelErr.
//
// This is the interruption point, and it sits HERE — immediately before a
// CheckSignature — rather than at a phase boundary, because the phases are what
// take the time: computeDistances pays the proven BFS eagerly and pathFrom asks
// proven for every candidate parent of every node it walks, so a bundle whose
// certificates are mutually name-linked fills the memo with up to
// maxChainCerts*(maxChainCerts-1) distinct pairs. A check at entry to each phase
// would leave that whole product uninterruptible; a check per verification bounds
// the delay to one signature check.
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

// canonicalName ASN.1-decodes a raw DER distinguished name and re-encodes the decoded
// sequence, so semantic name equality is a byte comparison of two canonical forms
// rather than a reflect.DeepEqual walk over two decoded trees.
//
// The walk is the cost the decoded-name cache was added to remove and only half
// removed: the DECODE is now paid once per certificate, but the COMPARISON is paid
// once per ordered pair and costs the same as a decode. Measured on go1.26.5 over a
// 138 KB name (a 64-block bundle inside MaxInputBytes), one decode is 3.6ms and one
// DeepEqual 3.2ms, so fillEvidence's 64*63 pairs spend 12.9s where the marshal-once
// form spends 0.65s.
//
// Member order inside ONE RDN is deliberately not significant. An RDN is an ASN.1
// SET, which is unordered by definition, so a multi-valued RDN spelling its
// attributes CN-then-O and one spelling them O-then-CN are two encodings of the SAME
// distinguished name, and RFC 5280 gives the encoded order no meaning. encoding/asn1's
// setEncoder sorts SET members before emitting them, so re-marshalling folds both
// spellings onto one canonical DER and they compare equal here. That is why this
// comparison is CANONICAL-DER rather than positional, and it is the intended rule
// rather than a side effect: the positional decoded comparison it replaced read those
// two encodings as two different names. What canonicalisation does NOT reorder is the
// RDNSequence itself — a SEQUENCE, whose order IS significant — so `O=Acme, CN=x` as
// two separate RDNs stays distinct from `CN=x, O=Acme`, which is the distinction
// nameLink's doc describes. Both halves are pinned by
// TestCanonicalName_treats_SET_member_order_as_insignificant.
//
// The equivalence is exact for every attribute value the interface decode maps to a
// concrete Go type (string, int64, bool, []byte, time.Time, BitString, OID):
// identical values marshal to identical bytes, and different values cannot collide
// because each type re-encodes under its own tag. It deliberately DIVERGES for a
// value the decode maps to nil (NULL, ENUMERATED, GeneralString and the other tags
// encoding/asn1 does not surface through an interface): asn1.Marshal refuses a nil
// value, so such a name cannot be keyed and matches nothing -- where the old
// reflect.DeepEqual rule compared those values as nil == nil and matched two such
// names CONTENT-BLIND (DER-different GeneralString values, or a NULL against a
// GeneralString, compared equal). Refusing the key trades that false link for a
// lost link on a name shape no real CA emits. A name that cannot be decoded OR
// cannot be re-encoded matches nothing, the same direction the decode failure
// already takes: an unreadable name is compared against no other name rather than
// against everything.
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

// sameCanonicalName reports whether two names are the same name. It is the single home
// of the semantic half of the package's name rule: a name that could not be read
// matches nothing, and two names are equal only as whole canonicalised RDNSequences,
// so RDN order and multi-valued grouping are preserved.
func sameCanonicalName(a []byte, aOK bool, b []byte, bOK bool) bool {
	return aOK && bOK && bytes.Equal(a, b)
}

// canonicalDN is one memoised raw-name canonicalisation: the canonical DER of the
// decoded sequence, whether it could be produced, and whether it has been attempted
// at all (a name that cannot be read is a legitimate result worth caching, so "not
// yet asked" needs its own flag).
//
// The canonical DER rather than the decoded sequence, because the pairwise question
// is asked O(n^2) times and this makes answering it a byte compare; see canonicalName.
// It is never compared against a certificate's own RawSubject/RawIssuer, which
// nameLink compares separately and exactly.
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
// proven applies the ceiling. Construction performs no refusal, so the answer is already
// in the distance walks by the time oversizedIssuerError runs (analyseAt, after identity
// selection) and refuses the bundles where such a certificate stands beside a guessed
// hop - which is what leaves the remaining cases harmless: it decides
// only two harmless things: such a stray is no root for the distance walk, and if
// it is the IDENTITY itself its empty chain counts as a failure to prove rather
// than proof, so the additive fallback keeps the rest of the bundle and says so.
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
// either name fidelity, WITHOUT asking whether the self-signature verifies. It is
// the name half of isSelfSigned's question, split out because that is exactly the
// difference between "the anchor above this chain is absent" and "the anchor is
// this certificate and its self-signature could not be verified".
//
// Same fidelity rule as nameLink: a permitted DirectoryString difference between a
// certificate's own subject and issuer is still one name, and treating it as two
// costs the bundle its root.
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
			matched, supported := equalPublicKeys(c.PublicKey, s.Public())
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
func (g *certGraph) noMatchError(usableKeys, firstUnverifiable int, keyIssues keyDefects, certIssues skippedBlocks) error {
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
		var msg string
		if c.PublicKey == nil {
			// crypto/x509 parses a certificate whose SubjectPublicKeyInfo algorithm OID it
			// does not recognise and leaves PublicKey nil (parser.go's
			// UnknownPublicKeyAlgorithm branch), so %T would render "<nil>" here - the one
			// case where naming the algorithm matters most is the one where there is no
			// type to name. Say what happened instead.
			msg = fmt.Sprintf(
				"certificate %q uses a public key algorithm crypto/x509 does not recognise, so it cannot be verified against the private key; re-issue it with an RSA, ECDSA or Ed25519 key",
				subjectForLog(c))
		} else {
			msg = fmt.Sprintf(
				"certificate %q has a public key of type %T that cannot be verified against the private key",
				subjectForLog(c), c.PublicKey)
		}
		// The uncomparable count only covers PARSED certificate blocks, so "the
		// unsupported key is the only explanation left" does not rule out a
		// certificate-shaped block that was skipped (a link relabelled TRUSTED
		// CERTIFICATE) or a damaged key block keyDefects already recorded. Both
		// suffixes carry here for the same reason they carry on a plain mismatch:
		// returning without them sent the operator to re-issue the certificate this
		// sentence names while the block holding the supplied key's own certificate
		// went unmentioned.
		return errors.New(appendCertIssues(msg+keyIssues.suffix(), certIssues))
	}
	msg := fmt.Sprintf(
		"none of the %d distinct private key(s) in the key file matches any of the %d certificate(s) in the chain%s",
		usableKeys, len(g.certs), keyIssues.suffix())
	if firstUnverifiable >= 0 {
		// Same split as the all-uncomparable branch above, for the same reason: a nil
		// PublicKey is a key crypto/x509 could not READ, while a parsed key of an
		// unsupported type (a *dsa.PublicKey) was read fine and is merely not
		// comparable. Telling an operator the parser failed when it did not sends them
		// to re-issue a certificate whose encoding is intact.
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
	if certIssues.count == 0 {
		return msg
	}
	return msg + fmt.Sprintf("; the certificate file also holds %d block(s) that are neither a certificate nor a private key and were left out of the bundle (first %q)",
		certIssues.count, certIssues.firstTypeForLog())
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
func (g *certGraph) resolveAmbiguousMatches(matches []identityMatch, keyIssues keyDefects, certIssues skippedBlocks) (identityMatch, []Observation, error) {
	firstKey := matches[0].key
	for _, m := range matches[1:] {
		if m.key != firstKey {
			return identityMatch{}, nil, errors.New(appendCertIssues(fmt.Sprintf(
				"the input contains %d distinct certificate/key identities; this app converts one certificate/key pair per output (%s)%s",
				countDistinctKeys(matches), subjectsForLog(g.certsOf(matches)), keyIssues.suffix()), certIssues))
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
			len(matches), subjectForLog(g.certs[best.cert]),
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
// the choice is deterministic, and edge strength decides first: a parent whose
// signature proves it issued this certificate is preferred over every merely
// linked candidate, which are considered only when no proven parent exists
// (bestParent). Within one strength class the keys are validity at the scan
// instant, then a route to a self-signed root in this bundle proven by signature
// at every hop, then the shorter such route, then the inclusive route, then the
// later NotAfter, then a byte comparison of the certificate DER (betterParent).
// One path is emitted
// rather than every ancestor, because a consumer reading the bag sequence
// positionally should see one coherent chain; alternatives land in extra.
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

// equalPublicKeys is the single home of the comparison rule every caller shares:
// every public key type crypto/x509 parses exposes Equal(crypto.PublicKey) bool,
// and a type that does not is unverifiable rather than unequal. supported reports
// which of the two it was, so a caller that must distinguish them can (identity
// selection needs the algorithm-unsupported diagnosis), and one that need not can
// ignore it (samePublicKey collapses unsupported to false).
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

// assembleChain builds the emitted chain for the identity at path[0] — the walked
// path is handed in, so it is the same slice oversizedIssuerError judged — the
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
func (g *certGraph) assembleChain(path []int) (chain, extra []*x509.Certificate, obs []Observation) {
	leaf := g.certs[path[0]]
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

	// Whether the terminus is proven self-signed and whether any certificate is left
	// over are independent facts, so the diagnostic is NOT gated on leftovers: a lone
	// CA-signed leaf, or a proven leaf/intermediate pair whose root is absent, has an
	// unfinished chain with nothing to append, and reporting nothing at all made
	// exactly that case silent. The leftovers decide WHICH fact is reported, because
	// they are what separates the two:
	//
	//   - nothing left over: every parsed certificate is on the emitted path and the
	//     path stops below a trust anchor the bundle never carried. That is the
	//     documented shape of a Caddy/ACME fullchain, so it is ObsChainTrustAnchorAbsent
	//     at the informational class — a fact, not a defect, and one that recurs on
	//     every renewal.
	//   - certificates left over: this app could not place them, and included the
	//     issuer-eligible ones anyway, so the bundle carries certificates whose
	//     relationship to the identity is unestablished. That is ObsChainUnverified,
	//     and it stays a warning.
	terminal := path[len(path)-1]
	if !g.isSelfSigned(terminal) {
		kept, disqualified := partitionIssuerEligible(extra)
		chain = append(chain, kept...)
		fallbackObs := []Observation{g.terminusObservation(terminal, extra, kept, len(chain))}
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
// self-signed. The split it draws is the one the kinds mean: a terminus that names
// itself as its own issuer has its anchor present and only its self-signature
// unproven (ObsChainAnchorUnverifiable, a warning — a consumer will reject it);
// otherwise, with nothing left over, the only fact is that the anchor above the
// terminus is absent (ObsChainTrustAnchorAbsent, informational — the documented
// fullchain shape); with certificates left over, the fact is that this app could not
// place them and included the eligible ones regardless (ObsChainUnverified, a
// warning).
//
// It takes the leftovers and the kept subset rather than deriving them, because the
// caller has already partitioned them to build the chain and re-deriving here would
// let the sentence and the emitted chain disagree.
//
// chainLen is how many certificates the emitted chain carries, consulted only when
// nothing was left over: it is what separates a fullchain whose root is absent (chain
// material is present, the consumer supplies the anchor) from a bundle holding the
// identity alone (no chain material at all, which a consumer without the issuer cannot
// complete). Both are the same KIND at the same class; only the sentence differs,
// because only one of them is a bundle the operator probably did not mean to ship.
func (g *certGraph) terminusObservation(terminal int, extra, kept []*x509.Certificate, chainLen int) Observation {
	subject := subjectForLog(g.certs[terminal])
	leftovers := ""
	switch {
	case len(kept) > 0:
		leftovers = fmt.Sprintf("; %d of the remaining %d certificate(s) were kept rather than dropped", len(kept), len(extra))
	case len(extra) > 0:
		leftovers = "; none of the remaining certificate(s) could be kept as chain material"
	}
	// A terminus that names ITSELF as its own issuer has its anchor right here, so
	// what is missing is the proof rather than the certificate, and neither
	// absent-anchor kind states that. Reporting it as ObsChainTrustAnchorAbsent said
	// "whose issuer is not in the bundle" about a certificate whose issuer IS in the
	// bundle, at the informational class the fullchain shape earned.
	if g.selfIssuedByName(terminal) {
		return Observation{
			Kind: ObsChainAnchorUnverifiable,
			Detail: fmt.Sprintf("the chain ends at %q, which names itself as its own issuer, but its self-signature could not be verified here (a corrupt or re-signed certificate, a signature algorithm crypto/x509 refuses such as MD5 or DSA, or a key above this app's verification ceilings); a consumer that validates the chain will reject this anchor%s",
				subject, leftovers),
		}
	}
	if len(extra) == 0 {
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
				i+1, len(chain), subjectForLog(c),
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
				i, subjectForLog(g.certs[parent]), linkage,
				subjectForLog(g.certs[child])),
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
				i+1, len(chain), subjectForLog(c), reason),
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
		fmt.Fprintf(&b, "%q", subjectForLog(c))
	}
	return b.String()
}
