package convert

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"strings"
	"testing"
)

// renderAttr builds one attribute with a printable value, so a fixture can be sized
// in attributes rather than in bytes.
func renderAttr(oid asn1.ObjectIdentifier, v string) pkix.AttributeTypeAndValue {
	return pkix.AttributeTypeAndValue{Type: oid, Value: v}
}

// oidEmailAddress is an attribute type pkix does NOT keep in a named field, so
// Name.String() surfaces it out of Names and ToRDNSequence drops it. Every fixture
// below uses it, because the named types are unreachable through Names.
var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

// TestSubjectForLog_bound_does_not_change_what_an_operator_reads pins the equivalence
// maxSubjectRenderAttrs' doc claims and that no committed fixture reaches: bounding
// the attributes handed to pkix's quadratic renderer leaves the first
// maxSubjectLogLen bytes byte-identical to the unbounded render. Without this,
// boundedDN's truncation arm is never executed and any
// off-by-one, or the reverse RDN order the arm depends on, ships green.
func TestSubjectForLog_bound_does_not_change_what_an_operator_reads(t *testing.T) {
	t.Parallel()

	for _, count := range []int{
		1, 4, maxSubjectRenderAttrs - 1, maxSubjectRenderAttrs,
		maxSubjectRenderAttrs + 1, 1000, 5000,
	} {
		t.Run(fmt.Sprintf("%d attributes", count), func(t *testing.T) {
			t.Parallel()
			var n pkix.Name
			for i := range count {
				n.Names = append(n.Names, renderAttr(oidEmailAddress, fmt.Sprintf("a%d@example.com", i)))
			}
			full := n.String()
			bounded := boundedDN(dnSequence(&n)).String()
			if got, want := cutTo(bounded, maxSubjectLogLen), cutTo(full, maxSubjectLogLen); got != want {
				t.Errorf("bounded render differs from the unbounded one inside maxSubjectLogLen:\n got  %q\n want %q\nmaxSubjectRenderAttrs is documented as invisible to an operator, so the first %d bytes must match",
					got, want, maxSubjectLogLen)
			}
			if count > maxSubjectRenderAttrs && len(bounded) >= len(full) {
				t.Errorf("bounded render is %d bytes and the unbounded one %d: past %d attributes the bound must actually cut, or the quadratic render is still being paid in full",
					len(bounded), len(full), maxSubjectRenderAttrs)
			}
		})
	}
}

// cutTo truncates to n bytes, mirroring what subjectForLog's boundLogText cut compares.
func cutTo(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// TestMaxSubjectRenderAttrs_always_overruns_the_log_bound pins the PREMISE the
// equivalence above rests on and that the const's doc states as the reason 256 is
// safe: every rendered attribute costs at least a type name, an "=" and a separator,
// so maxSubjectRenderAttrs of the SHORTEST possible attributes still render past
// maxSubjectLogLen. If that ever stopped holding, the bound would start changing what
// an operator reads and the test above would be the only thing between the two.
func TestMaxSubjectRenderAttrs_always_overruns_the_log_bound(t *testing.T) {
	t.Parallel()

	// C is the shortest name in pkix's attributeTypeNames table, and an empty value is
	// the shortest value, so this is the cheapest maxSubjectRenderAttrs-attribute name
	// that exists.
	var shortest pkix.RDNSequence
	for range maxSubjectRenderAttrs {
		shortest = append(shortest, []pkix.AttributeTypeAndValue{
			renderAttr(asn1.ObjectIdentifier{2, 5, 4, 6}, ""),
		})
	}
	if got := len(shortest.String()); got <= maxSubjectLogLen {
		t.Errorf("the shortest %d-attribute render is %d bytes, at or under maxSubjectLogLen (%d): the bound can now change what an operator reads, which maxSubjectRenderAttrs' doc says it cannot",
			maxSubjectRenderAttrs, got, maxSubjectLogLen)
	}
}

// TestDNSequence_surfaces_the_attributes_ToRDNSequence_drops pins why dnSequence
// exists at all, and is the only thing that would catch it being "simplified" back to
// c.Subject.ToRDNSequence() -- the form h-f2's own suggested_fix proposed. pkix keeps
// nine attribute types in named fields; every OTHER type a certificate carries lives
// in Names, and Name.String() surfaces those while ToRDNSequence does not, so the
// simpler form silently shortens the operator's diagnostic AND leaves the quadratic
// path unbounded for names built from unrecognised OIDs.
func TestDNSequence_surfaces_the_attributes_ToRDNSequence_drops(t *testing.T) {
	t.Parallel()

	n := pkix.Name{
		CommonName: "leaf.example.com",
		Names: []pkix.AttributeTypeAndValue{
			renderAttr(oidEmailAddress, "admin@example.com"),
		},
	}
	mirrored := dnSequence(&n).String()
	if mirrored != n.String() {
		t.Errorf("dnSequence(&n).String() = %q, want pkix.Name.String()'s own output %q: the mirror is what makes the bounded render byte-identical to the unbounded one",
			mirrored, n.String())
	}
	// pkix renders an attribute type it has no name for as `<oid>=#<hex DER>`, so the
	// OID text is what marks the attribute's presence, not the value bytes.
	if !strings.Contains(mirrored, oidEmailAddress.String()) {
		t.Errorf("dnSequence dropped an attribute pkix does not keep in a named field (%q): that is what ToRDNSequence does, and it is why dnSequence is not ToRDNSequence",
			mirrored)
	}
	if dropped := n.ToRDNSequence().String(); strings.Contains(dropped, oidEmailAddress.String()) {
		t.Fatal("pkix.Name.ToRDNSequence now surfaces Names; re-derive dnSequence's justification")
	}
}
