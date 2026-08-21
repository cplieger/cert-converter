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

// TestDNSequence_does_not_repeat_an_attribute_pkix_keeps_in_a_named_field pins the
// filter dnSequence applies before it appends ToRDNSequence's own output. The sibling
// test above proves dnSequence SURFACES what ToRDNSequence drops; this one proves it
// does not surface what ToRDNSequence keeps, which is the other half and the half no
// fixture reached: every fixture in this file uses an attribute type pkix has no named
// field for, so the filter never fired and a diagnostic that named the subject twice
// would have shipped green.
//
// The shape matters: crypto/x509 puts EVERY parsed attribute in Names, and the nine
// types pkix also keeps in a named field are therefore reachable twice.
func TestDNSequence_does_not_repeat_an_attribute_pkix_keeps_in_a_named_field(t *testing.T) {
	t.Parallel()

	n := pkix.Name{
		CommonName:   "leaf.example.com",
		Organization: []string{"Example"},
		Country:      []string{"NL"},
		Names: []pkix.AttributeTypeAndValue{
			renderAttr(asn1.ObjectIdentifier{2, 5, 4, 6}, "NL"),
			renderAttr(asn1.ObjectIdentifier{2, 5, 4, 10}, "Example"),
			renderAttr(asn1.ObjectIdentifier{2, 5, 4, 3}, "leaf.example.com"),
		},
	}

	const want = "CN=leaf.example.com,O=Example,C=NL"
	if got := dnSequence(&n).String(); got != want {
		t.Errorf("dnSequence(a parsed name).String() = %q, want %q: an attribute pkix keeps in a named field must be emitted once, by ToRDNSequence, or every subject in a diagnostic is doubled",
			got, want)
	}
}

// TestBoundedDN_cuts_on_an_attribute_boundary pins what the cut LEAVES, which the
// byte-prefix comparison above cannot see: maxSubjectRenderAttrs is 256 attributes
// while maxSubjectLogLen is 256 BYTES, so the prefix comparison stops around the
// fiftieth attribute and everything the truncation arm does at the boundary itself is
// invisible to it.
//
// An off-by-one there costs an attribute group with nothing in it, which pkix renders
// as a bare separator: the operator reads a subject that ends in a comma.
func TestBoundedDN_cuts_on_an_attribute_boundary(t *testing.T) {
	t.Parallel()

	var n pkix.Name
	for i := range maxSubjectRenderAttrs + 44 {
		n.Names = append(n.Names, renderAttr(oidEmailAddress, fmt.Sprintf("a%d@example.com", i)))
	}
	bounded := boundedDN(dnSequence(&n))

	if got := len(bounded); got != maxSubjectRenderAttrs {
		t.Errorf("len(boundedDN(a %d-attribute name)) = %d, want %d attribute group(s)",
			maxSubjectRenderAttrs+44, got, maxSubjectRenderAttrs)
	}
	for i, rdn := range bounded {
		if len(rdn) == 0 {
			t.Errorf("boundedDN(a %d-attribute name)[%d] carries no attribute, and pkix renders an empty group as a bare separator",
				maxSubjectRenderAttrs+44, i)
		}
	}
	if rendered := bounded.String(); strings.HasSuffix(rendered, ",") {
		t.Errorf("boundedDN(a %d-attribute name).String() = %q..., want no trailing separator",
			maxSubjectRenderAttrs+44, rendered[max(0, len(rendered)-48):])
	}
}
