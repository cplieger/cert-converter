package convert

import (
	"encoding/asn1"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/cplieger/cert-converter/internal/testcerts"
)

// TestProfileFor_requires_all_three_algorithms pins the reverse half of the
// encoder-profile contract at the level the exported Inspect cannot reach: a
// bundle's identity is the (MAC, certificate-encryption, key-encryption) triple,
// not just the first two.
//
// The mixed case is the one that matters. A file with a SHA-256 MAC and PBES2
// certificates but a 3DES-wrapped private key is not something any profile emits,
// yet reporting it as modern2023 would leave a weakly protected private key on
// disk because the currency check would call it current.
func TestProfileFor_requires_all_three_algorithms(t *testing.T) {
	t.Parallel()

	for _, p := range profiles {
		t.Run(string(p.name), func(t *testing.T) {
			t.Parallel()
			got, err := profileFor(p.macOID, p.certEncOID, p.keyEncOID)
			if err != nil {
				t.Fatalf("profileFor(%s's own triple) = error %v, want nil", p.name, err)
			}
			if got != p.name {
				t.Errorf("profileFor identified %q, want %q", got, p.name)
			}
		})
	}

	for _, tc := range []struct {
		name                    string
		macOID, certOID, keyOID asn1.ObjectIdentifier
	}{
		{"modern MAC and certificates over a 3DES-wrapped key", oidSHA256, oidPBES2, oidPBEWithSHAAnd3KeyTripleDESCBC},
		{"legacy MAC and certificates over a PBES2-wrapped key", oidSHA1, oidPBEWithSHAAnd3KeyTripleDESCBC, oidPBES2},
		{"unknown key encryption", oidSHA256, oidPBES2, oidPBEWithSHAAnd40BitRC2CBC},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := profileFor(tc.macOID, tc.certOID, tc.keyOID); !errors.Is(err, ErrProfileUnknown) {
				t.Errorf("profileFor(%s) = %v, want ErrProfileUnknown", tc.name, err)
			}
		})
	}
}

// rawOID re-encodes a known identifier as the retained DER the preflight parses.
func rawOID(t *testing.T, oid asn1.ObjectIdentifier) asn1.RawValue {
	t.Helper()
	der, err := asn1.Marshal(oid)
	if err != nil {
		t.Fatalf("setup: marshal %v: %v", oid, err)
	}
	return asn1.RawValue{FullBytes: der}
}

// oversizedOID builds a syntactically valid OBJECT IDENTIFIER whose content is
// longer than the preflight's limit: a run of continuation bytes closed by a final
// byte, which is what an attacker would use to make the decoder allocate.
func oversizedOID() asn1.RawValue {
	content := make([]byte, maxOIDBytes+8)
	content[0] = 0x2a // the 1.2 arc, so the value stays a plausible identifier
	for i := 1; i < len(content)-1; i++ {
		content[i] = 0x81
	}
	content[len(content)-1] = 0x01
	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagOID, Bytes: content}
}

// TestInspect_rejects_an_oversized_identifier pins the allocation bound on
// untrusted identifier fields. Inspect runs on prior output before any
// authentication, and the store admits a prior PFX of up to 2*10 MiB, so decoding
// an identifier straight into asn1.ObjectIdentifier would let one crafted file
// allocate roughly eight bytes per encoded byte inside the scan's only goroutine.
// Both an algorithm identifier and a content-type identifier must be refused
// before that allocation happens.
func TestInspect_rejects_an_oversized_identifier(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		preamble pfxPreamble
	}{
		{
			name: "oversized MAC algorithm identifier",
			preamble: pfxPreamble{
				Version:  3,
				AuthSafe: contentInfo{ContentType: rawOID(t, oidDataContentType)},
				MacData: macData{
					Mac:        digestInfo{Algorithm: algorithmIdentifier{Algorithm: oversizedOID()}, Digest: []byte{0x01}},
					MacSalt:    []byte{0x01, 0x02},
					Iterations: 2048,
				},
			},
		},
		{
			name: "oversized authSafe content-type identifier",
			preamble: pfxPreamble{
				Version:  3,
				AuthSafe: contentInfo{ContentType: oversizedOID()},
				MacData: macData{
					Mac:        digestInfo{Algorithm: algorithmIdentifier{Algorithm: rawOID(t, oidSHA256)}, Digest: []byte{0x01}},
					MacSalt:    []byte{0x01, 0x02},
					Iterations: 2048,
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			der, err := asn1.Marshal(tc.preamble)
			if err != nil {
				t.Fatalf("setup: marshal preamble: %v", err)
			}
			if _, err := Inspect(der); !errors.Is(err, ErrProfileUnknown) {
				t.Errorf("Inspect(%s) = %v, want ErrProfileUnknown", tc.name, err)
			}
		})
	}
}

// TestInspect_rejects_an_oversized_safe_bag_identifier completes the allocation
// bound over the LAST untrusted identifier field: a safe bag's own id, reached
// through the plaintext-safe walk rather than through decodeOID in isolation.
// The oversized identifier rides on an EXTRA bag beside the intact key bag,
// because overwriting the key bag's own id cannot pin the bound: without it the
// oversized id merely decodes to something that is not a shrouded key bag, the bag
// is skipped, and "no shrouded private-key bag" is ErrProfileUnknown too. With the
// intact key bag still present, only the bound itself can produce a refusal.
// Production is correct today (safeBag.ID is an asn1.RawValue and keyBagAlgorithm
// decodes it under the bound), but changing that field back to
// asn1.ObjectIdentifier, or bypassing decodeOID at the bag site, leaves every
// other identifier case and all four own-profile round trips green while
// restoring the large pre-authentication allocation.
func TestInspect_rejects_an_oversized_safe_bag_identifier(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := Analyse(slices.Concat(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}
	pfx, err := Encode(&analysis, EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("setup: Encode: %v", err)
	}
	var preamble pfxPreamble
	testASN1Unmarshal(t, pfx, &preamble)
	mutateTestAuthenticatedSafe(t, &preamble, oidDataContentType, func(safe *contentInfo) {
		mutateTestSafeBags(t, safe, func(bags []safeBag) []safeBag {
			oversized := bags[0]
			oversized.ID = oversizedOID()
			return append(bags, oversized)
		})
	})
	if _, err := Inspect(testASN1Marshal(t, preamble)); !errors.Is(err, ErrProfileUnknown) {
		t.Errorf("Inspect(bundle with oversized safe-bag identifier) = %v, want ErrProfileUnknown", err)
	}
}

// TestInspect_rejects_excessive_iterations_in_every_derivation_location pins the
// bound at EVERY location the decoder would honour a stored iteration count, not
// just the modern2023 MAC integer the exported test patches.
//
// Inspect's safety contract is wider than one field: PBMAC1 nests its count in a
// PBKDF2 parameter block, every encrypted certificate safe carries its own, and so
// does the shrouded private-key bag, in two different parameter shapes (PBES2 and
// the legacy pkcs-12PbeParams). Bypassing any one of those checks leaves the
// mutated bundle identifiable as a known profile, so the bundle is accepted and an
// output-volume file can force attacker-chosen PBKDF work on the scan's only
// goroutine — with the MAC-only test still green. Fuzzing does not cover this:
// arbitrary bytes are rejected long before they form valid nested ASN.1.
func TestInspect_rejects_excessive_iterations_in_every_derivation_location(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := Analyse(slices.Concat(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}

	for _, tc := range []struct {
		name   string
		enc    EncoderType
		mutate func(*testing.T, *pfxPreamble)
	}{
		{
			name: "modern2023 MAC",
			enc:  EncNameModern2023,
			mutate: func(_ *testing.T, p *pfxPreamble) {
				p.MacData.Iterations = maxKDFIterations + 1
			},
		},
		{
			name: "modern2026 PBMAC1",
			enc:  EncNameModern2026,
			mutate: func(t *testing.T, p *pfxPreamble) {
				setTestPBKDF2Iterations(t, &p.MacData.Mac.Algorithm, maxKDFIterations+1)
			},
		},
		{
			name: "modern encrypted certificate safe",
			enc:  EncNameModern2023,
			mutate: func(t *testing.T, p *pfxPreamble) {
				mutateTestEncryptedSafe(t, p, func(alg *algorithmIdentifier) {
					setTestPBKDF2Iterations(t, alg, maxKDFIterations+1)
				})
			},
		},
		{
			name: "modern shrouded key bag",
			enc:  EncNameModern2023,
			mutate: func(t *testing.T, p *pfxPreamble) {
				mutateTestShroudedKeyBag(t, p, func(alg *algorithmIdentifier) {
					setTestPBKDF2Iterations(t, alg, maxKDFIterations+1)
				})
			},
		},
		{
			name: "legacy encrypted certificate safe",
			enc:  EncNameLegacyDES,
			mutate: func(t *testing.T, p *pfxPreamble) {
				mutateTestEncryptedSafe(t, p, func(alg *algorithmIdentifier) {
					setTestLegacyIterations(t, alg, maxKDFIterations+1)
				})
			},
		},
		{
			name: "legacy shrouded key bag",
			enc:  EncNameLegacyDES,
			mutate: func(t *testing.T, p *pfxPreamble) {
				mutateTestShroudedKeyBag(t, p, func(alg *algorithmIdentifier) {
					setTestLegacyIterations(t, alg, maxKDFIterations+1)
				})
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pfx, err := Encode(&analysis, tc.enc, "pw")
			if err != nil {
				t.Fatalf("setup: Encode(%s): %v", tc.enc, err)
			}
			if _, err := Inspect(pfx); err != nil {
				t.Fatalf("setup: Inspect(unmodified %s bundle): %v", tc.enc, err)
			}

			var preamble pfxPreamble
			testASN1Unmarshal(t, pfx, &preamble)
			tc.mutate(t, &preamble)
			mutated := testASN1Marshal(t, preamble)

			if _, err := Inspect(mutated); !errors.Is(err, ErrProfileUnknown) {
				t.Errorf("Inspect(%s bundle with excessive iterations) error = %v, want ErrProfileUnknown", tc.enc, err)
			}
		})
	}
}

// mutateTestEncryptedSafe rewrites the content-encryption AlgorithmIdentifier of
// the bundle's encrypted certificate safe.
func mutateTestEncryptedSafe(t *testing.T, p *pfxPreamble, mutate func(*algorithmIdentifier)) {
	t.Helper()
	mutateTestAuthenticatedSafe(t, p, oidEncryptedDataContentType, func(safe *contentInfo) {
		var encrypted encryptedData
		testASN1Unmarshal(t, safe.Content.Bytes, &encrypted)
		mutate(&encrypted.EncryptedContentInfo.ContentEncryptionAlgorithm)
		safe.Content.Bytes = testASN1Marshal(t, encrypted)
		safe.Content.FullBytes = nil
	})
}

// mutateTestShroudedKeyBag rewrites the encryption AlgorithmIdentifier of the
// shrouded private-key bag, which every profile puts in the PLAINTEXT safe.
func mutateTestShroudedKeyBag(t *testing.T, p *pfxPreamble, mutate func(*algorithmIdentifier)) {
	t.Helper()
	mutateTestAuthenticatedSafe(t, p, oidDataContentType, func(safe *contentInfo) {
		mutateTestSafeBags(t, safe, func(bags []safeBag) []safeBag {
			bag := &bags[testShroudedKeyBagIndex(t, bags)]
			var info encryptedPrivateKeyInfo
			testASN1Unmarshal(t, bag.Value.Bytes, &info)
			mutate(&info.Algorithm)
			bag.Value.Bytes = testASN1Marshal(t, info)
			bag.Value.FullBytes = nil
			return bags
		})
	})
}

// mutateTestAuthenticatedSafe applies mutate to the first authenticated safe whose
// content type is want, and re-encodes the enclosing authSafe around it.
func mutateTestAuthenticatedSafe(t *testing.T, p *pfxPreamble, want asn1.ObjectIdentifier, mutate func(*contentInfo)) {
	t.Helper()
	safes := testAuthenticatedSafes(t, p)
	mutate(&safes[testSafeIndex(t, safes, want)])
	setTestAuthenticatedSafes(t, p, safes)
}

// setTestPBKDF2Iterations rewrites the nested PBKDF2 iteration count of a PBES2 or
// PBMAC1 parameter block.
func setTestPBKDF2Iterations(t *testing.T, alg *algorithmIdentifier, iterations int) {
	t.Helper()
	setTestPBKDF2Params(t, alg, func(kdf *pbkdf2Params) { kdf.Iterations = iterations })
}

// setTestLegacyIterations rewrites the iteration count of a pkcs-12PbeParams block.
func setTestLegacyIterations(t *testing.T, alg *algorithmIdentifier, iterations int) {
	t.Helper()
	var params legacyPBEParams
	testASN1Unmarshal(t, alg.Parameters.FullBytes, &params)
	params.Iterations = iterations
	alg.Parameters = asn1.RawValue{FullBytes: testASN1Marshal(t, params)}
}

func testASN1Unmarshal(t *testing.T, der []byte, out any) {
	t.Helper()
	rest, err := asn1.Unmarshal(der, out)
	if err != nil {
		t.Fatalf("setup: ASN.1 unmarshal: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("setup: ASN.1 unmarshal left %d trailing byte(s)", len(rest))
	}
}

func testASN1Marshal(t *testing.T, value any) []byte {
	t.Helper()
	der, err := asn1.Marshal(value)
	if err != nil {
		t.Fatalf("setup: ASN.1 marshal: %v", err)
	}
	return der
}

// testSafeIndex returns the index of the first authenticated safe whose content type is
// want. One home for the walk, so every caller decodes a content type the same way.
func testSafeIndex(t *testing.T, safes []contentInfo, want asn1.ObjectIdentifier) int {
	t.Helper()
	for i := range safes {
		got, err := decodeOID(safes[i].ContentType)
		if err != nil {
			t.Fatalf("setup: decode safe content type: %v", err)
		}
		if got.Equal(want) {
			return i
		}
	}
	t.Fatalf("setup: no authenticated safe with content type %v", want)
	return -1
}

// mutateTestSafeBags decodes a safe's bag list, hands it to mutate, and re-encodes both
// DER layers the payload is wrapped in (the OCTET STRING and the SEQUENCE OF SafeBag)
// around whatever mutate returns.
func mutateTestSafeBags(t *testing.T, safe *contentInfo, mutate func([]safeBag) []safeBag) {
	t.Helper()
	var inner []byte
	testASN1Unmarshal(t, safe.Content.Bytes, &inner)
	var bags []safeBag
	testASN1Unmarshal(t, inner, &bags)
	safeDER := testASN1Marshal(t, mutate(bags))
	safe.Content.Bytes = testASN1Marshal(t, safeDER)
	safe.Content.FullBytes = nil
}

// testShroudedKeyBagIndex returns the index of the shrouded private-key bag, which every
// profile puts alone in the plaintext safe.
func testShroudedKeyBagIndex(t *testing.T, bags []safeBag) int {
	t.Helper()
	for i := range bags {
		id, err := decodeOID(bags[i].ID)
		if err != nil {
			t.Fatalf("setup: decode bag id: %v", err)
		}
		if id.Equal(oidPKCS8ShroudedKeyBag) {
			return i
		}
	}
	t.Fatal("setup: no shrouded key bag in the plaintext safe")
	return -1
}

func TestInspect_rejects_more_than_one_shrouded_key_bag(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := Analyse(slices.Concat(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}
	pfx, err := Encode(&analysis, EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("setup: Encode: %v", err)
	}
	if _, err := Inspect(pfx); err != nil {
		t.Fatalf("setup: Inspect(unmodified bundle) = %v, want nil", err)
	}

	for _, tc := range []struct {
		name string
		// wantErrText is the guard-specific fragment the refusal must carry.
		// errors.Is(ErrProfileUnknown) alone cannot pin these guards: with any one
		// of them deleted, Inspect still fails ErrProfileUnknown from a later arm
		// (a missing certificate or key bag), so the subtest would pass for the
		// wrong reason. Empty means the case must be accepted.
		wantErrText string
		mutate      func(*testing.T, []contentInfo) []contentInfo
	}{
		{"the control: re-encoded unchanged", "", func(_ *testing.T, safes []contentInfo) []contentInfo { return safes }},
		{"a second bag inside one plaintext safe", "more than one shrouded private-key bag in one safe", duplicateTestKeyBag},
		{"trailing bytes after the plaintext safe's content", "trailing byte(s) after a plaintext safe's content", appendTestTrailingByteToPlaintextSafe},
		{"trailing bytes after an encrypted safe's contents", "trailing byte(s) after an encrypted safe's contents", appendTestTrailingByteToEncryptedSafe},
		{"trailing bytes after the shrouded key bag", "trailing byte(s) after a shrouded key bag's EncryptedPrivateKeyInfo", appendTestTrailingByteToKeyBag},
		{"a second plaintext safe carrying its own bag", "more than one shrouded private-key bag", duplicateTestPlaintextSafe},
		{"a second encrypted certificate safe", "more than one encrypted certificate bag", duplicateTestEncryptedSafe},
		{"more authenticated safes than the preflight admits", "more than 2 element(s)", appendTestPlaintextSafe},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var preamble pfxPreamble
			testASN1Unmarshal(t, pfx, &preamble)
			setTestAuthenticatedSafes(t, &preamble, tc.mutate(t, testAuthenticatedSafes(t, &preamble)))
			got, err := Inspect(testASN1Marshal(t, preamble))
			if tc.wantErrText == "" {
				if err != nil {
					t.Fatalf("Inspect(%s) = %v, want nil", tc.name, err)
				}
				if got.Profile != EncNameModern2023 {
					t.Errorf("Inspect(%s) reported %q, want %q", tc.name, got.Profile, EncNameModern2023)
				}
				return
			}
			if !errors.Is(err, ErrProfileUnknown) {
				t.Fatalf("Inspect(bundle with %s) = %v, want ErrProfileUnknown", tc.name, err)
			}
			if !strings.Contains(err.Error(), tc.wantErrText) {
				t.Errorf("Inspect(bundle with %s) = %v, want the refusal to come from the guard naming %q, not a later arm",
					tc.name, err, tc.wantErrText)
			}
		})
	}
}

// TestInspect_rejects_a_non_v3_pfx_version pins the preamble version guard: every
// profile this app writes is a v3 PFX and go-pkcs12's decoder refuses anything else
// before it verifies the MAC, so a different version is not a bundle we wrote and
// must not be reported as a known profile.
func TestInspect_rejects_a_non_v3_pfx_version(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := Analyse(slices.Concat(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}
	pfx, err := Encode(&analysis, EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("setup: Encode: %v", err)
	}

	var preamble pfxPreamble
	testASN1Unmarshal(t, pfx, &preamble)
	preamble.Version = 1
	got, err := Inspect(testASN1Marshal(t, preamble))
	if !errors.Is(err, ErrProfileUnknown) {
		t.Fatalf("Inspect(v1 pfx) = (%+v, %v), want ErrProfileUnknown", got, err)
	}
	if !strings.Contains(err.Error(), "pfx version 1, want 3") {
		t.Errorf("Inspect(v1 pfx) = %v, want the refusal to name the version", err)
	}
}

// TestInspect_rejects_a_non_zero_encrypted_safe_version pins the encrypted-safe
// version guard, the sibling of the preamble's v3 check: go-pkcs12 writes version 0
// and its decoder refuses any other value before it decrypts the safe, so a
// different version is not a shape this app emits.
func TestInspect_rejects_a_non_zero_encrypted_safe_version(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := Analyse(slices.Concat(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}
	pfx, err := Encode(&analysis, EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("setup: Encode: %v", err)
	}

	var preamble pfxPreamble
	testASN1Unmarshal(t, pfx, &preamble)
	mutateTestAuthenticatedSafe(t, &preamble, oidEncryptedDataContentType, func(safe *contentInfo) {
		var encrypted encryptedData
		testASN1Unmarshal(t, safe.Content.Bytes, &encrypted)
		encrypted.Version = 7
		safe.Content.Bytes = testASN1Marshal(t, encrypted)
		safe.Content.FullBytes = nil
	})
	got, err := Inspect(testASN1Marshal(t, preamble))
	if !errors.Is(err, ErrProfileUnknown) {
		t.Fatalf("Inspect(encrypted safe v7) = (%+v, %v), want ErrProfileUnknown", got, err)
	}
	if !strings.Contains(err.Error(), "encrypted safe version 7, want 0") {
		t.Errorf("Inspect(encrypted safe v7) = %v, want the refusal to name the version", err)
	}
}

// testAuthenticatedSafes decodes the authenticated safe list out of a preamble.
func testAuthenticatedSafes(t *testing.T, p *pfxPreamble) []contentInfo {
	t.Helper()
	var inner []byte
	testASN1Unmarshal(t, p.AuthSafe.Content.Bytes, &inner)
	var safes []contentInfo
	testASN1Unmarshal(t, inner, &safes)
	return safes
}

// setTestAuthenticatedSafes re-encodes a safe list back into the preamble.
func setTestAuthenticatedSafes(t *testing.T, p *pfxPreamble, safes []contentInfo) {
	t.Helper()
	inner := testASN1Marshal(t, safes)
	p.AuthSafe.Content.Bytes = testASN1Marshal(t, inner)
	p.AuthSafe.Content.FullBytes = nil
}

// plaintextTestSafeIndex returns the index of the first data-type safe, which is
// where every profile puts the shrouded private-key bag.
func plaintextTestSafeIndex(t *testing.T, safes []contentInfo) int {
	t.Helper()
	return testSafeIndex(t, safes, oidDataContentType)
}

// duplicateTestKeyBag adds a second shrouded key bag INSIDE the plaintext safe.
func duplicateTestKeyBag(t *testing.T, safes []contentInfo) []contentInfo {
	t.Helper()
	mutateTestSafeBags(t, &safes[plaintextTestSafeIndex(t, safes)], func(bags []safeBag) []safeBag {
		return append(bags, bags[testShroudedKeyBagIndex(t, bags)])
	})
	return safes
}

// appendTestTrailingByteToPlaintextSafe appends one byte after the plaintext safe's
// content, so the preflight is asked to identify a profile from a PREFIX of a
// structure whose remaining bytes it never reads. Accepting that means inspecting one
// structure while the decoder acts on another, which is the parse differential the
// preflight exists to prevent.
func appendTestTrailingByteToPlaintextSafe(t *testing.T, safes []contentInfo) []contentInfo {
	t.Helper()
	safe := &safes[plaintextTestSafeIndex(t, safes)]
	safe.Content.Bytes = append(slices.Clone(safe.Content.Bytes), 0x00)
	safe.Content.FullBytes = nil
	return safes
}

// appendTestTrailingByteToEncryptedSafe appends one byte after the encrypted
// certificate safe's contents, the second of the preflight's four trailing-byte
// refusals.
func appendTestTrailingByteToEncryptedSafe(t *testing.T, safes []contentInfo) []contentInfo {
	t.Helper()
	safe := &safes[testSafeIndex(t, safes, oidEncryptedDataContentType)]
	safe.Content.Bytes = append(slices.Clone(safe.Content.Bytes), 0x00)
	safe.Content.FullBytes = nil
	return safes
}

// appendTestTrailingByteToKeyBag appends one byte after the shrouded key bag's
// EncryptedPrivateKeyInfo, the innermost of the four.
func appendTestTrailingByteToKeyBag(t *testing.T, safes []contentInfo) []contentInfo {
	t.Helper()
	mutateTestSafeBags(t, &safes[plaintextTestSafeIndex(t, safes)], func(bags []safeBag) []safeBag {
		bag := &bags[testShroudedKeyBagIndex(t, bags)]
		bag.Value.Bytes = append(slices.Clone(bag.Value.Bytes), 0x00)
		bag.Value.FullBytes = nil
		return bags
	})
	return safes
}

// duplicateTestPlaintextSafe REPLACES the safe list with two copies of the
// plaintext safe, so the bundle carries two shrouded key bags in two safes while
// staying inside maxAuthenticatedSafes. Appending a third element instead would
// trip sequenceElements' element-count bound before merge ever saw the duplicate.
func duplicateTestPlaintextSafe(t *testing.T, safes []contentInfo) []contentInfo {
	t.Helper()
	plaintext := safes[plaintextTestSafeIndex(t, safes)]
	return []contentInfo{plaintext, plaintext}
}

// duplicateTestEncryptedSafe replaces the safe list with two copies of the
// encrypted certificate safe: the shape merge refuses because a bundle's
// certificate-encryption identity would otherwise be read from one safe while the
// certificates lived in the other. Two elements, so the element-count bound is not
// what rejects it.
func duplicateTestEncryptedSafe(t *testing.T, safes []contentInfo) []contentInfo {
	t.Helper()
	encrypted := safes[testSafeIndex(t, safes, oidEncryptedDataContentType)]
	return []contentInfo{encrypted, encrypted}
}

// appendTestPlaintextSafe pushes the bundle one element PAST
// maxAuthenticatedSafes, pinning sequenceElements' element-count bound
// deliberately rather than as an accident of another case.
func appendTestPlaintextSafe(t *testing.T, safes []contentInfo) []contentInfo {
	t.Helper()
	return append(safes, safes[plaintextTestSafeIndex(t, safes)])
}

// TestInspect_rejects_a_weaker_pbes2_cipher pins checkPBES2Parameters' cipher arm.
// The profile
// identity is the (MAC, certificate, key) OID triple, and PBES2 names its cipher in
// its PARAMETERS, so without this arm a bundle whose PBES2 wraps AES-128-CBC reads
// as modern2023 and store.isCurrent keeps it as current indefinitely. The positive
// direction is already covered by the own-profile round trips, which is what proves
// the check does not over-reject this app's own output.
func TestInspect_rejects_a_weaker_pbes2_cipher(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := Analyse(slices.Concat(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}
	pfx, err := Encode(&analysis, EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("setup: Encode: %v", err)
	}
	var preamble pfxPreamble
	testASN1Unmarshal(t, pfx, &preamble)
	mutateTestEncryptedSafe(t, &preamble, func(alg *algorithmIdentifier) {
		// aes-128-CBC: a cipher go-pkcs12 decodes happily and no profile emits.
		setTestPBES2Cipher(t, alg, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2})
	})
	if _, err := Inspect(testASN1Marshal(t, preamble)); !errors.Is(err, ErrProfileUnknown) {
		t.Errorf("Inspect(bundle whose PBES2 wraps AES-128-CBC) = %v, want ErrProfileUnknown", err)
	}
}

// setTestPBES2Cipher rewrites the encryption scheme of a PBES2 parameter block.
func setTestPBES2Cipher(t *testing.T, alg *algorithmIdentifier, scheme asn1.ObjectIdentifier) {
	t.Helper()
	var params pbes2Params
	testASN1Unmarshal(t, alg.Parameters.FullBytes, &params)
	params.EncryptionScheme.Algorithm = asn1.RawValue{FullBytes: testASN1Marshal(t, scheme)}
	alg.Parameters = asn1.RawValue{FullBytes: testASN1Marshal(t, params)}
}

// TestInspect_rejects_a_weaker_nested_modern_algorithm pins every fixed algorithm
// choice a modern profile makes INSIDE a parameter block, where the (MAC,
// certificate, key) OID triple cannot see it.
//
// This is the currency hole, not just a hardening nicety. go-pkcs12's decoder
// accepts PBKDF2-HMAC-SHA1 and PBMAC1-HMAC-SHA1, and treats an absent PRF as
// HMAC-SHA1 by ASN.1 default, so a bundle carrying the same leaf, key, chain and
// password but SHA-1 in these nested fields decodes, matches the Analysis, and is
// reported current. An operator who selected modern2023 or modern2026 would keep
// SHA-1 derivation on disk indefinitely while the startup log announced the modern
// profile — the file is never regenerated, because nothing ever notices.
//
// Each case asserts the guard-specific message as well as ErrProfileUnknown: the
// sentinel alone cannot tell which arm refused, and several of these mutations are
// one field apart from each other.
func TestInspect_rejects_a_weaker_nested_modern_algorithm(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := Analyse(slices.Concat(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}
	// hmacWithSHA1: the PRF and MAC go-pkcs12 decodes happily and no profile emits.
	sha1HMAC := asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}

	for _, tc := range []struct {
		name        string
		enc         EncoderType
		wantErrText string
		mutate      func(*testing.T, *pfxPreamble)
	}{
		{
			name:        "certificate safe derived with HMAC-SHA1",
			enc:         EncNameModern2023,
			wantErrText: "pbes2 PBKDF2 PRF is 1.2.840.113549.2.7",
			mutate: func(t *testing.T, p *pfxPreamble) {
				mutateTestEncryptedSafe(t, p, func(alg *algorithmIdentifier) {
					setTestPBKDF2PRF(t, alg, sha1HMAC)
				})
			},
		},
		{
			name:        "shrouded key bag derived with HMAC-SHA1",
			enc:         EncNameModern2023,
			wantErrText: "pbes2 PBKDF2 PRF is 1.2.840.113549.2.7",
			mutate: func(t *testing.T, p *pfxPreamble) {
				mutateTestShroudedKeyBag(t, p, func(alg *algorithmIdentifier) {
					setTestPBKDF2PRF(t, alg, sha1HMAC)
				})
			},
		},
		{
			name:        "certificate safe naming no PRF at all",
			enc:         EncNameModern2023,
			wantErrText: "pbes2 PBKDF2 names no PRF",
			mutate: func(t *testing.T, p *pfxPreamble) {
				mutateTestEncryptedSafe(t, p, func(alg *algorithmIdentifier) {
					setTestPBKDF2PRF(t, alg, nil)
				})
			},
		},
		{
			name:        "certificate safe deriving with a salt that is not an OCTET STRING",
			enc:         EncNameModern2023,
			wantErrText: "pbes2 PBKDF2 salt is not a primitive OCTET STRING",
			mutate: func(t *testing.T, p *pfxPreamble) {
				mutateTestEncryptedSafe(t, p, func(alg *algorithmIdentifier) {
					setTestPBKDF2Params(t, alg, func(kdf *pbkdf2Params) {
						// A PrintableString where the specified-OCTET-STRING arm of
						// the CHOICE belongs: structurally valid DER the decoder
						// refuses too.
						kdf.Salt = asn1.RawValue{FullBytes: testASN1Marshal(t, "not-an-octet-string")}
					})
				})
			},
		},
		{
			name:        "certificate safe naming a key derivation that is not PBKDF2",
			enc:         EncNameModern2023,
			wantErrText: "pbes2 key derivation is 1.2.840.113549.1.5.13, want PBKDF2",
			mutate: func(t *testing.T, p *pfxPreamble) {
				mutateTestEncryptedSafe(t, p, func(alg *algorithmIdentifier) {
					setTestPBKDF2Algorithm(t, alg, asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13})
				})
			},
		},
		{
			name:        "PBMAC1 derived with HMAC-SHA1",
			enc:         EncNameModern2026,
			wantErrText: "pbmac1 PBKDF2 PRF is 1.2.840.113549.2.7",
			mutate: func(t *testing.T, p *pfxPreamble) {
				setTestPBKDF2PRF(t, &p.MacData.Mac.Algorithm, sha1HMAC)
			},
		},
		{
			name:        "PBMAC1 authenticated with HMAC-SHA1",
			enc:         EncNameModern2026,
			wantErrText: "pbmac1 message authentication is 1.2.840.113549.2.7",
			mutate: func(t *testing.T, p *pfxPreamble) {
				setTestPBMAC1Mac(t, &p.MacData.Mac.Algorithm, sha1HMAC)
			},
		},
		{
			// 20 octets is the shortest key the decoder accepts (mac.go:128),
			// so this is a weaker MAC that still round-trips.
			name:        "PBMAC1 deriving a 20-octet key",
			enc:         EncNameModern2026,
			wantErrText: "pbmac1 derives a 20-octet key, want 32",
			mutate: func(t *testing.T, p *pfxPreamble) {
				setTestPBKDF2KeyLength(t, &p.MacData.Mac.Algorithm, 20)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pfx, err := Encode(&analysis, tc.enc, "pw")
			if err != nil {
				t.Fatalf("setup: Encode(%s): %v", tc.enc, err)
			}
			if _, err := Inspect(pfx); err != nil {
				t.Fatalf("setup: Inspect(unmodified %s bundle): %v", tc.enc, err)
			}
			var preamble pfxPreamble
			testASN1Unmarshal(t, pfx, &preamble)
			tc.mutate(t, &preamble)

			got, err := Inspect(testASN1Marshal(t, preamble))
			if !errors.Is(err, ErrProfileUnknown) {
				t.Fatalf("Inspect(%s) = (%+v, %v), want ErrProfileUnknown", tc.name, got, err)
			}
			if !strings.Contains(err.Error(), tc.wantErrText) {
				t.Errorf("Inspect(%s) = %v, want the refusal to come from the guard naming %q",
					tc.name, err, tc.wantErrText)
			}
		})
	}
}

// setTestPBKDF2PRF rewrites the nested PBKDF2 pseudorandom function of a PBES2 or
// PBMAC1 parameter block; a nil prf REMOVES the field, which is how a file spells
// the ASN.1 default of HMAC-SHA1. pbes2Params reads either block here because both
// are a KDF identifier followed by one more algorithm identifier, and only the KDF
// half is touched.
func setTestPBKDF2PRF(t *testing.T, alg *algorithmIdentifier, prf asn1.ObjectIdentifier) {
	t.Helper()
	setTestPBKDF2Params(t, alg, func(kdf *pbkdf2Params) {
		if prf == nil {
			kdf.PRF = algorithmIdentifier{}
			return
		}
		kdf.PRF = algorithmIdentifier{Algorithm: rawOID(t, prf)}
	})
}

// setTestPBKDF2KeyLength rewrites the derived-key length a PBKDF2 block states.
func setTestPBKDF2KeyLength(t *testing.T, alg *algorithmIdentifier, octets int) {
	t.Helper()
	setTestPBKDF2Params(t, alg, func(kdf *pbkdf2Params) { kdf.KeyLength = octets })
}

// setTestPBKDF2Algorithm rewrites the key-derivation function a PBES2 or PBMAC1
// block names, leaving its parameters in place.
func setTestPBKDF2Algorithm(t *testing.T, alg *algorithmIdentifier, kdfOID asn1.ObjectIdentifier) {
	t.Helper()
	var params pbes2Params
	testASN1Unmarshal(t, alg.Parameters.FullBytes, &params)
	params.KeyDerivationFunc.Algorithm = rawOID(t, kdfOID)
	alg.Parameters = asn1.RawValue{FullBytes: testASN1Marshal(t, params)}
}

// setTestPBKDF2Params applies mutate to the PBKDF2 parameters nested in a PBES2 or
// PBMAC1 block and re-encodes both levels around it.
func setTestPBKDF2Params(t *testing.T, alg *algorithmIdentifier, mutate func(*pbkdf2Params)) {
	t.Helper()
	var params pbes2Params
	testASN1Unmarshal(t, alg.Parameters.FullBytes, &params)
	var kdf pbkdf2Params
	testASN1Unmarshal(t, params.KeyDerivationFunc.Parameters.FullBytes, &kdf)
	mutate(&kdf)
	params.KeyDerivationFunc.Parameters = asn1.RawValue{FullBytes: testASN1Marshal(t, kdf)}
	alg.Parameters = asn1.RawValue{FullBytes: testASN1Marshal(t, params)}
}

// setTestPBMAC1Mac rewrites the message-authentication scheme of a PBMAC1 block.
func setTestPBMAC1Mac(t *testing.T, alg *algorithmIdentifier, mac asn1.ObjectIdentifier) {
	t.Helper()
	var params pbmac1Params
	testASN1Unmarshal(t, alg.Parameters.FullBytes, &params)
	params.MessageAuthScheme.Algorithm = rawOID(t, mac)
	alg.Parameters = asn1.RawValue{FullBytes: testASN1Marshal(t, params)}
}

// TestInspect_rejects_more_safe_bags_than_it_admits pins the element-count bound
// on a plaintext safe's bag list. maxSafeBags is an allocation guard: Go's ASN.1
// decoder sizes a []safeBag from the input's element count and every element costs
// 216 bytes of RawValue headers however small its encoding is, and Inspect runs
// over a file found in the output tree before any authentication, on the scan's
// only goroutine.
//
// Nothing else pins it. Every profile writes exactly ONE bag, so the bound never
// fires on this app's own output, and the fuzz target cannot reach it either:
// arbitrary bytes are rejected long before they form a valid bag list with 65
// members. Raise or delete the bound and every other test in this package stays
// green.
//
// The filler bags carry the data content type as their id, so shroudedKeyBag skips
// them and the single real key bag still resolves: without the bound the 65-bag
// bundle is ACCEPTED as modern2023, which is what the accepted 64-bag case beside
// it shows the construction is otherwise valid for. The error text is asserted
// because ErrProfileUnknown alone cannot say which arm refused.
func TestInspect_rejects_more_safe_bags_than_it_admits(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := Analyse(slices.Concat(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}
	pfx, err := Encode(&analysis, EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("setup: Encode: %v", err)
	}

	for _, tc := range []struct {
		name string
		// fillers is how many non-key bags ride beside the real shrouded key bag.
		fillers int
		// wantErrText is empty when the bundle must still be accepted.
		wantErrText string
	}{
		{"the most bags the preflight admits", maxSafeBags - 1, ""},
		{"one bag more than the preflight admits", maxSafeBags, "more than 64 element(s) in plaintext safe bags"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var preamble pfxPreamble
			testASN1Unmarshal(t, pfx, &preamble)
			mutateTestAuthenticatedSafe(t, &preamble, oidDataContentType, func(safe *contentInfo) {
				var inner []byte
				testASN1Unmarshal(t, safe.Content.Bytes, &inner)
				var bags []safeBag
				testASN1Unmarshal(t, inner, &bags)
				filler := bags[0]
				filler.ID = rawOID(t, oidDataContentType)
				for range tc.fillers {
					bags = append(bags, filler)
				}
				safeDER := testASN1Marshal(t, bags)
				safe.Content.Bytes = testASN1Marshal(t, safeDER)
				safe.Content.FullBytes = nil
			})
			got, err := Inspect(testASN1Marshal(t, preamble))
			if tc.wantErrText == "" {
				if err != nil {
					t.Fatalf("Inspect(%s) = %v, want nil", tc.name, err)
				}
				if got.Profile != EncNameModern2023 {
					t.Errorf("Inspect(%s) reported %q, want %q", tc.name, got.Profile, EncNameModern2023)
				}
				return
			}
			if !errors.Is(err, ErrProfileUnknown) {
				t.Fatalf("Inspect(%s) = %v, want ErrProfileUnknown", tc.name, err)
			}
			if !strings.Contains(err.Error(), tc.wantErrText) {
				t.Errorf("Inspect(%s) = %v, want the refusal to come from the guard naming %q", tc.name, err, tc.wantErrText)
			}
		})
	}
}

// TestInspect_rejects_a_non_positive_iteration_count pins the LOWER half of
// checkIterations' range, which its own comment calls deliberate: a count of zero
// or below is not a value any profile emits, so a file that spells one out is a
// file whose framing this app does not understand and must be regenerated rather
// than trusted.
//
// Only the upper half is otherwise pinned (the excessive-iteration table), so
// narrowing the guard to n < 0, or dropping the non-positive half entirely, leaves
// every test in this package green while Inspect starts reporting such a bundle as
// one of this app's own profiles.
func TestInspect_rejects_a_non_positive_iteration_count(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := Analyse(slices.Concat(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}
	pfx, err := Encode(&analysis, EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("setup: Encode: %v", err)
	}

	for _, tc := range []struct {
		name        string
		iterations  int
		wantErrText string
	}{
		{"zero MAC iterations", 0, "mac iteration count 0 outside"},
		{"negative MAC iterations", -1, "mac iteration count -1 outside"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var preamble pfxPreamble
			testASN1Unmarshal(t, pfx, &preamble)
			preamble.MacData.Iterations = tc.iterations
			_, err := Inspect(testASN1Marshal(t, preamble))
			if !errors.Is(err, ErrProfileUnknown) {
				t.Fatalf("Inspect(%s) = %v, want ErrProfileUnknown", tc.name, err)
			}
			if !strings.Contains(err.Error(), tc.wantErrText) {
				t.Errorf("Inspect(%s) = %v, want the refusal to name %q", tc.name, err, tc.wantErrText)
			}
		})
	}
}

// TestInspect_rejects_trailing_bytes_after_the_authSafe_content pins the outermost
// of the preflight's four trailing-byte refusals. Nothing else reaches it: every
// own-profile bundle leaves exactly one element at this position, so the guard can
// be deleted with the whole package still green.
func TestInspect_rejects_trailing_bytes_after_the_authSafe_content(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := Analyse(slices.Concat(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}
	pfx, err := Encode(&analysis, EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("setup: Encode: %v", err)
	}

	var preamble pfxPreamble
	testASN1Unmarshal(t, pfx, &preamble)
	preamble.AuthSafe.Content.Bytes = append(slices.Clone(preamble.AuthSafe.Content.Bytes), 0x00)
	preamble.AuthSafe.Content.FullBytes = nil

	_, err = Inspect(testASN1Marshal(t, preamble))
	if !errors.Is(err, ErrProfileUnknown) {
		t.Fatalf("Inspect(bundle with a byte after the authSafe content) = %v, want ErrProfileUnknown", err)
	}
	if want := "trailing byte(s) after the authSafe content"; !strings.Contains(err.Error(), want) {
		t.Errorf("Inspect = %v, want the refusal to name %q", err, want)
	}
}

// TestBundleAlgorithms_rejects_wrong_auth_safe_type pins the outer authSafe
// content-type guard: the wrapper must be a data ContentInfo. Nothing else reaches
// it — every own-profile bundle carries the right identifier here, and the generic
// malformed-bytes cases fail earlier in the parse — so the guard can be deleted
// with the whole package still green while a wrapper claiming encryptedData is
// classified as a known profile.
func TestBundleAlgorithms_rejects_wrong_auth_safe_type(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := Analyse(slices.Concat(m.LeafPEM, m.CAPEM), m.LeafKeyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse: %v", err)
	}
	pfx, err := Encode(&analysis, EncNameModern2023, "pw")
	if err != nil {
		t.Fatalf("setup: Encode: %v", err)
	}

	var preamble pfxPreamble
	testASN1Unmarshal(t, pfx, &preamble)
	preamble.AuthSafe.ContentType = rawOID(t, oidEncryptedDataContentType)

	_, err = Inspect(testASN1Marshal(t, preamble))
	if !errors.Is(err, ErrProfileUnknown) {
		t.Fatalf("Inspect(wrong authSafe content type) = %v, want ErrProfileUnknown", err)
	}
	if want := "authSafe is not a data ContentInfo"; !strings.Contains(err.Error(), want) {
		t.Errorf("Inspect(wrong authSafe content type) = %v, want the refusal to name %q", err, want)
	}
}

// testProfilePBKDF2 builds the PBKDF2 AlgorithmIdentifier both modern profiles
// emit, round-tripped through DER so every retained field carries the raw bytes
// parseProfilePBKDF2 reads, and asserts it is accepted as it stands. Each caller
// below mutates exactly one field, so the refusal it asserts can only come from
// that mutation.
func testProfilePBKDF2(t *testing.T) algorithmIdentifier {
	t.Helper()
	params := pbkdf2Params{
		Salt:       asn1.RawValue{FullBytes: testASN1Marshal(t, []byte("salt"))},
		Iterations: 2048,
		PRF:        algorithmIdentifier{Algorithm: rawOID(t, oidHMACWithSHA256)},
	}
	encoded := algorithmIdentifier{
		Algorithm:  rawOID(t, oidPBKDF2),
		Parameters: asn1.RawValue{FullBytes: testASN1Marshal(t, params)},
	}
	var alg algorithmIdentifier
	testASN1Unmarshal(t, testASN1Marshal(t, encoded), &alg)
	if _, err := parseProfilePBKDF2("pbes2", &alg); err != nil {
		t.Fatalf("setup: parseProfilePBKDF2(unmutated block) = %v, want nil", err)
	}
	return alg
}

// setTestProfilePBKDF2Params applies mutate to the parameters of a bare PBKDF2
// AlgorithmIdentifier and re-encodes the block around them. Distinct from
// setTestPBKDF2Params, which reaches the same parameters through an enclosing
// PBES2 or PBMAC1 block.
func setTestProfilePBKDF2Params(t *testing.T, alg *algorithmIdentifier, mutate func(*pbkdf2Params)) {
	t.Helper()
	var params pbkdf2Params
	testASN1Unmarshal(t, alg.Parameters.FullBytes, &params)
	mutate(&params)
	alg.Parameters = asn1.RawValue{FullBytes: testASN1Marshal(t, params)}
}

// TestParseProfilePBKDF2_rejects_trailing_parameters pins the trailing-byte
// refusal of the PBKDF2 parameter block. The neighbouring authSafe, safe and bag
// layers each have one, but this innermost layer has none: valid parameters with
// appended DER would otherwise be accepted as a shape this app emits.
func TestParseProfilePBKDF2_rejects_trailing_parameters(t *testing.T) {
	t.Parallel()
	alg := testProfilePBKDF2(t)
	alg.Parameters.FullBytes = append(slices.Clone(alg.Parameters.FullBytes), 0)

	_, err := parseProfilePBKDF2("pbes2", &alg)
	if !errors.Is(err, ErrProfileUnknown) {
		t.Fatalf("parseProfilePBKDF2(trailing parameters) = %v, want ErrProfileUnknown", err)
	}
	if want := "trailing byte(s) after the pbes2 PBKDF2 parameters"; !strings.Contains(err.Error(), want) {
		t.Errorf("parseProfilePBKDF2(trailing parameters) = %v, want the refusal to name %q", err, want)
	}
}

// TestParseProfilePBKDF2_rejects_every_invalid_salt_shape completes the salt guard.
// The existing nested-algorithm table exercises its TAG clause only, so the
// universal-class and primitive-form clauses can be dropped while every other test
// stays green — and either regression would accept a context-specific or
// constructed salt the decoder cannot consume, reporting an unsupported bundle as
// current instead of regenerating it.
func TestParseProfilePBKDF2_rejects_every_invalid_salt_shape(t *testing.T) {
	t.Parallel()

	for name, salt := range map[string]asn1.RawValue{
		"context-specific tag 4": {
			Class: asn1.ClassContextSpecific,
			Tag:   asn1.TagOctetString,
			Bytes: []byte("salt"),
		},
		"constructed universal OCTET STRING": {
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagOctetString,
			IsCompound: true,
			Bytes:      testASN1Marshal(t, []byte("salt")),
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			alg := testProfilePBKDF2(t)
			setTestProfilePBKDF2Params(t, &alg, func(params *pbkdf2Params) { params.Salt = salt })

			_, err := parseProfilePBKDF2("pbes2", &alg)
			if !errors.Is(err, ErrProfileUnknown) {
				t.Fatalf("parseProfilePBKDF2(%s) = %v, want ErrProfileUnknown", name, err)
			}
			if want := "not a primitive OCTET STRING"; !strings.Contains(err.Error(), want) {
				t.Errorf("parseProfilePBKDF2(%s) = %v, want the refusal to name %q", name, err, want)
			}
		})
	}
}

// TestParseProfilePBKDF2_bounds_both_nested_identifiers pins that the two identifier
// fields nested inside a PBKDF2 block are read through the BOUNDED decoder. The bound
// itself is one shared helper (decodeOID) already pinned at the outer MAC, authSafe,
// safe-bag, encryption and message-authentication sites, so what can regress here is
// not the bound but the routing: a nested field re-read with a raw asn1.Unmarshal would
// let an unauthenticated bundle drive oversized identifier decoding on the scan's only
// goroutine while every bound test stayed green.
func TestParseProfilePBKDF2_bounds_both_nested_identifiers(t *testing.T) {
	t.Parallel()

	for name, mutate := range map[string]func(*testing.T, *algorithmIdentifier){
		"KDF identifier": func(_ *testing.T, alg *algorithmIdentifier) {
			alg.Algorithm = oversizedOID()
		},
		"PRF identifier": func(t *testing.T, alg *algorithmIdentifier) {
			setTestProfilePBKDF2Params(t, alg, func(params *pbkdf2Params) {
				params.PRF.Algorithm = oversizedOID()
			})
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			alg := testProfilePBKDF2(t)
			mutate(t, &alg)

			_, err := parseProfilePBKDF2("pbes2", &alg)
			if !errors.Is(err, ErrProfileUnknown) {
				t.Fatalf("parseProfilePBKDF2(oversized %s) = %v, want ErrProfileUnknown", name, err)
			}
			if want := "object identifier exceeds"; !strings.Contains(err.Error(), want) {
				t.Errorf("parseProfilePBKDF2(oversized %s) = %v, want the refusal to name %q", name, err, want)
			}
		})
	}
}
