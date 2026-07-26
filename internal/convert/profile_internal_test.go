package convert

import (
	"encoding/asn1"
	"errors"
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
// Production is correct today (safeBag.ID is an asn1.RawValue and keyBagAlgorithm
// decodes it under the bound), but changing that field back to
// asn1.ObjectIdentifier, or bypassing decodeOID at the bag site, leaves every
// other identifier case and all four own-profile round trips green while
// restoring the large pre-authentication allocation.
func TestInspect_rejects_an_oversized_safe_bag_identifier(t *testing.T) {
	t.Parallel()
	m := testcerts.GenerateChainMaterial(t)
	analysis, err := Analyse(append(append([]byte{}, m.LeafPEM...), m.CAPEM...), m.LeafKeyPEM)
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
		var inner []byte
		testASN1Unmarshal(t, safe.Content.Bytes, &inner)
		var bags []safeBag
		testASN1Unmarshal(t, inner, &bags)
		bags[0].ID = oversizedOID()
		safeDER := testASN1Marshal(t, bags)
		safe.Content.Bytes = testASN1Marshal(t, safeDER)
		safe.Content.FullBytes = nil
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
	analysis, err := Analyse(append(append([]byte{}, m.LeafPEM...), m.CAPEM...), m.LeafKeyPEM)
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
		var inner []byte
		testASN1Unmarshal(t, safe.Content.Bytes, &inner)
		var bags []safeBag
		testASN1Unmarshal(t, inner, &bags)
		for i := range bags {
			id, err := decodeOID(bags[i].ID)
			if err != nil {
				t.Fatalf("setup: decode bag id: %v", err)
			}
			if !id.Equal(oidPKCS8ShroudedKeyBag) {
				continue
			}
			var info encryptedPrivateKeyInfo
			testASN1Unmarshal(t, bags[i].Value.Bytes, &info)
			mutate(&info.Algorithm)
			bags[i].Value.Bytes = testASN1Marshal(t, info)
			bags[i].Value.FullBytes = nil
			safeDER := testASN1Marshal(t, bags)
			safe.Content.Bytes = testASN1Marshal(t, safeDER)
			safe.Content.FullBytes = nil
			return
		}
		t.Fatal("setup: no shrouded key bag found")
	})
}

// mutateTestAuthenticatedSafe applies mutate to the first authenticated safe whose
// content type is want, and re-encodes the enclosing authSafe around it.
func mutateTestAuthenticatedSafe(t *testing.T, p *pfxPreamble, want asn1.ObjectIdentifier, mutate func(*contentInfo)) {
	t.Helper()
	var inner []byte
	testASN1Unmarshal(t, p.AuthSafe.Content.Bytes, &inner)
	var safes []contentInfo
	testASN1Unmarshal(t, inner, &safes)
	for i := range safes {
		got, err := decodeOID(safes[i].ContentType)
		if err != nil {
			t.Fatalf("setup: decode safe content type: %v", err)
		}
		if got.Equal(want) {
			mutate(&safes[i])
			inner = testASN1Marshal(t, safes)
			p.AuthSafe.Content.Bytes = testASN1Marshal(t, inner)
			p.AuthSafe.Content.FullBytes = nil
			return
		}
	}
	t.Fatalf("setup: no authenticated safe with content type %v", want)
}

// setTestPBKDF2Iterations rewrites the nested PBKDF2 iteration count of a PBES2 or
// PBMAC1 parameter block.
func setTestPBKDF2Iterations(t *testing.T, alg *algorithmIdentifier, iterations int) {
	t.Helper()
	var params pbes2Params
	testASN1Unmarshal(t, alg.Parameters.FullBytes, &params)
	var kdf pbkdf2Params
	testASN1Unmarshal(t, params.KeyDerivationFunc.Parameters.FullBytes, &kdf)
	kdf.Iterations = iterations
	params.KeyDerivationFunc.Parameters = asn1.RawValue{FullBytes: testASN1Marshal(t, kdf)}
	alg.Parameters = asn1.RawValue{FullBytes: testASN1Marshal(t, params)}
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
