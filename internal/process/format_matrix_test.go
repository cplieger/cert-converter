package process_test

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/outputpolicy"
	"github.com/cplieger/cert-converter/internal/process"
	"github.com/cplieger/cert-converter/internal/testcerts"
	"github.com/cplieger/slogx/capture"
	"software.sslmate.com/src/go-pkcs12"
)

func TestScannerRun_PEMSourceEmitsSelectedFormats(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		formats   outputpolicy.Formats
		wantPaths []string
	}{
		{name: "pfx only", formats: outputpolicy.Formats{PFX: true}, wantPaths: []string{"site.pfx"}},
		{name: "pem only", formats: outputpolicy.Formats{PEM: true}, wantPaths: []string{"site.crt", "site.key"}},
		{name: "both", formats: outputpolicy.Formats{PFX: true, PEM: true}, wantPaths: []string{"site.crt", "site.key", "site.pfx"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			input := t.TempDir()
			output := t.TempDir()
			certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "pem-source.example.com", "ecdsa")
			writePEMSource(t, input, "site", certPEM, keyPEM)
			scanner := newFormatScanner(input, output, tc.formats, outputpolicy.LayoutMirror, "", outputpolicy.LifecycleWarn)

			first, err := scanner.Run(t.Context())
			if err != nil {
				t.Fatalf("Run(PEM source, formats=%v) = %v", tc.formats.Names(), err)
			}
			if first.Converted != 1 || first.Failed != 0 {
				t.Fatalf("Run(PEM source, formats=%v) = %+v, want Converted 1 Failed 0", tc.formats.Names(), first)
			}
			assertOnlyRegularFiles(t, output, tc.wantPaths)
			if tc.formats.PEM {
				assertFileBytes(t, filepath.Join(output, "site.crt"), certPEM)
				assertFileBytes(t, filepath.Join(output, "site.key"), keyPEM)
			}
			if tc.formats.PFX {
				assertPFXCommonName(t, filepath.Join(output, "site.pfx"), "output-password", "pem-source.example.com")
			}

			second, err := scanner.Run(t.Context())
			if err != nil {
				t.Fatalf("second Run(PEM source, formats=%v) = %v", tc.formats.Names(), err)
			}
			if second.Unchanged != 1 || second.Converted != 0 {
				t.Errorf("second Run(PEM source, formats=%v) = %+v, want Unchanged 1 Converted 0", tc.formats.Names(), second)
			}
		})
	}
}

func TestScannerRun_PFXSourceEmitsPEMAndReencodedPFX(t *testing.T) {
	t.Parallel()
	input := t.TempDir()
	output := t.TempDir()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "pfx-source.example.com", "ecdsa")
	writePFXSource(t, input, "site.p12", certPEM, keyPEM, "input-password", convert.EncNameLegacyDES)
	scanner := newFormatScanner(input, output, outputpolicy.Formats{PFX: true, PEM: true}, outputpolicy.LayoutMirror, "input-password", outputpolicy.LifecycleWarn)

	result, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("Run(PFX source) = %v", err)
	}
	if result.Converted != 1 || result.Failed != 0 {
		t.Fatalf("Run(PFX source) = %+v, want Converted 1 Failed 0", result)
	}
	assertOnlyRegularFiles(t, output, []string{"site.crt", "site.key", "site.pfx"})
	assertPFXCommonName(t, filepath.Join(output, "site.pfx"), "output-password", "pfx-source.example.com")
	if _, _, _, err := pkcs12.DecodeChain(readFile(t, filepath.Join(output, "site.pfx")), "input-password"); err == nil {
		t.Error("output PFX decoded with the input password, want it re-encoded with the configured output password")
	}
	assertPEMCommonName(t, filepath.Join(output, "site.crt"), filepath.Join(output, "site.key"), "pfx-source.example.com")

	second, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("second Run(PFX source) = %v", err)
	}
	if second.Unchanged != 1 || second.Converted != 0 {
		t.Errorf("second Run(PFX source) = %+v, want Unchanged 1 Converted 0", second)
	}
}

func TestScannerRun_PEMPairTakesPrecedenceOverBundleWithSameStem(t *testing.T) {
	t.Parallel()
	input := t.TempDir()
	output := t.TempDir()
	pairCert, pairKey := testcerts.GenerateSelfSignedCert(t, "pair-wins.example.com", "ecdsa")
	bundleCert, bundleKey := testcerts.GenerateSelfSignedCert(t, "bundle-loses.example.com", "ecdsa")
	writePEMSource(t, input, "site", pairCert, pairKey)
	writePFXSource(t, input, "site.pfx", bundleCert, bundleKey, "input-password", convert.EncNameModern2023)
	scanner := newFormatScanner(input, output, outputpolicy.Formats{PFX: true}, outputpolicy.LayoutMirror, "input-password", outputpolicy.LifecycleWarn)

	result, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("Run(pair and bundle with same stem) = %v", err)
	}
	if result.Total != 1 || result.Converted != 1 {
		t.Fatalf("Run(pair and bundle with same stem) = %+v, want Total 1 Converted 1", result)
	}
	assertPFXCommonName(t, filepath.Join(output, "site.pfx"), "output-password", "pair-wins.example.com")
}

func TestScannerRun_PFXSpellingTakesPrecedenceOverP12(t *testing.T) {
	t.Parallel()
	input := t.TempDir()
	output := t.TempDir()
	pfxCert, pfxKey := testcerts.GenerateSelfSignedCert(t, "pfx-wins.example.com", "ecdsa")
	p12Cert, p12Key := testcerts.GenerateSelfSignedCert(t, "p12-loses.example.com", "ecdsa")
	writePFXSource(t, input, "site.pfx", pfxCert, pfxKey, "input-password", convert.EncNameModern2023)
	writePFXSource(t, input, "site.p12", p12Cert, p12Key, "input-password", convert.EncNameModern2023)
	scanner := newFormatScanner(input, output, outputpolicy.Formats{PFX: true}, outputpolicy.LayoutMirror, "input-password", outputpolicy.LifecycleWarn)

	result, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("Run(.pfx and .p12 with same stem) = %v", err)
	}
	if result.Total != 1 || result.Converted != 1 {
		t.Fatalf("Run(.pfx and .p12 with same stem) = %+v, want Total 1 Converted 1", result)
	}
	assertPFXCommonName(t, filepath.Join(output, "site.pfx"), "output-password", "pfx-wins.example.com")
}

// TestScannerRun_flatOrphanCertDoesNotSuppressBundle pins the arbitration
// population: only SOURCES claim an output stem. A certificate whose sibling
// key is gone is not a pair — it resolves as an ordinary orphan, and the valid
// same-stem bundle converts instead of being refused as a collision.
func TestScannerRun_flatOrphanCertDoesNotSuppressBundle(t *testing.T) {
	t.Parallel()
	input := t.TempDir()
	output := t.TempDir()
	bundleCert, bundleKey := testcerts.GenerateSelfSignedCert(t, "orphan-vs-bundle.example.com", "ecdsa")
	writePFXSource(t, input, "site.pfx", bundleCert, bundleKey, "input-password", convert.EncNameModern2023)
	strayCert, _ := testcerts.GenerateSelfSignedCert(t, "stray.example.com", "ecdsa")
	if err := os.WriteFile(filepath.Join(input, "site.crt"), strayCert, 0o600); err != nil {
		t.Fatalf("setup: write orphan certificate: %v", err)
	}
	scanner := newFormatScanner(input, output, outputpolicy.Formats{PFX: true}, outputpolicy.LayoutFlat, "input-password", outputpolicy.LifecycleWarn)

	result, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("Run(orphan cert beside bundle) = %v", err)
	}
	if result.Converted != 1 || result.Orphan != 1 || result.Collided != 0 {
		t.Fatalf("Run(orphan cert beside bundle) = %+v, want Converted 1 Orphan 1 Collided 0", result)
	}
	assertPFXCommonName(t, filepath.Join(output, "site.pfx"), "output-password", "orphan-vs-bundle.example.com")
}

// TestScannerRun_flatCollisionConvertsNeitherAndNamesBoth pins the fail-loud
// collision contract: two inputs claiming one flat output name is operator
// ambiguity this app refuses to arbitrate, whatever their arrival order. Neither
// converts, nothing is published at the contested name, and the ERROR record
// names every claimant with the remediation.
func TestScannerRun_flatCollisionConvertsNeitherAndNamesBoth(t *testing.T) {
	input := t.TempDir()
	output := t.TempDir()
	aCert, aKey := testcerts.GenerateSelfSignedCert(t, "issuer-a-copy.example.com", "ecdsa")
	bCert, bKey := testcerts.GenerateSelfSignedCert(t, "issuer-b-copy.example.com", "ecdsa")
	writePEMSource(t, filepath.Join(input, "issuer-a", "shared"), "site", aCert, aKey)
	writePEMSource(t, filepath.Join(input, "issuer-b", "shared"), "site", bCert, bKey)
	scanner := newFormatScanner(input, output, outputpolicy.Formats{PFX: true}, outputpolicy.LayoutFlat, "", outputpolicy.LifecycleWarn)
	logs := capture.Default(t)

	result, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("Run(flat collision) = %v", err)
	}
	if result.Converted != 0 || result.Collided != 2 || result.Failed != 0 {
		t.Fatalf("Run(flat collision) = %+v, want Converted 0 Collided 2 Failed 0", result)
	}
	assertOnlyRegularFiles(t, output, nil)
	if count := logs.CountLevel(slog.LevelError, collisionMsgPublished); count != 1 {
		t.Errorf("Run(flat collision) logged %q at ERROR %d times, want 1: %v", collisionMsgPublished, count, logs.Messages())
	}
}

// collisionMsgPublished is the exact production record; retyped here so a reword
// of the ERROR line fails this test instead of silently unpinning the published
// CertConverterOutputNameCollision alert.
const collisionMsgPublished = "output name collision: several inputs produce the same output path, so none of them is converted"

func TestScannerRun_syncRemovesEveryArtifactOfGoneSource(t *testing.T) {
	input := t.TempDir()
	output := t.TempDir()
	anchorCert, anchorKey := testcerts.GenerateSelfSignedCert(t, "anchor.example.com", "ecdsa")
	goneCert, goneKey := testcerts.GenerateSelfSignedCert(t, "gone.example.com", "ecdsa")
	writePEMSource(t, input, "anchor", anchorCert, anchorKey)
	writePEMSource(t, input, "gone", goneCert, goneKey)
	formats := outputpolicy.Formats{PFX: true, PEM: true}
	scanner := newFormatScanner(input, output, formats, outputpolicy.LayoutMirror, "", outputpolicy.LifecycleSync)

	first, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("initial Run(sync all formats) = %v", err)
	}
	if first.Converted != 2 {
		t.Fatalf("initial Run(sync all formats) = %+v, want Converted 2", first)
	}
	if err := os.Remove(filepath.Join(input, "gone.crt")); err != nil {
		t.Fatalf("remove gone.crt: %v", err)
	}
	if err := os.Remove(filepath.Join(input, "gone.key")); err != nil {
		t.Fatalf("remove gone.key: %v", err)
	}

	second, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("second Run(sync all formats) = %v", err)
	}
	if second.Removed != 3 {
		t.Errorf("second Run(sync all formats) Removed = %d, want 3 artifacts", second.Removed)
	}
	for _, name := range []string{"gone.pfx", "gone.crt", "gone.key"} {
		if _, err := os.Stat(filepath.Join(output, name)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("os.Stat(output/%s) = %v, want fs.ErrNotExist", name, err)
		}
	}
	for _, name := range []string{"anchor.pfx", "anchor.crt", "anchor.key"} {
		if _, err := os.Stat(filepath.Join(output, name)); err != nil {
			t.Errorf("os.Stat(output/%s) = %v, want retained anchor artifact", name, err)
		}
	}
}

func newFormatScanner(input, output string, formats outputpolicy.Formats, layoutMode outputpolicy.Layout, inputPassword string, lifecycle outputpolicy.Lifecycle) *process.Scanner {
	return process.New(&process.Options{
		CertsRoot:          input,
		OutRoot:            output,
		Password:           "output-password",
		InputPassword:      inputPassword,
		InputPasswordReady: inputPassword != "",
		Encoder:            convert.EncNameModern2023,
		Formats:            formats,
		FormatsExplicit:    true,
		Layout:             layoutMode,
		Lifecycle:          lifecycle,
	})
}

func writePEMSource(t *testing.T, dir, stem string, certPEM, keyPEM []byte) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("setup: mkdir %s: %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, stem+".crt"), certPEM, 0o644); err != nil {
		t.Fatalf("setup: write %s.crt: %v", stem, err)
	}
	if err := os.WriteFile(filepath.Join(dir, stem+".key"), keyPEM, 0o600); err != nil {
		t.Fatalf("setup: write %s.key: %v", stem, err)
	}
}

func writePFXSource(t *testing.T, dir, name string, certPEM, keyPEM []byte, password string, encoder convert.EncoderType) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("setup: mkdir %s: %v", dir, err)
	}
	analysis, err := convert.Analyse(t.Context(), certPEM, keyPEM)
	if err != nil {
		t.Fatalf("setup: Analyse PFX source: %v", err)
	}
	data, err := analysis.Encode(encoder, password)
	if err != nil {
		t.Fatalf("setup: Encode PFX source: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
		t.Fatalf("setup: write %s: %v", name, err)
	}
}

func assertPFXCommonName(t *testing.T, file, password, want string) {
	t.Helper()
	_, leaf, _, err := pkcs12.DecodeChain(readFile(t, file), password)
	if err != nil {
		t.Fatalf("DecodeChain(%s) = %v", file, err)
	}
	if leaf.Subject.CommonName != want {
		t.Errorf("DecodeChain(%s) CommonName = %q, want %q", file, leaf.Subject.CommonName, want)
	}
}

func assertPEMCommonName(t *testing.T, certFile, keyFile, want string) {
	t.Helper()
	certPEM := readFile(t, certFile)
	if _, err := convert.Analyse(t.Context(), certPEM, readFile(t, keyFile)); err != nil {
		t.Fatalf("Analyse(%s, %s) = %v", certFile, keyFile, err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatalf("pem.Decode(%s) returned no certificate block", certFile)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate(%s) = %v", certFile, err)
	}
	if got := cert.Subject.CommonName; got != want {
		t.Errorf("ParseCertificate(%s) CommonName = %q, want %q", certFile, got, want)
	}
}

func assertFileBytes(t *testing.T, file string, want []byte) {
	t.Helper()
	if got := readFile(t, file); !bytes.Equal(got, want) {
		t.Errorf("read %s = %d bytes that differ from the %d-byte source", file, len(got), len(want))
	}
}

func assertOnlyRegularFiles(t *testing.T, root string, want []string) {
	t.Helper()
	var got []string
	if err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root || d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		got = append(got, rel)
		return nil
	}); err != nil {
		t.Fatalf("walk output %s: %v", root, err)
	}
	if !slices.Equal(got, want) {
		t.Errorf("output files = %v, want %v", got, want)
	}
}

func readFile(t *testing.T, file string) []byte {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	return data
}

func TestScannerRun_orphanedPEMHalfDoesNotShadowBundle(t *testing.T) {
	t.Parallel()
	input := t.TempDir()
	output := t.TempDir()
	orphanCert, _ := testcerts.GenerateSelfSignedCert(t, "orphan.example.com", "ecdsa")
	bundleCert, bundleKey := testcerts.GenerateSelfSignedCert(t, "bundle-works.example.com", "ecdsa")
	if err := os.WriteFile(filepath.Join(input, "site.crt"), orphanCert, 0o644); err != nil {
		t.Fatalf("setup: write orphan certificate: %v", err)
	}
	writePFXSource(t, input, "site.pfx", bundleCert, bundleKey, "input-password", convert.EncNameModern2023)
	scanner := newFormatScanner(input, output, outputpolicy.Formats{PFX: true}, outputpolicy.LayoutMirror, "input-password", outputpolicy.LifecycleWarn)

	result, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("Run(orphan certificate plus bundle) = %v", err)
	}
	if result.Total != 2 || result.Orphan != 1 || result.Converted != 1 {
		t.Fatalf("Run(orphan certificate plus bundle) = %+v, want Total 2 Orphan 1 Converted 1", result)
	}
	assertPFXCommonName(t, filepath.Join(output, "site.pfx"), "output-password", "bundle-works.example.com")
}

func TestScannerRun_rewritesOnlyStalePEMArtifact(t *testing.T) {
	t.Parallel()
	input := t.TempDir()
	output := t.TempDir()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "one-stale-artifact.example.com", "ecdsa")
	writePEMSource(t, input, "site", certPEM, keyPEM)
	scanner := newFormatScanner(input, output, outputpolicy.Formats{PEM: true}, outputpolicy.LayoutMirror, "", outputpolicy.LifecycleWarn)

	if result, err := scanner.Run(t.Context()); err != nil || result.Converted != 1 {
		t.Fatalf("initial Run(PEM currency) = (%+v, %v), want Converted 1 and nil", result, err)
	}
	certPath := filepath.Join(output, "site.crt")
	keyPath := filepath.Join(output, "site.key")
	certBefore, err := os.Stat(certPath)
	if err != nil {
		t.Fatalf("stat current certificate output: %v", err)
	}
	staleKey := slices.Clone(keyPEM)
	staleKey[len(staleKey)/2] ^= 1
	if err := os.WriteFile(keyPath, staleKey, 0o600); err != nil {
		t.Fatalf("replace key output with same-length stale bytes: %v", err)
	}

	result, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("second Run(one stale PEM artifact) = %v", err)
	}
	if result.Converted != 1 || result.Failed != 0 {
		t.Fatalf("second Run(one stale PEM artifact) = %+v, want Converted 1 Failed 0", result)
	}
	certAfter, err := os.Stat(certPath)
	if err != nil {
		t.Fatalf("stat certificate output after repair: %v", err)
	}
	if !os.SameFile(certBefore, certAfter) {
		t.Error("current certificate artifact was replaced while repairing only the stale key")
	}
	assertFileBytes(t, keyPath, keyPEM)
}

func TestScannerRun_syncRemovesArtifactsOfGonePFXSource(t *testing.T) {
	input := t.TempDir()
	output := t.TempDir()
	anchorCert, anchorKey := testcerts.GenerateSelfSignedCert(t, "anchor-pfx.example.com", "ecdsa")
	goneCert, goneKey := testcerts.GenerateSelfSignedCert(t, "gone-pfx.example.com", "ecdsa")
	writePFXSource(t, input, "anchor.pfx", anchorCert, anchorKey, "input-password", convert.EncNameModern2023)
	writePFXSource(t, input, "gone.pfx", goneCert, goneKey, "input-password", convert.EncNameModern2023)
	formats := outputpolicy.Formats{PFX: true, PEM: true}
	scanner := newFormatScanner(input, output, formats, outputpolicy.LayoutMirror, "input-password", outputpolicy.LifecycleSync)

	if result, err := scanner.Run(t.Context()); err != nil || result.Converted != 2 {
		t.Fatalf("initial Run(PFX source lifecycle) = (%+v, %v), want Converted 2 and nil", result, err)
	}
	if err := os.Remove(filepath.Join(input, "gone.pfx")); err != nil {
		t.Fatalf("remove gone PFX source: %v", err)
	}
	result, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("second Run(PFX source lifecycle) = %v", err)
	}
	if result.Removed != 3 {
		t.Errorf("second Run(PFX source lifecycle) Removed = %d, want 3 artifacts", result.Removed)
	}
	for _, name := range []string{"gone.pfx", "gone.crt", "gone.key"} {
		if _, err := os.Stat(filepath.Join(output, name)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("os.Stat(output/%s) = %v, want fs.ErrNotExist", name, err)
		}
	}
}

func TestScannerRun_syncDoesNotReportCurrentPEMArtifactsAsOrphans(t *testing.T) {
	input := t.TempDir()
	output := t.TempDir()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "current-pem.example.com", "ecdsa")
	writePEMSource(t, input, "site", certPEM, keyPEM)
	logs := capture.Default(t)
	scanner := newFormatScanner(input, output, outputpolicy.Formats{PEM: true}, outputpolicy.LayoutMirror, "", outputpolicy.LifecycleSync)

	result, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("Run(current PEM artifacts under sync) = %v", err)
	}
	if result.Removed != 0 {
		t.Errorf("Run(current PEM artifacts under sync) Removed = %d, want 0", result.Removed)
	}
	if count := logs.CountLevel(slog.LevelInfo, "possible orphaned output artifacts"); count != 0 {
		t.Errorf("Run(current PEM artifacts under sync) logged %d possible-orphan records, want none (logs %v)", count, logs.Messages())
	}
}

func TestScannerRun_PFXSourceIsIgnoredUntilInputIsEnabled(t *testing.T) {
	input := t.TempDir()
	output := t.TempDir()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "empty-input-password.example.com", "ecdsa")
	writePFXSource(t, input, "site.pfx", certPEM, keyPEM, "", convert.EncNameModern2023)
	scanner := process.New(&process.Options{
		CertsRoot: input,
		OutRoot:   output,
		Password:  "output-password",
		// Bypass config intentionally: New must not let an internal caller enable
		// an empty input password.
		InputPasswordReady: true,
		Encoder:            convert.EncNameModern2023,
		Formats:            outputpolicy.Formats{PEM: true},
		FormatsExplicit:    true,
		Layout:             outputpolicy.LayoutMirror,
	})
	logs := capture.Default(t)

	result, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("Run(PFX source while PFX input is disabled) = %v", err)
	}
	if result.Total != 0 || result.Ignored != 1 || result.Failed != 0 || result.Converted != 0 {
		t.Errorf("Run(PFX source while PFX input is disabled) = %+v, want Ignored 1 and no conversion outcomes", result)
	}
	assertOnlyRegularFiles(t, output, nil)
	if count := logs.CountLevel(slog.LevelWarn, "no certificate sources found under the input root"); count != 0 {
		t.Errorf("disabled PFX input logged no-source warning %d times, want none: %v", count, logs.Messages())
	}
}

// TestScannerRun_flatSyncReapsArtifactOfGoneSource pins the flat layout's
// deletion path end to end: sync mode confirms over a fresh /input
// re-enumeration (not per-candidate path stats, which flat names cannot
// support) and then reaps the artifact whose source is gone, while the
// still-live source's artifact stays.
func TestScannerRun_flatSyncReapsArtifactOfGoneSource(t *testing.T) {
	input := t.TempDir()
	output := t.TempDir()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "flat-lifecycle.example.com", "ecdsa")
	sourceDir := filepath.Join(input, "issuer", "site")
	writePEMSource(t, sourceDir, "cert", certPEM, keyPEM)
	anchorCert, anchorKey := testcerts.GenerateSelfSignedCert(t, "flat-anchor.example.com", "ecdsa")
	writePEMSource(t, filepath.Join(input, "issuer", "anchor"), "cert", anchorCert, anchorKey)
	scanner := newFormatScanner(input, output, outputpolicy.Formats{PFX: true}, outputpolicy.LayoutFlat, "", outputpolicy.LifecycleSync)

	if result, err := scanner.Run(t.Context()); err != nil || result.Converted != 2 {
		t.Fatalf("initial Run(flat sync) = (%+v, %v), want Converted 2 and nil", result, err)
	}
	if err := os.Remove(filepath.Join(sourceDir, "cert.crt")); err != nil {
		t.Fatalf("remove flat source certificate: %v", err)
	}
	if err := os.Remove(filepath.Join(sourceDir, "cert.key")); err != nil {
		t.Fatalf("remove flat source key: %v", err)
	}
	result, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("second Run(flat sync) = %v", err)
	}
	if result.Removed != 1 {
		t.Errorf("second Run(flat sync) Removed = %d, want 1: the artifact's source is gone and the re-enumeration confirmed it", result.Removed)
	}
	if _, statErr := os.Stat(filepath.Join(output, "site", "cert.pfx")); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("os.Stat(output/site/cert.pfx) = %v, want the orphaned flat artifact removed", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(output, "anchor", "cert.pfx")); statErr != nil {
		t.Errorf("live source's flat artifact was deleted: %v", statErr)
	}
}

// TestScannerRun_flatSyncLoneKeyVetoesReap pins the half-deleted-pair veto in
// the flat namespace: a certificate that is gone while its private key is still
// under /input is a pair mid-change, not proof of an orphan, so the artifact is
// kept and the retention is reported.
func TestScannerRun_flatSyncLoneKeyVetoesReap(t *testing.T) {
	input := t.TempDir()
	output := t.TempDir()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "flat-lone-key.example.com", "ecdsa")
	sourceDir := filepath.Join(input, "issuer", "site")
	writePEMSource(t, sourceDir, "cert", certPEM, keyPEM)
	// A second live source keeps Total > 0 on the second scan: an input tree with
	// no source at all disables reaping outright (the empty-mount veto), which
	// would pass this test without ever reaching the lone-key veto it pins.
	anchorCert, anchorKey := testcerts.GenerateSelfSignedCert(t, "flat-lone-anchor.example.com", "ecdsa")
	writePEMSource(t, filepath.Join(input, "issuer", "anchor"), "cert", anchorCert, anchorKey)
	scanner := newFormatScanner(input, output, outputpolicy.Formats{PFX: true}, outputpolicy.LayoutFlat, "", outputpolicy.LifecycleSync)

	if result, err := scanner.Run(t.Context()); err != nil || result.Converted != 2 {
		t.Fatalf("initial Run(flat sync) = (%+v, %v), want Converted 2 and nil", result, err)
	}
	if err := os.Remove(filepath.Join(sourceDir, "cert.crt")); err != nil {
		t.Fatalf("remove flat source certificate: %v", err)
	}
	logs := capture.Default(t)

	result, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("second Run(flat sync, lone key) = %v", err)
	}
	if result.Removed != 0 {
		t.Errorf("second Run(flat sync, lone key) Removed = %d, want 0: the pair's key is still under /input", result.Removed)
	}
	if _, statErr := os.Stat(filepath.Join(output, "site", "cert.pfx")); statErr != nil {
		t.Errorf("artifact with a lone input key was deleted: %v", statErr)
	}
	const retained = "keeping an output artifact whose certificate is gone but whose private key is still in /input"
	if count := logs.CountLevel(slog.LevelWarn, retained); count != 1 {
		t.Errorf("second Run(flat sync, lone key) logged %q %d times, want 1: %v", retained, count, logs.Messages())
	}
}

func TestScannerRun_syncRemovesArtifactsFromDisabledFormat(t *testing.T) {
	input := t.TempDir()
	output := t.TempDir()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "format-switch.example.com", "ecdsa")
	writePEMSource(t, input, "site", certPEM, keyPEM)

	both := newFormatScanner(input, output, outputpolicy.Formats{PFX: true, PEM: true}, outputpolicy.LayoutMirror, "", outputpolicy.LifecycleSync)
	if result, err := both.Run(t.Context()); err != nil || result.Converted != 1 {
		t.Fatalf("Run(before format switch) = (%+v, %v), want Converted 1 and nil", result, err)
	}
	pfxOnly := newFormatScanner(input, output, outputpolicy.Formats{PFX: true}, outputpolicy.LayoutMirror, "", outputpolicy.LifecycleSync)
	result, err := pfxOnly.Run(t.Context())
	if err != nil {
		t.Fatalf("Run(after OUTPUT_FORMATS pfx switch) = %v", err)
	}
	if result.Removed != 2 || result.Unchanged != 1 {
		t.Errorf("Run(after OUTPUT_FORMATS pfx switch) = %+v, want Removed 2 Unchanged 1", result)
	}
	for _, name := range []string{"site.crt", "site.key"} {
		if _, err := os.Stat(filepath.Join(output, name)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("os.Stat(output/%s) = %v, want disabled PEM artifact removed", name, err)
		}
	}
	assertPFXCommonName(t, filepath.Join(output, "site.pfx"), "output-password", "format-switch.example.com")
}

func TestScannerRun_legacyUnsetFormatsDoNotDeletePEMFiles(t *testing.T) {
	input := t.TempDir()
	output := t.TempDir()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "legacy-default.example.com", "ecdsa")
	writePEMSource(t, input, "site", certPEM, keyPEM)
	for _, name := range []string{"operator.crt", "operator.key"} {
		if err := os.WriteFile(filepath.Join(output, name), []byte("operator-owned"), 0o600); err != nil {
			t.Fatalf("setup: write %s: %v", name, err)
		}
	}
	scanner := process.New(&process.Options{
		CertsRoot: input,
		OutRoot:   output,
		Password:  "output-password",
		Encoder:   convert.EncNameModern2023,
		Lifecycle: outputpolicy.LifecycleSync,
	})

	result, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("Run(legacy unset OUTPUT_FORMATS under sync) = %v", err)
	}
	if result.Removed != 0 || result.Converted != 1 {
		t.Errorf("Run(legacy unset OUTPUT_FORMATS under sync) = %+v, want Removed 0 Converted 1", result)
	}
	for _, name := range []string{"operator.crt", "operator.key"} {
		assertFileBytes(t, filepath.Join(output, name), []byte("operator-owned"))
	}
}

// TestScannerRun_flatLayoutConvertsEnumeratedPrefixAtBudgetStop pins flat's
// availability parity with mirror: a budget-stopped walk converts every source
// it enumerated (mirror converts them inline; flat converts its deferred batch),
// and only orphan reaping stays disabled for that scan.
func TestScannerRun_flatLayoutConvertsEnumeratedPrefixAtBudgetStop(t *testing.T) {
	t.Parallel()
	input := t.TempDir()
	output := t.TempDir()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "partial-flat.example.com", "ecdsa")
	writePEMSource(t, input, "a", certPEM, keyPEM)
	if err := os.WriteFile(filepath.Join(input, "z-filler"), []byte("x"), 0o600); err != nil {
		t.Fatalf("setup: write budget filler: %v", err)
	}
	scanner := process.New(&process.Options{
		CertsRoot:       input,
		OutRoot:         output,
		Password:        "output-password",
		Encoder:         convert.EncNameModern2023,
		Formats:         outputpolicy.Formats{PFX: true},
		FormatsExplicit: true,
		Layout:          outputpolicy.LayoutFlat,
		MaxScanEntries:  3, // root + a.crt + a.key; z-filler stops the walk
	})

	result, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("Run(flat budget stop) = %v, want reported budget stop rather than scan error", err)
	}
	if result.Converted != 1 || result.Total != 1 {
		t.Errorf("Run(flat budget stop) = %+v, want the one enumerated source converted", result)
	}
	assertOnlyRegularFiles(t, output, []string{"a.pfx"})
}

func TestScannerRun_rejectsAliasedInputAndOutputRoots(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "aliased-roots.example.com", "ecdsa")
	writePEMSource(t, root, "site", certPEM, keyPEM)
	certBefore := readFile(t, filepath.Join(root, "site.crt"))
	keyBefore := readFile(t, filepath.Join(root, "site.key"))
	scanner := newFormatScanner(root, root, outputpolicy.Formats{PFX: true}, outputpolicy.LayoutMirror, "", outputpolicy.LifecycleSync)

	result, err := scanner.Run(t.Context())
	if err == nil {
		t.Fatalf("Run(aliased input/output roots) = (%+v, nil), want refusal", result)
	}
	assertFileBytes(t, filepath.Join(root, "site.crt"), certBefore)
	assertFileBytes(t, filepath.Join(root, "site.key"), keyBefore)
	if _, statErr := os.Stat(filepath.Join(root, "site.pfx")); !errors.Is(statErr, fs.ErrNotExist) {
		t.Errorf("os.Stat(site.pfx) = %v, want no output written into the input root", statErr)
	}
}

func TestScannerRun_rejectsAncestorInputOutputRoots(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name             string
		outputBelowInput bool
	}{
		{name: "output below input", outputBelowInput: true},
		{name: "input below output"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			parent := t.TempDir()
			var input, output string
			if tc.outputBelowInput {
				input, output = parent, filepath.Join(parent, "output")
			} else {
				input, output = filepath.Join(parent, "input"), parent
			}
			if err := os.MkdirAll(input, 0o750); err != nil {
				t.Fatalf("setup: mkdir input: %v", err)
			}
			if err := os.MkdirAll(output, 0o750); err != nil {
				t.Fatalf("setup: mkdir output: %v", err)
			}
			certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "nested-roots.example.com", "ecdsa")
			writePEMSource(t, input, "site", certPEM, keyPEM)
			scanner := newFormatScanner(input, output, outputpolicy.Formats{PFX: true}, outputpolicy.LayoutMirror, "", outputpolicy.LifecycleSync)

			if result, err := scanner.Run(t.Context()); err == nil {
				t.Fatalf("Run(%s) = (%+v, nil), want overlapping-root refusal", tc.name, result)
			}
			assertFileBytes(t, filepath.Join(input, "site.crt"), certPEM)
			assertFileBytes(t, filepath.Join(input, "site.key"), keyPEM)
		})
	}
}

// TestScannerRun_flatLayoutConvertsVisibleSourcesPastUnresolvedSubtree pins the
// other half of that parity: an unresolvable symlink skips ITS subtree and
// blocks orphan reaping, while every visible source still converts.
func TestScannerRun_flatLayoutConvertsVisibleSourcesPastUnresolvedSubtree(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink confinement semantics differ on Windows")
	}
	input := t.TempDir()
	output := t.TempDir()
	certPEM, keyPEM := testcerts.GenerateSelfSignedCert(t, "visible-flat.example.com", "ecdsa")
	writePEMSource(t, input, "visible", certPEM, keyPEM)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "hidden.crt"), certPEM, 0o600); err != nil {
		t.Fatalf("setup: write hidden source: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(input, "hidden")); err != nil {
		t.Fatalf("setup: symlink unresolved subtree: %v", err)
	}
	scanner := newFormatScanner(input, output, outputpolicy.Formats{PFX: true}, outputpolicy.LayoutFlat, "", outputpolicy.LifecycleWarn)

	result, err := scanner.Run(t.Context())
	if err != nil {
		t.Fatalf("Run(flat unresolved subtree) = %v", err)
	}
	if result.Unresolved != 1 || result.Converted != 1 || result.Total != 1 {
		t.Errorf("Run(flat unresolved subtree) = %+v, want Unresolved 1 and the visible source converted", result)
	}
	assertOnlyRegularFiles(t, output, []string{"visible.pfx"})
}
