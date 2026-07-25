// Package process provides the certificate scanning and conversion orchestration.
package process

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cplieger/cert-converter/internal/convert"
)

// ScanResult carries per-pair outcome summary counts from a scan run.
type ScanResult struct {
	Total      int
	Converted  int
	Unchanged  int
	Orphan     int
	Failed     int
	Unreadable int
}

// Options carries the process-lifetime scan configuration the composition root
// chooses once at startup: the confined input and output roots, the password
// embedded in generated PFX files, and the PKCS#12 encoder profile. The encoder
// is carried as the app-owned convert.EncoderType name, not as a go-pkcs12
// value, so the vendor type stays confined to internal/convert. These values
// never vary between Run calls, so they are injected at construction rather
// than re-supplied per scan.
type Options struct {
	Encoder   convert.EncoderType
	CertsRoot string
	OutRoot   string
	Password  string
}

// Scanner walks a certificate directory, checks for changes via a hash cache,
// and dispatches conversion of cert/key pairs to PFX format.
//
// A Scanner is NOT safe for concurrent Run calls: they share the Scanner's own
// fingerprint cache. Each cache method is individually atomic, but the per-entry
// matches -> convert -> record sequence is not: overlapping scans could let one
// skip a pair as unchanged on the strength of a fingerprint the other recorded
// for a different set of bytes, and one scan's prune can drop the other's live
// fingerprints. Run every scan from a single goroutine, as main.go does (initial
// scan, then the watcher's synchronous onChange callback).
type Scanner struct {
	cache *hashCache
	opts  Options
}

// New constructs a Scanner with the given process-lifetime scan configuration
// and a fresh fingerprint cache.
func New(opts Options) *Scanner {
	return &Scanner{cache: newHashCache(), opts: opts}
}

// Run walks the configured certs root, converts changed .crt/.key pairs to PFX
// in the configured output root, and returns a ScanResult with outcome counts
// plus any walk-level error. Every
// /input read is confined to certsRoot through an *os.Root, so a symlink in the
// watched tree cannot redirect a read outside it, and every /output stat,
// directory creation and PFX write is confined to outRoot the same way, so a
// symlink planted there cannot redirect the private-key-bearing PFX outside the
// mounted volume. A certsRoot or outRoot that cannot be opened as a root is a
// hard error (the caller marks the container unhealthy).
func (s *Scanner) Run(ctx context.Context) (ScanResult, error) {
	certsRoot, outRoot := s.opts.CertsRoot, s.opts.OutRoot
	inHandle, err := os.OpenRoot(certsRoot)
	if err != nil {
		return ScanResult{}, fmt.Errorf("open input root %q: %w", certsRoot, err)
	}
	defer func() { _ = inHandle.Close() }()

	outHandle, err := os.OpenRoot(outRoot)
	if err != nil {
		return ScanResult{}, fmt.Errorf("open output root %q: %w", outRoot, err)
	}
	defer func() { _ = outHandle.Close() }()

	reapStaleTemps(ctx, outHandle)

	sw := &scanWalk{
		cache:     s.cache,
		inHandle:  inHandle,
		outHandle: outHandle,
		password:  s.opts.Password,
		enc:       s.opts.Encoder,
		seen:      make(map[string]struct{}),
	}
	// Enumerate the input tree THROUGH the root handle, exactly as the
	// /output stale-temp sweep does: every step is an openat-relative
	// syscall and every path handed downstream is root-relative, so no
	// ambient absolute path exists for a later read to reach for.
	walkErr := fs.WalkDir(inHandle.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		return sw.visit(ctx, rel, d, err)
	})

	// A non-nil walkErr means WalkDir aborted before visiting every entry
	// (e.g. the /input root briefly became unreadable on a network mount),
	// so `seen` is incomplete; pruning against a partial set drops live
	// fingerprints and forces a full, timestamp-churning reconversion on the
	// next clean cycle. Prune only after a complete walk -- a genuinely
	// removed pair is reaped on the next successful scan.
	// An unreadable sub-path leaves `seen` incomplete for the certs beneath
	// it in exactly the same way, so it gets the same treatment.
	if walkErr == nil && sw.unreadable == 0 {
		s.cache.prune(sw.seen)
	}

	result := countResults(sw.results, sw.unreadable)
	logScanOutcome(ctx, result, walkErr)
	return result, walkErr
}

// --- /output stale-temp sweep ---

// tempNamePrefix, tempNameSuffix and staleTempAge mirror atomicfile's temp
// naming (".atomicfile-<digits>.tmp") and the reap cutoff, so the sweep stays
// matched to the writes and can never delete a caller-owned file.
const (
	tempNamePrefix = ".atomicfile-"
	tempNameSuffix = ".tmp"
	staleTempAge   = time.Hour
)

// isStaleTempName reports whether name has exactly atomicfile's temp shape:
// ".atomicfile-" followed by one or more decimal digits and ".tmp".
func isStaleTempName(name string) bool {
	digits, ok := strings.CutPrefix(name, tempNamePrefix)
	if !ok {
		return false
	}
	digits, ok = strings.CutSuffix(digits, tempNameSuffix)
	if !ok || digits == "" {
		return false
	}
	for _, r := range digits {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// reapStaleTemp handles one candidate entry of the reapStaleTemps walk: it
// filters non-candidates, re-checks the entry through the root before unlinking
// (only a regular file older than cutoff is a reclaimable orphan, and Lstat
// never follows a symlink planted under the temp's name) and removes it. Every
// operation stays root-relative through outHandle, so the confinement invariant
// is identical to doing the work inline in the callback. It reports whether a
// file was reaped and whether a non-benign failure occurred — a candidate that
// could not be inspected counts too, matching atomicfile.CleanupStaleTemps,
// whose equivalent stat failure also feeds its aggregate warning (the caller
// aggregates both).
func reapStaleTemp(outHandle *os.Root, rel string, d fs.DirEntry, cutoff time.Time) (didRemove, didFail bool) {
	if d.IsDir() || !isStaleTempName(d.Name()) {
		return false, false
	}
	fi, err := outHandle.Lstat(rel)
	if err != nil {
		// One per-entry detail stays at Debug; the aggregate Warn in
		// reapStaleTemps carries the operator signal.
		slog.Debug("skipping unstattable temp during cleanup", "path", rel, "error", err)
		if errors.Is(err, fs.ErrNotExist) {
			// The candidate vanished between the readdir and the Lstat (a
			// co-mounting reaper, or the write it belonged to finishing its
			// rename). Benign, exactly as the unlink race below.
			return false, false
		}
		// A permission or IO error means a stale temp may be accumulating
		// unnoticed, so it must reach the aggregate Warn rather than being
		// visible only under LOG_LEVEL=debug.
		return false, true
	}
	if !fi.Mode().IsRegular() || fi.ModTime().After(cutoff) {
		return false, false
	}
	if err := outHandle.Remove(rel); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// The temp vanished between the Lstat and the unlink (a co-mounting
			// reaper, or the write it belonged to finishing its rename). Benign,
			// exactly as atomicfile's own CleanupStaleTemps treats it.
			return false, false
		}
		// One unlink failure is not actionable on its own; the aggregate Warn
		// in reapStaleTemps carries the operator signal, matching
		// atomicfile.CleanupStaleTemps' per-entry Debug policy.
		slog.Debug("stale temp remove failed", "path", rel, "error", err)
		return false, true
	}
	return true, false
}

// reapStaleTemps removes PFX temp files orphaned by an interrupted atomic write
// (a crash between temp-write and rename). It matches exactly the
// ".atomicfile-<digits>.tmp" shape atomicfile stages, so a caller-owned file in
// /output is never touched. The sweep covers the whole output tree, not just its
// top level: atomicfile stages its temp in the TARGET directory, so a nested
// cert (input/example.com/cert.crt) leaves its orphaned temp in the matching
// nested output directory.
//
// Every step — the walk, the stat and the unlink — is root-relative through
// outHandle, so a co-mounting writer that swaps an output subdirectory for a
// symlink mid-sweep cannot redirect the deletion outside the mounted volume.
// Reconstructed ambient paths are deliberately never handed to
// atomicfile.CleanupStaleTemps: that helper reopens the directory outside the
// root, which would reintroduce exactly that TOCTOU window.
//
// The sweep is cancellable: it walks the whole output tree before the input
// walk starts, so an already-cancelled or mid-shutdown scan must stop between
// entries instead of traversing (and unlinking across) a large tree while
// SIGTERM handling waits.
func reapStaleTemps(ctx context.Context, outHandle *os.Root) {
	tr := &tempReap{outHandle: outHandle, cutoff: time.Now().Add(-staleTempAge)}
	walkErr := fs.WalkDir(outHandle.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		return tr.visit(ctx, rel, d, err)
	})
	tr.logOutcome(walkErr)
}

// tempReap carries the confined output root, the staleness cutoff and the
// mutable accounting for one reapStaleTemps walk (files reaped, candidates that
// could not be inspected or unlinked, unreadable output sub-paths). Hoisting the
// WalkDir callback onto this struct keeps reapStaleTemps flat, mirroring
// scanWalk's role for the input walk.
type tempReap struct {
	outHandle  *os.Root
	cutoff     time.Time
	reaped     int
	failed     int
	unreadable int
}

// visit is the reapStaleTemps WalkDir callback. A cancelled context aborts the
// sweep between entries; a walk error at the root (".") aborts it too, while an
// error below the root is counted as an unreadable sub-path, logged and skipped
// (a sub-path the sweep cannot enter may be hiding orphaned temps, so it feeds
// the aggregate Warn rather than being visible only at Debug). Every surviving
// entry goes to reapStaleTemp, whose two outcomes are aggregated here.
func (tr *tempReap) visit(ctx context.Context, rel string, d fs.DirEntry, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		if rel == "." {
			return err
		}
		slog.Debug("skipping unreadable output path during temp cleanup", "path", rel, "error", err)
		tr.unreadable++
		return nil
	}
	removed, didFail := reapStaleTemp(tr.outHandle, rel, d, tr.cutoff)
	if removed {
		tr.reaped++
	}
	if didFail {
		tr.failed++
	}
	return nil
}

// logOutcome emits the end-of-sweep logs: the walk error (Debug for a shutdown
// cancellation, Warn otherwise), the reclaimed-orphan count, the count of temps
// that could not be inspected or removed, and the count of output sub-paths the
// sweep could not enter. The last two are steady-state permissions/UID
// misconfigurations that let stale atomic-write artifacts accumulate unnoticed,
// so they carry a remediation hint at the default log level.
func (tr *tempReap) logOutcome(walkErr error) {
	const remediation = "check /output ownership and permissions for the UID in user:"
	if walkErr != nil {
		if isShutdown(walkErr) {
			// Shutdown, not an operator-actionable cleanup failure; the input
			// walk's own context check reports the cancellation to the caller.
			slog.Debug("stale temp cleanup cancelled during shutdown", "dir", tr.outHandle.Name(), "error", walkErr)
		} else {
			slog.Warn("stale temp cleanup failed", "dir", tr.outHandle.Name(), "error", walkErr)
		}
	}
	if tr.reaped > 0 {
		// A reclaimed orphan is evidence of an earlier interrupted write (a
		// crash or a kill between temp-write and rename), so it belongs in the
		// default-level log rather than only under LOG_LEVEL=debug.
		slog.Info("reaped stale temp files", "dir", tr.outHandle.Name(), "count", tr.reaped)
	}
	if tr.failed > 0 {
		slog.Warn("some stale output temps could not be inspected or removed", "dir", tr.outHandle.Name(),
			"count", tr.failed, "remediation", remediation)
	}
	if tr.unreadable > 0 {
		slog.Warn("some output paths could not be inspected during stale temp cleanup",
			"dir", tr.outHandle.Name(), "count", tr.unreadable, "remediation", remediation)
	}
}

// --- Input walk ---

// scanWalk carries the read-only conversion parameters and the mutable
// accounting for one Scanner.Run tree walk: the per-pair results, the count of
// unreadable sub-paths, and the set of cert paths seen (for cache pruning).
// Hoisting the WalkDir callback onto this struct keeps Scanner.Run flat.
type scanWalk struct {
	cache      *hashCache
	inHandle   *os.Root
	outHandle  *os.Root
	seen       map[string]struct{}
	enc        convert.EncoderType
	password   string
	results    []conversionStatus
	unreadable int
}

// visit is the WalkDir callback. The context is checked before and after each
// entry: a walk error at the root ("."), or a cancelled context, aborts the
// walk; an error below the root marks one unreadable sub-path and continues.
// Every path is root-relative (the walk runs through the *os.Root). Directories
// and non-.crt files convert nothing; they are only inspected by
// noteUnwalkableSymlink, which reports a symlink the walk cannot follow. Every
// .crt entry is recorded as seen and dispatched to convertEntry.
func (sw *scanWalk) visit(ctx context.Context, rel string, d fs.DirEntry, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		if rel == "." {
			return err
		}
		slog.Warn("skipping unreadable path", "path", rel, "error", err)
		sw.unreadable++
		return nil
	}
	if d.IsDir() || !strings.HasSuffix(rel, ".crt") {
		sw.noteUnwalkableSymlink(rel, d)
		return nil
	}
	sw.seen[rel] = struct{}{}
	sw.results = append(sw.results, sw.convertEntry(ctx, rel))
	// A cancellation that landed *during* the conversion above already turned
	// that entry into statusFailed (the bounded read and the atomic write both
	// return ctx.Err()). Re-check here so the walk aborts and Run reports the
	// cancellation, instead of returning a "completed" scan whose failed count
	// is really a shutdown artifact.
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return nil
}

// noteUnwalkableSymlink reports a symlink under the input root that the walk
// cannot follow. fs.WalkDir never descends a symlinked directory, and a link
// the confined handle cannot resolve at all (a target outside the root, or an
// unreadable component of an in-root target) tells us nothing about what it
// points to, so every certificate beneath such a link is invisible to the
// scan: it is counted in nothing, no PFX is produced, and health stays green.
// An /input populated with symlinks to other certificate directories would
// otherwise fail silently. The .crt/.key pair names are excluded because
// convertEntry already classifies and logs those (an unreadable .crt fails the
// entry, a sibling .key that cannot be stat-ed is a warned orphan), so warning
// here as well would double-report one condition. A dangling link (ENOENT)
// hides nothing and stays silent.
func (sw *scanWalk) noteUnwalkableSymlink(rel string, d fs.DirEntry) {
	if d.Type()&fs.ModeSymlink == 0 || strings.HasSuffix(rel, ".crt") || strings.HasSuffix(rel, ".key") {
		return
	}
	fi, err := sw.inHandle.Stat(rel)
	switch {
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		// The error is the only evidence of the cause here (a target outside the
		// root, or an unreadable component inside it), so name the consequence and
		// let the error carry the cause. The target's type is unknown on this arm
		// (fi is unusable when err != nil), so the message covers a linked file as
		// well as a linked directory.
		slog.Warn("skipping symlink that could not be resolved through the input root; anything it points to, including certificates under a linked directory, is not scanned",
			"path", rel, "error", err,
			"remediation", "mount that certificate path into /input directly instead of linking to it, or fix the permissions on the link target")
	case err == nil && fi.IsDir():
		// The target is inside the root, so the walk reaches those
		// certificates through the real directory; nothing is missed.
		slog.Debug("skipping symlinked directory; its target is walked directly", "path", rel)
	}
}

// --- Logging policy ---

// logScanOutcome emits the end-of-scan summary. A completed walk logs at Info;
// a walk aborted by shutdown (context cancellation or deadline) logs at Debug;
// any other abort logs at Warn so an operator sees the partial scan and its
// error. The count attributes are identical in all three cases (the README's Loki
// alert matches on them), so they are built once.
func logScanOutcome(ctx context.Context, result ScanResult, walkErr error) {
	level, msg := slog.LevelInfo, "scan complete"
	if walkErr != nil {
		level, msg = slog.LevelWarn, "scan aborted before completion"
		if isShutdown(walkErr) {
			level, msg = slog.LevelDebug, "scan cancelled during shutdown"
		}
	}
	attrs := make([]any, 0, 14)
	if walkErr != nil {
		attrs = append(attrs, "error", walkErr)
	}
	attrs = append(attrs,
		"total", result.Total,
		"converted", result.Converted,
		"unchanged", result.Unchanged,
		"orphan", result.Orphan,
		"unreadable", result.Unreadable,
		"failed", result.Failed)
	slog.Log(ctx, level, msg, attrs...)
	if walkErr == nil && result.Total == 0 && result.Unreadable == 0 {
		// A completed scan that visited no .crt at all is indistinguishable from
		// a healthy steady state in the counts above (failed=0 keeps the marker
		// set, and the README's Loki rules match on failed/unreadable or on the
		// absence of "scan complete"), yet it is the signature of a wrong or
		// vanished /input mount: no PFX is produced and nothing fires. Name it.
		slog.Warn("no certificate pairs found under the input root; no PFX output is being produced",
			"remediation", "check that the /input mount points at the PEM certificate directory")
	}
}

// isShutdown reports whether err is the process shutting down (context
// cancellation or a deadline) rather than an operator-actionable failure. It is
// the single decision behind every Debug-instead-of-Warn/Error downgrade in
// this file, so the walk-level, sweep-level and per-entry logs cannot drift
// apart.
func isShutdown(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// logEntryFailure logs a per-entry failure. A failure caused by shutdown
// (context cancellation or deadline) logs at Debug -- it is not an operator
// actionable conversion error -- while every real failure logs at Error, the
// same split logScanOutcome applies to the walk-level error.
func logEntryFailure(logPath, msg string, err error) {
	if isShutdown(err) {
		slog.Debug(msg+" (shutdown)", "path", logPath, "error", err)
		return
	}
	slog.Error(msg, "path", logPath, "error", err)
}

// failEntry records one per-entry failure: it logs via logEntryFailure and
// returns the failed status for the caller to propagate. It carries no cache
// obligation: the cache's record method commits a fingerprint only after a successful
// conversion, so a failed entry leaves the previous (or absent) fingerprint in
// place and the next scan retries the pair.
func failEntry(logPath, msg string, err error) conversionStatus {
	logEntryFailure(logPath, msg, err)
	return statusFailed
}

// --- Per-entry conversion ---

// pairInputs carries the cert and key PEM bytes readPair read through the
// confined input root, so one return value covers both inputs of a pair.
type pairInputs struct {
	certPEM []byte
	keyPEM  []byte
}

// readPair resolves and reads the input side of one .crt entry: it classifies
// the sibling .key (a missing key is a health-neutral orphan; a non-ENOENT stat
// failure is the same outcome but warned, since it is a diagnosable
// misconfiguration rather than a genuine "no key") and then performs both
// bounded reads through inHandle, so every /input byte is read once from within
// the confined root.
//
// The returned conversionStatus is meaningful only when ok is false: it is the
// outcome convertEntry must propagate for that entry, with the failure already
// logged. On the ok path it is the zero value and the caller ignores it. Every
// status and log message is identical to what convertEntry emitted inline.
func (sw *scanWalk) readPair(ctx context.Context, rel, keyRel string) (pairInputs, conversionStatus, bool) {
	if _, statErr := sw.inHandle.Stat(keyRel); statErr != nil {
		if errors.Is(statErr, fs.ErrNotExist) {
			slog.Debug("skipping cert without matching key", "path", rel)
		} else {
			// A non-ENOENT stat failure (a sibling key that is a symlink the
			// *os.Root refuses because it escapes /input, or a permission/IO
			// error) is not a genuine "no key" orphan: surface it so the
			// misconfiguration is diagnosable instead of silently skipped at
			// debug. Still health-neutral (statusOrphan) and non-invalidating.
			slog.Warn("skipping cert: cannot stat sibling key", "path", rel, "error", statErr)
		}
		return pairInputs{}, statusOrphan, false
	}

	certPEM, err := convert.ReadBoundedFromRoot(ctx, sw.inHandle, rel, convert.MaxFileSize)
	if err != nil {
		return pairInputs{}, failEntry(rel, "failed to read certificate", err), false
	}
	keyPEM, err := convert.ReadBoundedFromRoot(ctx, sw.inHandle, keyRel, convert.MaxFileSize)
	if err != nil {
		return pairInputs{}, failEntry(rel, "failed to read private key", err), false
	}
	return pairInputs{certPEM: certPEM, keyPEM: keyPEM}, 0, true
}

// convertEntry resolves the outcome for one .crt entry under certsRoot. It
// reads the cert and its sibling .key exactly once through inHandle, fingerprints
// them, and either skips (input unchanged and the prior PFX still present),
// regenerates (input unchanged but the output went missing), or converts
// (input changed). Every output touch — the stat, the directory creation and
// the atomic write — is confined to outHandle, so a symlink planted under the
// output tree cannot redirect the private-key-bearing PFX outside it. The
// fingerprint is committed to the cache only after the write succeeds, so every
// failure path leaves the pair due for a retry without needing a rollback. All
// per-cert logs use the certsRoot-relative path for a stable, non-leaky
// identifier.
func (sw *scanWalk) convertEntry(ctx context.Context, rel string) conversionStatus {
	// One stem for every sibling name derived from this .crt entry.
	stem := strings.TrimSuffix(rel, ".crt")
	keyRel := stem + ".key"

	inputs, outcome, ok := sw.readPair(ctx, rel, keyRel)
	if !ok {
		return outcome
	}
	certPEM, keyPEM := inputs.certPEM, inputs.keyPEM

	pfxRel := stem + ".pfx"
	fingerprint := pairFingerprint(certPEM, keyPEM)

	if sw.outputIsCurrent(rel, pfxRel, fingerprint) {
		return statusUnchanged
	}

	if destDir := filepath.Dir(pfxRel); destDir != "." {
		if err := sw.outHandle.MkdirAll(destDir, 0o750); err != nil {
			// destDir is filepath.Dir(rel), and the *os.Root error names the
			// failing component, so the cert path carries the directory too.
			return failEntry(rel, "failed to create output directory", err)
		}
	}

	slog.Debug("converting cert pair", "path", rel)
	if err := convert.PairInRoot(ctx, certPEM, keyPEM, sw.outHandle, pfxRel, sw.password, sw.enc); err != nil {
		return failEntry(rel, "conversion failed", err)
	}
	// Commit the fingerprint at the success boundary: only now is it true that
	// the output under pfxRel was produced from these bytes.
	sw.cache.record(rel, fingerprint)

	slog.Info("wrote pfx", "path", pfxRel)
	return statusConverted
}

// outputIsCurrent reports whether the entry can be skipped as already
// converted: the cert+key fingerprint matches the one recorded for the last
// successful conversion AND the prior PFX is still present under outHandle as a
// regular file. The cache fingerprints inputs only, so a PFX deleted out of band
// would otherwise never be regenerated while the input stays unchanged (until a
// renewal or process restart), and a skip-only scan still counts as a healthy
// cycle, masking the missing file from monitoring; hence the output stat, which
// forces a reconvert when the prior output is gone or is no longer a usable PFX
// file.
//
// It is a pure query: neither the cache lookup nor the stat mutates state, so a
// false result carries no caller obligation — convertEntry may exit on any
// failure path between here and the write without the cache ever claiming the
// pair is current.
func (sw *scanWalk) outputIsCurrent(rel, pfxRel, fingerprint string) bool {
	if !sw.cache.matches(rel, fingerprint) {
		return false
	}
	// Lstat, not Stat: a symlink planted under the output name must not be
	// accepted as the prior PFX (it would let unrelated content satisfy the
	// cache-coherence gate), and only a regular file is a usable PFX. Anything
	// else -- a directory, a symlink, a device node -- means the output
	// contract is broken, so force a reconvert whose confined atomic write
	// either restores a regular PFX or fails the entry and reports unhealthy.
	fi, statErr := sw.outHandle.Lstat(pfxRel)
	if statErr == nil && fi.Mode().IsRegular() {
		slog.Debug("skipping unchanged cert pair", "path", rel)
		return true
	}
	switch {
	case statErr == nil:
		slog.Warn("unchanged input but output PFX is not a regular file; regenerating",
			"path", rel, "type", fi.Mode().Type().String())
	case errors.Is(statErr, fs.ErrNotExist):
		slog.Warn("unchanged input but output PFX missing; regenerating", "path", rel)
	default:
		slog.Warn("unchanged input but output PFX stat failed; regenerating", "path", rel, "error", statErr)
	}
	return false
}

// countResults derives summary counts from typed results.
func countResults(results []conversionStatus, unreadable int) ScanResult {
	var converted, unchanged, orphan, failed int
	for _, r := range results {
		switch r {
		case statusConverted:
			converted++
		case statusUnchanged:
			unchanged++
		case statusOrphan:
			orphan++
		case statusFailed:
			failed++
		}
	}
	return ScanResult{
		Total:      len(results),
		Converted:  converted,
		Unchanged:  unchanged,
		Orphan:     orphan,
		Failed:     failed,
		Unreadable: unreadable,
	}
}
