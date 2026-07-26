// Package process provides the certificate scanning and conversion orchestration.
package process

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/layout"
)

// ScanResult carries per-pair outcome summary counts from a scan run.
type ScanResult struct {
	// Removed counts outputs deleted because their input pair is gone. It is
	// reported for visibility only and never affects health: a reap is the
	// operator's configured intent, not a failure.
	Removed    int
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
	Lifecycle Lifecycle
	CertsRoot string
	OutRoot   string
	Password  string
}

// Scanner walks a certificate directory, decides which cert/key pairs are out of
// date by reading the bundle already on disk, and dispatches their conversion to
// PFX format.
//
// A Scanner holds no mutable state, but Run must still be called from a single
// goroutine: concurrent scans share the OUTPUT TREE, not a cache. Both would read
// the same prior bundle, both would decide it is stale, and both would rewrite it
// with fresh KDF salts (churning mtimes and re-replicating downstream), and one
// scan's orphan reap could race the other's write of the same path. main.go does
// this (initial scan, then the watcher's synchronous onChange callback).
type Scanner struct {
	opts Options
}

// New constructs a Scanner with the given process-lifetime scan configuration.
// The options are taken by pointer only because the struct is large enough that
// copying it is wasteful (gocritic hugeParam); New does not retain the pointer's
// identity, it copies the value into the Scanner.
func New(opts *Options) *Scanner {
	return &Scanner{opts: *opts}
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

	out := &store{root: outHandle}
	out.sweepStaleTemps(ctx)

	sw := &scanWalk{
		src:      &source{root: inHandle},
		out:      out,
		password: s.opts.Password,
		enc:      s.opts.Encoder,
		seen:     make(map[string]struct{}),
	}
	// Enumerate the input tree THROUGH the root handle, exactly as the
	// /output stale-temp sweep does: every step is an openat-relative
	// syscall and every path handed downstream is root-relative, so no
	// ambient absolute path exists for a later read to reach for.
	walkErr := fs.WalkDir(inHandle.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		return sw.visit(ctx, rel, d, err)
	})

	result := countResults(sw.results, sw.unreadable)
	removed, reconcileErr := out.reconcile(ctx, s.opts.Lifecycle, sw.seen, reapContext{
		scanTotal: result.Total,
		failed:    result.Failed,
		// result.Unreadable, not sw.unreadable: it also carries the per-entry
		// statusUnreadable count. A cert the scan could not read is absent from `seen`,
		// so its existing .pfx would read as an orphan and be deleted on the very scan
		// that failed to read its input.
		unreadable:    result.Unreadable,
		unresolved:    sw.unresolved,
		walkCompleted: walkErr == nil,
		shutdown:      walkErr != nil && IsShutdown(walkErr),
	})
	result.Removed = removed
	// A shutdown that arrives after the input walk completed cancels reconciliation
	// instead, and that scan is NOT complete: without folding the error in, the
	// caller would log "scan complete" and mark the container healthy on a scan that
	// stopped halfway through the output tree.
	if walkErr == nil {
		walkErr = reconcileErr
	}

	logScanOutcome(ctx, result, walkErr)
	return result, walkErr
}

// scanWalk carries the read-only conversion parameters and the mutable
// accounting for one Scanner.Run tree walk: the per-pair results, the count of
// unreadable sub-paths, and the set of cert paths seen (the input enumeration
// store.reconcile checks the output tree against).
// Hoisting the WalkDir callback onto this struct keeps Scanner.Run flat.
type scanWalk struct {
	src        *source
	out        *store
	seen       map[string]struct{}
	enc        convert.EncoderType
	password   string
	results    []conversionStatus
	unreadable int
	// unresolved counts input symlinks the confined root could not resolve. Each
	// one may hide certificates, so `seen` is NOT a complete enumeration of the
	// input tree afterwards. It is deliberately separate from `unreadable`, which
	// is a documented ScanResult field feeding the README's alert attributes:
	// conflating them would change an operator-visible signal to fix an internal
	// precondition.
	unresolved int
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
		// Debug, not Warn: this is the per-path half of a two-level contract shared
		// with the /output sweep. An unreadable sub-path is a steady-state
		// permissions/UID misconfiguration the app deliberately tolerates, and it
		// recurs on EVERY scan (each debounced fsnotify event and each fallback
		// tick) — so naming every one at the default level put N lines plus an
		// aggregate into the log forever for a condition the operator already knows
		// about. The aggregate Warn in scanAndSetHealth carries the signal and the
		// remediation hint; LOG_LEVEL=debug names the individual paths.
		slog.Debug("skipping unreadable path", "path", rel, "error", err)
		sw.unreadable++
		return nil
	}
	if d.IsDir() || !layout.IsCert(rel) {
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
	if d.Type()&fs.ModeSymlink == 0 || layout.IsRelevant(rel) {
		return
	}
	fi, err := sw.src.stat(rel)
	switch {
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		// The error is the only evidence of the cause here (a target outside the
		// root, or an unreadable component inside it), so name the consequence and
		// let the error carry the cause. The target's type is unknown on this arm
		// (fi is unusable when err != nil), so the message covers a linked file as
		// well as a linked directory.
		// The walk KNOWS it is blind here, which is exactly the state that must
		// block orphan reaping: a certificate behind this link still exists but
		// will not appear in `seen`.
		sw.unresolved++
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
		if IsShutdown(walkErr) {
			level, msg = slog.LevelDebug, "scan cancelled during shutdown"
		}
	}
	attrs := make([]any, 0, 16)
	if walkErr != nil {
		attrs = append(attrs, "error", walkErr)
	}
	attrs = append(attrs,
		"total", result.Total,
		"converted", result.Converted,
		"unchanged", result.Unchanged,
		"orphan", result.Orphan,
		"unreadable", result.Unreadable,
		"removed", result.Removed,
		"failed", result.Failed)
	slog.Log(ctx, level, msg, attrs...)
	logInputCoverageWarnings(result, walkErr)
}

// logInputCoverageWarnings names the two health-neutral outcomes that produce no
// PFX at all and that the summary counts alone cannot distinguish from a healthy
// steady state. Both require a completed walk with no unreadable sub-path:
// Unreadable == 0 is what makes "every certificate" provable, because Run
// deliberately continues past an unreadable sub-path, so a partial enumeration
// cannot know what lies beneath it, and the unreadable-path WARN already carries
// the actionable diagnosis for that shape.
func logInputCoverageWarnings(result ScanResult, walkErr error) {
	if walkErr != nil || result.Unreadable > 0 {
		return
	}
	switch {
	case result.Total == 0:
		// A completed scan that visited no .crt at all is indistinguishable from
		// a healthy steady state in the summary counts (failed=0 keeps the marker
		// set, and the README's Loki rules match on failed/unreadable or on the
		// absence of "scan complete"), yet it is the signature of a wrong or
		// vanished /input mount: no PFX is produced and nothing fires. Name it.
		slog.Warn("no certificate pairs found under the input root; no PFX output is being produced",
			"remediation", "check that the /input mount points at the PEM certificate directory")
	case result.Orphan == result.Total:
		// Every .crt under /input lacks its sibling .key, so the scan
		// completed with failed=0 and produced nothing at all. The summary counts
		// carry orphan, but no README Loki rule keys on it and the
		// per-cert reason is Debug-only, so this steady-state naming
		// misconfiguration (a key extension that is not .key) is silent at
		// the default level, exactly like the Total==0 case above. Name it.
		slog.Warn("every certificate under the input root is missing its sibling .key; no PFX output is being produced",
			"orphan", result.Orphan,
			"remediation", "name each private key <name>.key beside its <name>.crt (Caddy's layout)")
	}
}

// IsShutdown reports whether err is the process shutting down (context
// cancellation or a deadline) rather than an operator-actionable failure. It is
// the single decision behind every Debug-instead-of-Warn/Error downgrade in
// this package AND behind the composition root's choice to leave the health
// marker untouched on a shutdown, so the walk-level, sweep-level, per-entry and
// health-marker decisions cannot drift apart. Exported for the composition
// root; Run returns the walk error unwrapped, so main classifies the same value
// this package does.
func IsShutdown(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// logEntryFailure logs a per-entry failure. A failure caused by shutdown
// (context cancellation or deadline) logs at Debug -- it is not an operator
// actionable conversion error -- while every real failure logs at Error, the
// same split logScanOutcome applies to the walk-level error.
// Callers may pass extra slog key/value pairs (a remediation hint, the output
// path) for failures whose cause is not evident from the input path alone.
func logEntryFailure(logPath, msg string, err error, extra ...any) {
	attrs := append([]any{"path", logPath, "error", err}, extra...)
	if IsShutdown(err) {
		slog.Debug(msg+" (shutdown)", attrs...)
		return
	}
	slog.Error(msg, attrs...)
}

// failEntry records one per-entry failure: it logs via logEntryFailure and
// returns the failed status for the caller to propagate. It carries no rollback
// obligation: currency is derived from the output file itself, so a failed entry
// leaves the previous bundle (or nothing) at the output path and the next scan
// reaches the same verdict and retries the pair.
func failEntry(logPath, msg string, err error, extra ...any) conversionStatus {
	logEntryFailure(logPath, msg, err, extra...)
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
// the sibling .key (a missing key is a health-neutral statusOrphan; a non-ENOENT
// stat failure is statusUnreadable instead, because the key is there and cannot
// be read — health-neutral too, but it also blocks orphan reaping, which an
// orphan does not) and then performs both bounded reads through the input
// source, so every /input byte is read once from within the confined root.
//
// The returned conversionStatus is meaningful only when ok is false: it is the
// outcome convertEntry must propagate for that entry, with the failure already
// logged. On the ok path it is statusUnset, which is not an outcome, so a status
// propagated from a successful read can never be mistaken for a conversion.
func (sw *scanWalk) readPair(ctx context.Context, rel, keyRel string) (pairInputs, conversionStatus, bool) {
	if _, statErr := sw.src.stat(keyRel); statErr != nil {
		if errors.Is(statErr, fs.ErrNotExist) {
			// A genuine orphan: the certificate has no sibling key at all.
			slog.Debug("skipping cert without matching key", "path", rel)
			return pairInputs{}, statusOrphan, false
		}
		// A non-ENOENT stat failure (a sibling key that is a symlink the *os.Root
		// refuses because it escapes /input, or a permission/IO error) is NOT a
		// genuine "no key" orphan — the key is there and cannot be read. Reporting it
		// as an orphan misdescribed it in the scan summary and in the all-orphan
		// diagnostic, so it is statusUnreadable, the same outcome the two bounded
		// reads below produce for the same class of condition. Health-neutral either
		// way; the message is unchanged because an alert rule keys on it.
		slog.Warn("skipping cert: cannot stat sibling key", "path", rel, "error", statErr)
		return pairInputs{}, statusUnreadable, false
	}

	certPEM, err := sw.src.readBounded(ctx, rel)
	if err != nil {
		noteUnreadableInput(rel, "certificate", err)
		return pairInputs{}, statusUnreadable, false
	}
	keyPEM, err := sw.src.readBounded(ctx, keyRel)
	if err != nil {
		noteUnreadableInput(rel, "private key", err)
		return pairInputs{}, statusUnreadable, false
	}
	return pairInputs{certPEM: certPEM, keyPEM: keyPEM}, statusUnset, true
}

// noteUnreadableInput logs a failed read of an /input file the same way readPair's
// sibling-key stat does: Debug when the file simply vanished, Warn otherwise. The
// caller returns the health-neutral statusUnreadable, kept at the call site so the
// outcome is visible where the branch is taken.
//
// Every reason a read fails here is a steady-state condition a restart cannot clear
// (deferred finding h-f9). A confinement refusal in particular cannot be identified by
// sentinel — os.Root reports "path escapes from parent", which matches none of
// fs.ErrPermission, fs.ErrNotExist, fs.ErrInvalid, syscall.ELOOP or syscall.EXDEV — so
// classifying per-error would mean matching on Go's error text. Treating every
// non-ENOENT read failure alike avoids that entirely and makes the two reads of a pair
// agree, which was the actual defect: the sibling key's stat failure was already
// health-neutral while the cert's read failure flipped the container unhealthy.
//
// ENOENT is a benign race — the entry existed at readdir and was gone by the read (a
// renewal replacing a file, an atomic-write temp) — so it stays at Debug.
//
// The pair is still not converted, so the outcome feeds ScanResult.Unreadable, which
// blocks orphan reaping: an input tree the scan could not fully read cannot prove an
// output is orphaned.
func noteUnreadableInput(rel, what string, err error) {
	if errors.Is(err, fs.ErrNotExist) {
		slog.Debug("skipping cert: "+what+" vanished during the scan", "path", rel, "error", err)
		return
	}
	slog.Warn("skipping cert: cannot read "+what,
		"path", rel, "error", err,
		"remediation", "check /input permissions and that the path is a regular file inside the mount, not a symlink out of it")
}

// convertEntry resolves the outcome for one .crt entry under certsRoot. It
// reads the cert and its sibling .key exactly once through the input source,
// analyses the pair, and either skips it (the bundle on disk is already the one
// these inputs produce) or converts and writes it (it is not, whether because the
// inputs changed, the output went missing or was replaced, or the encoder profile
// or password changed). Every output touch — the prior-bundle read, the directory
// creation and the atomic write — is confined to the store's root, so a symlink
// planted under the output tree cannot redirect the private-key-bearing PFX
// outside it. Nothing is recorded anywhere on success, so every failure path
// leaves the pair due for a retry without needing a rollback. All per-cert logs
// use the certsRoot-relative path for a stable, non-leaky identifier.
func (sw *scanWalk) convertEntry(ctx context.Context, rel string) conversionStatus {
	// Both sibling names come from layout, so this package and internal/watch
	// derive the pairing rule from one place instead of two copies that can drift.
	keyRel := layout.KeyFor(rel)

	inputs, outcome, ok := sw.readPair(ctx, rel, keyRel)
	if !ok {
		return outcome
	}
	certPEM, keyPEM := inputs.certPEM, inputs.keyPEM

	pfxRel := layout.OutputFor(rel)

	// Resolve the pair BEFORE consulting the output: currency is now "is the file
	// on disk the bundle these inputs produce?", which cannot be asked until the
	// bundle those inputs produce is known. Observations describe the INPUT, so
	// they are logged either way — a reordered bundle or a multi-key file is the
	// same operator-visible fact whether or not a write follows.
	analysis, err := convert.Analyse(certPEM, keyPEM)
	if err != nil {
		return failEntry(rel, "conversion failed", err)
	}
	current, err := sw.out.isCurrent(ctx, pfxRel, &analysis, sw.enc, sw.password)
	if err != nil {
		// Only shutdown gets here: isCurrent resolves every unreadable-output case to
		// "stale" itself and reserves an error for cancellation, which is neither
		// current nor stale. failEntry logs it at Debug, and visit's post-conversion
		// context check turns it into the walk-level cancellation the caller reports,
		// so this entry's statusFailed never reaches the health marker.
		return failEntry(rel, "failed to inspect existing pfx", err)
	}
	if current {
		// Observations are deliberately NOT logged here. Analyse now runs before the
		// currency check (it has to: currency is "is the file on disk the bundle
		// these inputs produce?"), so logging them unconditionally would re-emit a
		// WARN for every unchanged pair on every fsnotify event and every fallback
		// tick — turning a one-off notice into permanent log noise.
		slog.Debug("skipping unchanged cert pair", "path", rel)
		return statusUnchanged
	}

	logConversionObservations(rel, analysis.Observations)
	slog.Debug("converting cert pair", "path", rel)
	pfxData, err := convert.Encode(&analysis, sw.enc, sw.password)
	if err != nil {
		return failEntry(rel, "conversion failed", err)
	}
	if err := sw.out.write(ctx, pfxRel, pfxData); err != nil {
		// The message is unchanged (an operator's log query keys on it); the
		// remediation names the two steady-state output-side causes.
		return failEntry(rel, "conversion failed", err, "output_path", pfxRel,
			"remediation", "check /output ownership and permissions for the UID in user:, "+
				"and that no symlink is planted at the output path")
	}

	slog.Info("wrote pfx", "path", pfxRel)
	return statusConverted
}

// logConversionObservations surfaces Analyse's non-fatal findings about a pair's
// input. Every one of them is a CONVERTIBLE condition, so none flips health:
// health tracks conversion failures, and these all converted. They are logged at
// WARN because each names something the operator probably did not intend, except
// the duplicate-block artefact, which is noise at that level.
//
// Observations are emitted only on the conversion path, which is what keeps them
// from becoming noise: a pair skipped as unchanged returns before this is called,
// so an odd-but-convertible input is reported when it is converted rather than on
// every scan for the life of the deployment. A pair that keeps FAILING re-emits per
// attempt, matching how the failure itself is logged.
// Detail is already bounded by convert, so it needs no further truncation here.
func logConversionObservations(rel string, observations []convert.Observation) {
	for _, o := range observations {
		if o.Kind == convert.ObsDuplicateCerts {
			slog.Debug("cert input observation", "path", rel, "kind", string(o.Kind), "detail", o.Detail)
			continue
		}
		slog.Warn("cert input observation", "path", rel, "kind", string(o.Kind), "detail", o.Detail)
	}
}

// countResults derives summary counts from typed results.
//
// walkUnreadable (sub-paths the walk could not enter) and per-entry statusUnreadable
// (a cert or key the scan could not read) are folded into one Unreadable count on
// purpose: both mean "an /input path this app could not read", both carry the same
// operator remediation, both are health-neutral, and both must block orphan reaping.
func countResults(results []conversionStatus, walkUnreadable int) ScanResult {
	var converted, unchanged, orphan, failed, unreadable int
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
		case statusUnreadable:
			unreadable++
		}
	}
	return ScanResult{
		Total:      len(results),
		Converted:  converted,
		Unchanged:  unchanged,
		Orphan:     orphan,
		Failed:     failed,
		Unreadable: walkUnreadable + unreadable,
	}
}
