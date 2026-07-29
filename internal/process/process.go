// Package process provides the certificate scanning and conversion orchestration.
package process

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"

	"github.com/cplieger/cert-converter/internal/convert"
	"github.com/cplieger/cert-converter/internal/layout"
	"github.com/cplieger/cert-converter/internal/outputpolicy"
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
	// Unresolved counts input symlinks the confined root could not resolve.
	// Deliberately a SEPARATE field, never folded into Unreadable: the
	// README's Loki rules match on the `unreadable=` log attribute, and
	// conflating the two would change that operator-visible signal. Kept on
	// ScanResult so both coverage dimensions have one accumulator.
	Unresolved int
	// Vanished counts /input files this scan saw evidence of and then could not find:
	// a cert or key that existed at readdir and was gone by the bounded read, and a
	// sibling .key that a previous scan of this process read whole and that is gone by
	// this scan's stat (noteMissingKey). Both are the ordinary renewal race, one
	// observed a moment later than the other. Deliberately a SEPARATE field, never
	// folded into Unreadable, for the same reason as Unresolved: the README's Loki
	// rules match on the `unreadable=` attribute and carry a permissions
	// remediation, which is the wrong diagnosis for a transient replacement that the
	// next scan converts. It is health-neutral, and like Unreadable it still blocks
	// orphan reaping.
	Vanished int
	// Unwritable counts prior bundles whose mode repair AND repairing rewrite were both
	// refused for a permission reason (statusUnwritable). Health-neutral for the same
	// reason Unreadable is — no restart grants the UID a permission it does not have —
	// and a SEPARATE field for the same reason as the two above: `unreadable=` carries
	// an /input remediation and drives the documented alert, while this condition is
	// entirely on the /output side. It blocks orphan reaping like every other outcome
	// that left a bundle this app is not satisfied with (conversionsClean).
	Unwritable int
}

// summaryAttrs is the ONE list of the scan-summary attributes, in the order
// logScanOutcome emits them; the README's alerting section keys Loki rules on these
// names, so both the names and the order are the operator-visible contract. It sits
// beside ScanResult because it IS the reporting half of that struct: a counter added
// above without a row here never reaches the only operator-visible summary, and the
// omission is not a compile error.
//
// Field order is pointer-region packing (govet fieldalignment), not narrative order:
// the func pointer leads so the string's pointer+len sit behind it. Each row is
// written keyed so the operator-visible name still reads first.
var summaryAttrs = []struct {
	of   func(*ScanResult) int
	name string
}{
	{name: "total", of: func(r *ScanResult) int { return r.Total }},
	{name: "converted", of: func(r *ScanResult) int { return r.Converted }},
	{name: "unchanged", of: func(r *ScanResult) int { return r.Unchanged }},
	{name: "orphan", of: func(r *ScanResult) int { return r.Orphan }},
	{name: "unreadable", of: func(r *ScanResult) int { return r.Unreadable }},
	{name: "unresolved", of: func(r *ScanResult) int { return r.Unresolved }},
	{name: "vanished", of: func(r *ScanResult) int { return r.Vanished }},
	{name: "unwritable", of: func(r *ScanResult) int { return r.Unwritable }},
	{name: "removed", of: func(r *ScanResult) int { return r.Removed }},
	{name: "failed", of: func(r *ScanResult) int { return r.Failed }},
}

// conversionsClean reports whether nothing this scan did leaves the output tree in a
// state this app is still trying to repair. It is the ONE spelling of the reap veto
// that is about the OUTPUT rather than the input enumeration: Failed is the obvious
// member, and Unwritable joins it because a bundle whose permission repair the volume
// refused is one this app wanted to replace and could not — deleting other bundles on
// the strength of that same volume is exactly what the Failed veto refuses. Health
// deliberately does NOT ask this question; it asks Failed alone
// (main.healthyAfterScan), because a restart can clear one and never the other.
// Pointer receiver like its two siblings below: ScanResult reached gocritic's
// hugeParam threshold when Unwritable was added, and a read-only predicate is the
// wrong place to copy 80 bytes.
func (r *ScanResult) conversionsClean() bool {
	return r.Failed == 0 && r.Unwritable == 0
}

// durablyEnumerated reports whether every DURABLE veto on the input enumeration is
// clear: nothing under /input was unreadable and no symlink was unresolvable. It is
// the ONE spelling of that veto set, kept on the type that owns the counters, so a
// new durable coverage dimension cannot be added to one asker and missed in another.
// Vanished is deliberately excluded: it is the transient renewal race, and the two
// predicates that differ only in their Vanished term compose this one.
func (r *ScanResult) durablyEnumerated() bool {
	return r.Unreadable == 0 && r.Unresolved == 0
}

// inputFullyEnumerated reports whether nothing prevented this scan from observing
// every /input path: no unreadable path, no unresolved symlink, nothing that vanished
// mid-walk. It is the ONE spelling of that veto set — reapContext.enumerationClean
// and logInputCoverageWarnings both ask this question, so a new coverage dimension
// cannot be added to one of them and missed in the other.
func (r *ScanResult) inputFullyEnumerated() bool {
	return r.durablyEnumerated() && r.Vanished == 0
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
	Lifecycle outputpolicy.Lifecycle
	CertsRoot string
	OutRoot   string
	Password  string
}

// Scanner walks a certificate directory, decides which cert/key pairs are out of
// date by reading the bundle already on disk, and dispatches their conversion to
// PFX format.
//
// A Scanner's input-observation cache and output tree require Run to be called from a
// single goroutine. The cache is a plain map, so two concurrent scans is a fatal
// "concurrent map writes" throw, not merely wasted work; and on the output tree they
// would both read the same prior bundle, both would decide it is stale, and both
// would rewrite it with fresh KDF salts (churning mtimes and re-replicating
// downstream), and one scan's orphan reap could race the other's write of the same
// path. main.go does this (initial scan, then the watcher's synchronous onChange
// callback).
type Scanner struct {
	observations *observationLog
	opts         Options
}

// New constructs a Scanner with the given process-lifetime scan configuration.
// The options are taken by pointer only because the struct is large enough that
// copying it is wasteful (gocritic hugeParam); New does not retain the pointer's
// identity, it copies the value into the Scanner.
func New(opts *Options) *Scanner {
	return &Scanner{
		opts:         *opts,
		observations: newObservationLog(),
	}
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
		return ScanResult{}, failScan(ctx, fmt.Errorf("open input root %q: %w", certsRoot, err))
	}
	defer func() { _ = inHandle.Close() }()

	outHandle, err := os.OpenRoot(outRoot)
	if err != nil {
		return ScanResult{}, failScan(ctx, fmt.Errorf("open output root %q: %w", outRoot, err))
	}
	defer func() { _ = outHandle.Close() }()

	out := &store{root: outHandle}
	out.sweepStaleTemps(ctx)

	sw := &scanWalk{
		src:          &source{root: inHandle},
		out:          out,
		observations: s.observations,
		password:     s.opts.Password,
		enc:          s.opts.Encoder,
		seen:         make(map[string]struct{}),
	}
	// Enumerate the input tree THROUGH the root handle, exactly as the
	// /output stale-temp sweep does: every step is an openat-relative
	// syscall and every path handed downstream is root-relative, so no
	// ambient absolute path exists for a later read to reach for.
	walkErr := fs.WalkDir(inHandle.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		return sw.visit(ctx, rel, d, err)
	})

	result := countResults(sw.results, sw.unreadable, sw.unresolved, sw.vanished)
	rc := reapContext{
		// The scan's counts are carried whole rather than copied field-by-field:
		// result.Unreadable (not sw.unreadable) is what the veto needs, because it also
		// carries the per-entry statusUnreadable count. That term is about the TREE, not
		// about the unreadable pair's own bundle — visit records every .crt in `seen`
		// before dispatching it, so a cert whose read failed still matches its .pfx and
		// is never an orphan candidate. What it vetoes is the claim behind every reap: a
		// scan that could not READ part of /input has not enumerated the tree completely
		// in the README's sense ("no unreadable path"), so no output under it can be
		// proven orphaned. A cert that vanished mid-walk leaves the same hole in `seen`,
		// so it vetoes reaping too — but transiently: the next scan sees the replacement
		// and reconciles then.
		result:        result,
		walkCompleted: walkErr == nil,
		shutdown:      walkErr != nil && IsShutdown(walkErr),
	}
	// Prune observation state for pairs that are gone, but ONLY when the walk
	// proved the enumeration complete: an aborted walk, an unreadable sub-path or
	// an unresolved symlink means `seen` is not the whole input tree, so a pair
	// hidden behind it would be forgotten and re-warn on the next clean scan.
	// result.Total is deliberately NOT part of this gate (unlike enumeratedInput): a
	// clean walk that found nothing proves every remembered pair is gone.
	if rc.enumerationClean() {
		s.observations.forget(sw.seen)
	}
	rp := &reaper{src: sw.src, out: out, mode: s.opts.Lifecycle}
	removed, reconcileErr := rp.reconcile(ctx, sw.seen, &rc)
	result.Removed = removed
	// A shutdown that arrives after the input walk completed cancels reconciliation
	// instead, and that scan is NOT complete: without folding the error in, the
	// caller would log "scan complete" and mark the container healthy on a scan that
	// stopped halfway through the output tree.
	if walkErr == nil {
		walkErr = reconcileErr
	}

	logScanOutcome(ctx, &result, walkErr)
	return result, walkErr
}

// scanWalk carries the read-only conversion parameters and the mutable
// accounting for one Scanner.Run tree walk: the per-pair results, the count of
// unreadable sub-paths, and the set of cert paths seen (the input enumeration
// reaper.reconcile checks the output tree against). The one exception is
// observations, which is process-lifetime state owned by the Scanner and shared
// with the walk, not per-run accounting: it survives across scans by design.
// Hoisting the WalkDir callback onto this struct keeps Scanner.Run flat.
type scanWalk struct {
	src          *source
	out          *store
	seen         map[string]struct{}
	observations *observationLog
	enc          convert.EncoderType
	password     string
	results      []conversionStatus
	unreadable   int
	// vanished counts paths the walk enumerated and then could not find: the
	// directory half of the renewal race whose file half readPair classifies as
	// statusVanished. countResults folds it into ScanResult.Vanished.
	vanished int
	// unresolved counts input symlinks the confined root could not resolve. Each
	// one may hide certificates, so `seen` is NOT a complete enumeration of the
	// input tree afterwards. countResults folds it into ScanResult.Unresolved.
	unresolved int
}

// visit is the WalkDir callback. The context is checked before and after each
// entry: a walk error at the root ("."), or a cancelled context, aborts the
// walk; an error below the root marks one unreadable sub-path and continues.
// Every path is root-relative (the walk runs through the *os.Root). Directories
// and non-.crt files convert nothing; a directory whose name is a certificate
// path is counted as one unreadable sub-path, and any other non-.crt entry is
// only inspected by noteUnwalkableSymlink, which reports a symlink the walk
// cannot follow. Every .crt entry is recorded as seen and dispatched to
// convertEntry.
func (sw *scanWalk) visit(ctx context.Context, rel string, d fs.DirEntry, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		if rel == "." {
			return err
		}
		// An ENOENT below the root is the WALK's half of the renewal race the read
		// side already classifies as statusVanished. fs.WalkDir only ReadDirs real
		// directories -- it never descends a symlink -- so the only way a path it
		// just enumerated answers ENOENT is that it was removed under the walk;
		// there is no surviving-symlink reading to rule out here, which is why this
		// arm needs no src.pathVanished second observation. Counting it as
		// unreadable raised the documented `unreadable=` alert, whose remediation
		// points at /input permissions, for a directory that is merely being
		// replaced. Health-neutral and reap-vetoing either way.
		if errors.Is(err, fs.ErrNotExist) {
			slog.Debug("skipping path that vanished during the scan", "path", rel, "error", err)
			sw.vanished++
			return nil
		}
		// Debug, not Warn: this is the per-path half of a two-level contract shared
		// with the /output sweep. An unreadable sub-path is a steady-state
		// permissions/UID misconfiguration the app deliberately tolerates, and it
		// recurs on EVERY scan (each debounced fsnotify event and each fallback
		// tick) — so naming every one at the default level put N lines plus an
		// aggregate into the log forever for a condition the operator already knows
		// about. The aggregate Warn in logInputCoverageWarnings carries the signal and
		// the remediation hint; LOG_LEVEL=debug names the individual paths.
		slog.Debug("skipping unreadable path", "path", rel, "error", err)
		sw.unreadable++
		return nil
	}
	if d.IsDir() {
		// A directory occupying a <name>.crt path is a certificate the scan cannot
		// read, not an ordinary directory: counting it as unreadable keeps it
		// health-neutral (a restart cannot clear it) while blocking orphan reaping,
		// so sync reconciliation never deletes the still-live <name>.pfx of an input
		// path that still exists in an unusable shape. The walk continues into it so
		// genuinely nested certificate entries are still discovered.
		//
		// Debug for the reason the unreadable-sub-path arm above states in full: this
		// is the same shape of steady-state layout mistake, recurring on EVERY scan
		// until an operator moves the directory, and the unreadable count incremented
		// here is what raises the aggregate Warn in logInputCoverageWarnings on this
		// same scan. Naming the path at the default level too would emit both halves of
		// that two-level contract as Warn for one condition.
		if layout.IsCert(rel) {
			slog.Debug("skipping cert: certificate path is a directory",
				"path", rel,
				"remediation", "replace the directory with a regular <name>.crt file")
			sw.unreadable++
		}
		return nil
	}
	if !layout.IsCert(rel) {
		sw.noteUnwalkableSymlink(rel, d)
		return nil
	}
	sw.seen[rel] = struct{}{}
	sw.results = append(sw.results, sw.convertEntry(ctx, rel))
	// A cancellation that landed *during* the conversion above already turned that
	// entry into a shutdown artifact, but not always the same one: an interrupted
	// /input read is statusUnreadable (noteUnreadableInput routes a cancelled read
	// there, health-neutral, and reserves statusVanished for an ENOENT race), while an
	// interrupted prior-bundle read or atomic write is statusFailed. Re-check here so
	// the walk aborts and Run reports the cancellation, instead of returning a
	// "completed" scan whose unreadable, vanished or failed count is really that
	// artifact.
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

// failScan reports a scan that ended before the walk began: a certs or output
// root that could not be opened as an *os.Root. It routes the error through
// logScanOutcome so the "scan aborted before completion" record — the one the
// README's CertConverterScanAborted rule matches — is emitted for an unusable
// root too, not only for a walk that aborted at ".". The counts it logs are all
// zero, which is accurate: nothing was visited. logInputCoverageWarnings
// self-vetoes on a non-nil walk error, so no coverage WARN is emitted alongside
// it. The error is returned unchanged so the caller pairs it with a zero
// ScanResult at the return site.
func failScan(ctx context.Context, err error) error {
	logScanOutcome(ctx, &ScanResult{}, err)
	return err
}

// logScanOutcome emits the end-of-scan summary. A completed walk logs at Info;
// a walk aborted by shutdown (context cancellation or deadline) logs at Debug;
// any other abort logs at Warn so an operator sees the partial scan and its
// error. The count attributes are identical in all three cases (the README's Loki
// alert matches on them), so they are built once. Every count is named here,
// including the ones deliberately kept out of Unreadable; ScanResult's field
// comments carry why each is separate.
func logScanOutcome(ctx context.Context, result *ScanResult, walkErr error) {
	level, msg := slog.LevelInfo, "scan complete"
	if walkErr != nil {
		level, msg = slog.LevelWarn, "scan aborted before completion"
		if IsShutdown(walkErr) {
			level, msg = slog.LevelDebug, "scan cancelled during shutdown"
		}
	}
	attrs := make([]any, 0, 2+2*len(summaryAttrs))
	if walkErr != nil {
		attrs = append(attrs, "error", walkErr)
	}
	for _, a := range summaryAttrs {
		attrs = append(attrs, a.name, a.of(result))
	}
	slog.Log(ctx, level, msg, attrs...)
	logInputCoverageWarnings(result, walkErr)
}

// logInputCoverageWarnings names the health-neutral outcomes that produce no PFX --
// for the whole input tree, or for one certificate in it -- and that the summary
// counts alone cannot distinguish from a healthy steady state: an input tree the scan
// could not fully read, one holding no certificate pair at all, one whose every
// certificate lacks its sibling .key, and one where only some of them do.
//
// This is the single home for EVERY default-level /input-coverage diagnostic. The
// unreadable aggregate used to be rendered by the composition root instead, from the
// exported count, which split one taxonomy across two packages: a change to the
// classification here silently changed what that WARN covered, with no compile-time
// or structural signal. main keeps only healthyAfterScan, the health boundary.
//
// The unreadable arm fires ahead of the full-enumeration gate below because it IS the
// diagnosis for an incomplete enumeration; it needs only a completed walk (walkErr ==
// nil), the same condition the composition root applied by returning early on a scan
// error. The three arms after the gate require a completed walk with no unreadable
// sub-path, no unresolved symlink and nothing that vanished mid-scan. Unreadable == 0
// is what makes "every certificate" provable, because Run deliberately continues past
// an unreadable sub-path, so a partial enumeration cannot know what lies beneath it,
// and the unreadable arm already carries the actionable diagnosis for that shape.
// Vanished == 0 is the same argument for the transient case: a cert, or the key that
// pairs with one, replaced during the walk was not observed whole, so "every
// certificate lacks its key" is not a claim this scan can make, and the next one can.
func logInputCoverageWarnings(result *ScanResult, walkErr error) {
	if walkErr != nil {
		return
	}
	if result.Unreadable > 0 {
		// Message byte-identical to the one the composition root emitted: README's
		// Alerting section tells an operator at LOG_LEVEL=warn to alert on this exact
		// line, so its wording is a contract regardless of which package renders it.
		// Health is deliberately unaffected (see main.healthyAfterScan): nothing the
		// scan merely could not READ is clearable by a restart.
		slog.Warn("some /input paths were unreadable and were skipped; health is unaffected",
			"unreadable", result.Unreadable,
			// inputPermRemediation, not a permission-only hint of its own: the count
			// aggregates every unreadable shape this package classifies, and only some
			// of them are permission problems. A directory occupying a <name>.crt path
			// is a LAYOUT mistake whose per-path Debug line names the right action, so
			// an aggregate that said only "fix /input permissions or run as a UID that
			// can read it" sent the operator to re-check permissions that were already
			// correct. Sharing the package's one /input-side hint keeps the aggregate
			// and the per-path lines from prescribing two different actions for one
			// condition.
			"remediation", inputPermRemediation)
	}
	if !result.inputFullyEnumerated() {
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
	case result.Orphan > 0:
		// Some, not all. The pairs that DO have their key still convert, so the scan
		// completes with failed=0 and the summary's orphan count is the only trace at
		// the default level. An orphaned .crt is also recorded as seen, so its
		// existing bundle is never reaped either: it keeps being served, indefinitely
		// stale, with nothing naming it. Same reasoning as the arm above, one blast
		// radius smaller. The per-cert path stays Debug; this is the once-per-scan
		// aggregate.
		slog.Warn("some certificates under the input root are missing their sibling .key; those produce no PFX and any existing bundle for them goes stale",
			"orphan", result.Orphan, "total", result.Total,
			"remediation", "name each private key <name>.key beside its <name>.crt (Caddy's layout), or remove the certificate from /input")
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

// failEntry records one per-entry failure: it logs the failure and returns the
// failed status for the caller to propagate. A failure caused by shutdown
// (context cancellation or deadline) logs at Debug -- it is not an operator
// actionable conversion error -- while every real failure logs at Error, the same
// split logScanOutcome applies to the walk-level error. Callers may pass extra
// slog key/value pairs (a remediation hint, the output path) for failures whose
// cause is not evident from the input path alone.
//
// It carries no rollback obligation: currency is derived from the output file
// itself, so a failed entry leaves the previous bundle (or nothing) at the output
// path and the next scan reaches the same verdict and retries the pair.
func failEntry(logPath, msg string, err error, extra ...any) conversionStatus {
	attrs := append([]any{"path", logPath, "error", err}, extra...)
	if IsShutdown(err) {
		slog.Debug(msg+" (shutdown)", attrs...)
	} else {
		slog.Error(msg, attrs...)
	}
	return statusFailed
}

// --- Per-entry conversion ---

// pairInputs carries the cert and key PEM bytes readPair read through the
// confined input root, so one return value covers both inputs of a pair.
type pairInputs struct {
	certPEM []byte
	keyPEM  []byte
}

// pairFingerprint identifies the exact cert/key input bytes. Each side is
// hashed separately before combining, so moving bytes across the boundary is
// still detected. It controls diagnostic emission only; output-derived currency
// remains the authority for whether a PFX needs rewriting.
func pairFingerprint(certPEM, keyPEM []byte) [sha256.Size]byte {
	certSum := sha256.Sum256(certPEM)
	keySum := sha256.Sum256(keyPEM)
	var pair [2 * sha256.Size]byte
	copy(pair[:sha256.Size], certSum[:])
	copy(pair[sha256.Size:], keySum[:])
	return sha256.Sum256(pair[:])
}

// observationLog de-duplicates the per-pair observation WARNs across scans: an
// odd-but-convertible input is named on the scan that introduced it and stays
// silent on every later fsnotify event and fallback tick. It maps each cert path
// to a signature of the last input bytes AND the observations derived from them,
// and is NEVER consulted for currency, which store.isCurrent derives from the
// bundle on disk. It is process-lifetime state held by the Scanner, so a restart
// re-reports each pair exactly once.
//
// The map is plain, so it inherits Scanner's single-goroutine Run contract.
//
// It carries a SECOND, structural fact that readPair's missing-key classifier
// depends on, in its own `whole` set: a path is in that set only if this process read
// that pair WHOLE — cert and sibling key both — because note and record are reached only
// past readPair's success. That MEMBERSHIP is the one piece of in-process evidence that a
// key which is missing now was there before (completedPair). It is a separate field
// precisely because it is spent on a different schedule than the signature: forgetPair
// spends the wholeness, never the de-duplication.
type observationLog struct {
	seen map[string][sha256.Size]byte
	// whole holds the paths this process has read as a COMPLETE pair. It is the
	// structural half of the log, kept separate from `seen` because the two are spent
	// differently: forgetPair spends one scan of missing-key grace, which must not
	// also reset the WARN de-duplication for input bytes that never changed.
	whole map[string]struct{}
}

func newObservationLog() *observationLog {
	return &observationLog{
		seen:  make(map[string][sha256.Size]byte),
		whole: make(map[string]struct{}),
	}
}

// observationSignature identifies both the input bytes and the observations
// Analyse currently derives from them. Not every observation is a property of the
// bytes alone: the validity-window ones (expired, not-yet-valid, chain cert out of
// window) also depend on the scan time, so keying de-duplication on the input
// fingerprint alone would suppress a cert crossing NotAfter forever while the
// daemon stays up. Hashing each field separately keeps the variable-length
// kind/detail boundary unambiguous.
func observationSignature(input [sha256.Size]byte, observations []convert.Observation) [sha256.Size]byte {
	data := append([]byte{}, input[:]...)
	for _, observation := range observations {
		kind := sha256.Sum256([]byte(observation.Kind))
		detail := sha256.Sum256([]byte(observation.Detail))
		data = append(data, kind[:]...)
		data = append(data, detail[:]...)
	}
	return sha256.Sum256(data)
}

// note records the pair's signature and emits its observations when that
// signature differs from the last one observed for that path. The observations
// describe the INPUT as read on this scan, so a semantically equivalent input
// edit (a reordered chain, an appended duplicate cert, a second key) still has to
// be named once even though the bundle on disk stays correct — and so does a
// newly derived expiry, whose bytes never changed. Keying the emission on the
// signature reports each one on the scan that introduced it, which is what
// unconditional logging would turn into noise.
func (o *observationLog) note(rel string, fp [sha256.Size]byte, obs []convert.Observation) {
	current := observationSignature(fp, obs)
	previous, ok := o.seen[rel]
	o.seen[rel] = current
	o.whole[rel] = struct{}{}
	if !ok || previous != current {
		logConversionObservations(rel, obs)
	}
}

// record commits the signature without re-emitting: the conversion path has
// already logged the observations unconditionally.
func (o *observationLog) record(rel string, fp [sha256.Size]byte, obs []convert.Observation) {
	o.seen[rel] = observationSignature(fp, obs)
	o.whole[rel] = struct{}{}
}

// completedPair reports whether this process has already read rel's pair whole, which
// is what noteMissingKey reads as "this certificate HAD its sibling key".
//
// A false answer is the safe direction, and it is deliberately the answer for every
// pair this process never got through: a first scan after a restart, a cert whose PEM
// does not parse, a key that was already missing when the daemon started. All of them
// keep the default-level missing-key diagnostic they have today, because no memory
// exists to suppress it.
func (o *observationLog) completedPair(rel string) bool {
	_, remembered := o.whole[rel]
	return remembered
}

// forgetPair spends the wholeness evidence for one pair, spending the single scan of
// grace completedPair grants: the scan that reports a vanished key forgets that the pair
// was ever read whole, so a key that is STILL missing on the next scan — one fsnotify
// event or one fallback tick later — has no memory behind it and is reported as the
// genuine orphan it is. The observation signature in `seen` deliberately SURVIVES: the
// input bytes did not change, so a re-read of the same pair must not re-emit its
// observation WARN. It is the per-path sibling of forget, which prunes every path a
// COMPLETE walk did not see.
func (o *observationLog) forgetPair(rel string) {
	delete(o.whole, rel)
}

// forget drops entries for paths a COMPLETE walk did not see, so a pair that
// comes back is reported once again. Callers must gate this on a complete
// enumeration: with a partial one, a pair hidden behind an unreadable sub-path
// or an unresolved symlink would be forgotten and re-warn on the next clean
// scan.
func (o *observationLog) forget(seen map[string]struct{}) {
	for rel := range o.seen {
		if _, ok := seen[rel]; !ok {
			delete(o.seen, rel)
			delete(o.whole, rel)
		}
	}
}

// inputPermRemediation is the one remediation hint every /input-side WARN in this
// package carries -- the per-path cert and key lines AND the once-per-scan unreadable
// aggregate -- and the mirror of store.go's outputPermRemediation: they all name the
// SAME operator action for the same root cause, so an operator who sees the cert-side
// line, the key-side line and the aggregate in one scan must not read three variants
// of it.
//
// It names all three shapes the unreadable count aggregates, not permissions alone: a
// permission or UID problem, a path that is not a regular file (a directory occupying
// a <name>.crt path, a FIFO), and a symlink whose target escapes the mount. The
// aggregate previously offered permission/UID advice only, which sent an operator with
// a layout mistake to re-check permissions that were already correct.
const inputPermRemediation = "check /input permissions and that the container runs as a UID that can read it, and that each certificate path is a regular file inside the mount, not a directory or a symlink out of it"

// readPair resolves and reads the input side of one .crt entry: it classifies
// the sibling .key (a key that is not there is a health-neutral statusOrphan, or the
// transient statusVanished when this process had already read the pair whole — see
// noteMissingKey; a non-ENOENT stat failure is statusUnreadable instead, because the
// key is there and cannot be read — health-neutral too, but it also blocks orphan
// reaping, which an orphan does not) and then performs both bounded reads through the
// input source, so every /input byte is read once from within the confined root.
//
// The returned conversionStatus is statusUnset on success and, on failure, the
// outcome convertEntry must propagate for that entry, with the failure already
// logged. statusUnset is not an outcome, so it doubles as the success signal: a
// status propagated from a successful read can never be mistaken for a
// conversion, and no second return value can disagree with it.
func (sw *scanWalk) readPair(ctx context.Context, rel, keyRel string) (pairInputs, conversionStatus) {
	if _, statErr := sw.src.stat(keyRel); statErr != nil {
		if errors.Is(statErr, fs.ErrNotExist) {
			return pairInputs{}, sw.noteMissingKey(rel, keyRel)
		}
		// A non-ENOENT stat failure (a sibling key that is a symlink the *os.Root
		// refuses because it escapes /input, or a permission/IO error) is NOT a
		// genuine "no key" orphan — the key is there and cannot be read. Reporting it
		// as an orphan misdescribed it in the scan summary and in the all-orphan
		// diagnostic, so it is statusUnreadable, the same outcome the two bounded
		// reads below produce for the same class of condition. Health-neutral either
		// way; the message is unchanged because an alert rule keys on it.
		slog.Warn("skipping cert: cannot stat sibling key", "path", rel, "error", statErr,
			"remediation", inputPermRemediation)
		return pairInputs{}, statusUnreadable
	}

	certPEM, err := sw.src.readBounded(ctx, rel)
	if err != nil {
		return pairInputs{}, sw.noteUnreadableInput(rel, rel, "certificate", err)
	}
	keyPEM, err := sw.src.readBounded(ctx, keyRel)
	if err != nil {
		return pairInputs{}, sw.noteUnreadableInput(rel, keyRel, "private key", err)
	}
	return pairInputs{certPEM: certPEM, keyPEM: keyPEM}, statusUnset
}

// noteMissingKey classifies a sibling .key that is not there at the stat and returns the
// outcome, with its diagnosis already logged.
//
// One ENOENT, two conditions. The STEADY STATE is a key that was never named
// <name>.key beside its <name>.crt: no PFX is produced, any existing bundle goes
// indefinitely stale, and logInputCoverageWarnings' once-per-scan aggregate is the only
// default-level trace of it — so that case stays statusOrphan and keeps that WARN and
// its rename remediation. The TRANSIENT is a key being replaced while the scan reads
// the tree: the same renewal window the cert and key READS classify as statusVanished,
// where naming a misnamed key would tell an operator to rename files that are correct.
//
// One ENOENT cannot separate them, so this needs a second observation, and the only
// honest one available in-process is memory: observationLog holds an entry for a pair
// only once this process has read that pair WHOLE, so its presence is evidence the key
// was there (completedPair). The memory is SPENT on use, which is what keeps the
// genuine case loud — see forgetPair — and a pair this process never read whole has no
// memory at all, so every shape that is missing its key from the start keeps today's
// default-level diagnostic.
//
// src.pathVanished is the read side's primitive, asked here for the question its
// second arm was written for. Its answers all read correctly for a stat that just
// returned ENOENT: the key path is GONE (the replacement has not landed yet), or it is
// a non-symlink again (it landed between this stat and that Lstat) — either way the
// tree moved under the scan; against a SURVIVING symlink whose target does not exist,
// which is the steady-state certbot live/ -> archive/ shape and stays an orphan. Any
// other Lstat failure answers false there, so a key the scan cannot even classify
// stays an orphan too: no arm that fails to prove a replacement takes the quieter
// reading.
//
// statusVanished rather than a count of its own, because it is the same condition the
// read side already named: health-neutral, out of the documented unreadable= alert and
// its permissions remediation, Debug-only per path, and — for this one scan — a veto on
// both the orphan aggregate (ScanResult.inputFullyEnumerated) and the reap, exactly as
// a vanished cert is. This pair's OWN bundle was never at risk either way: visit
// records the .crt in `seen` before dispatching it, so it is not an orphan candidate,
// and the next scan sees the replacement and reconciles the rest.
func (sw *scanWalk) noteMissingKey(rel, keyRel string) conversionStatus {
	if sw.observations.completedPair(rel) && sw.src.pathVanished(keyRel) {
		sw.observations.forgetPair(rel)
		// Byte-identical to the read side's vanish line for the same condition on the
		// same pair, so an operator correlating one renewal does not meet two
		// vocabularies for it.
		slog.Debug("skipping cert: private key vanished during the scan", "path", rel)
		return statusVanished
	}
	// A genuine orphan: the certificate has no sibling key at all.
	slog.Debug("skipping cert without matching key", "path", rel)
	return statusOrphan
}

// noteUnreadableInput logs a failed read of an /input file and RETURNS the outcome it
// diagnosed, so the classification and its diagnostic cannot drift apart: Debug plus
// statusUnreadable when the read was cancelled by shutdown, Debug plus the transient
// statusVanished when the file simply vanished, and Warn plus statusUnreadable
// otherwise -- the last matching readPair's sibling-key stat. Both outcomes are
// health-neutral.
//
// logRel is the .crt path every per-entry log line names (so the cert-side and the
// key-side line of one pair are attributable to the same entry); inputRel is the path
// the failed read actually used, which is what the ENOENT arm re-examines.
//
// Every OPERATOR-ACTIONABLE reason a read fails here is a steady-state condition a
// restart cannot clear. A confinement refusal in particular cannot be identified by
// sentinel — os.Root reports "path escapes from parent", which matches none of
// fs.ErrPermission, fs.ErrNotExist, fs.ErrInvalid, syscall.ELOOP or syscall.EXDEV — so
// classifying per-error would mean matching on Go's error text. Treating every
// non-ENOENT read failure alike avoids that entirely and makes the two reads of a pair
// agree, which was the actual defect: the sibling key's stat failure was already
// health-neutral while the cert's read failure flipped the container unhealthy.
//
// ENOENT alone is not enough to call the entry a benign race. It IS one when the path
// itself is gone — the entry existed at readdir and was gone by the read (a renewal
// replacing a file, an atomic-write temp) — so that stays at Debug AND out of the
// Unreadable count: folding it in raised the documented unreadable-path alert, with its
// permissions remediation, on the ordinary renewal this daemon exists to process. It
// becomes statusVanished instead, which the next scan clears. But the SAME ENOENT comes
// back on every scan from a symlink that is still there and points at a target that is
// not (the certbot live/ -> archive/ layout with only live/ mounted, or a link left
// behind by a removed cert): that is a steady-state operator-actionable condition, and
// reporting it as a transient race would leave a certificate producing no PFX forever
// with no default-level signal anywhere. sw.src.pathVanished separates the two.
//
// The pair is still not converted either way, so both outcomes block orphan reaping:
// an input tree the scan could not fully read cannot prove an output is orphaned.
func (sw *scanWalk) noteUnreadableInput(logRel, inputRel, what string, err error) conversionStatus {
	if IsShutdown(err) {
		// A cancelled read is the shutdown itself, not an unreadable path: the WARN
		// below is the message the README recommends alerting on, so emitting it for
		// a normal SIGTERM would page an operator for a mount that is fine.
		slog.Debug("skipping cert: "+what+" read interrupted by shutdown", "path", logRel, "error", err)
		return statusUnreadable
	}
	if errors.Is(err, fs.ErrNotExist) && sw.src.pathVanished(inputRel) {
		slog.Debug("skipping cert: "+what+" vanished during the scan", "path", logRel, "error", err)
		return statusVanished
	}
	slog.Warn("skipping cert: cannot read "+what,
		"path", logRel, "error", err,
		"remediation", inputPermRemediation)
	return statusUnreadable
}

// convertEntry resolves the outcome for one .crt entry under certsRoot. It
// reads the cert and its sibling .key exactly once through the input source,
// analyses the pair, and either skips it (the bundle on disk is already the one
// these inputs produce) or converts and writes it (it is not, whether because the
// inputs changed, the output went missing or was replaced, or the encoder profile
// or password changed). Every output touch — the prior-bundle read, the directory
// creation and the atomic write — is confined to the store's root, so a symlink
// planted under the output tree cannot redirect the private-key-bearing PFX
// outside it. The only thing recorded on success is the pair's observation
// signature (input fingerprint plus the observations derived from it), which gates
// one-shot input diagnostics and never currency, so every failure path
// leaves the pair due for a retry without needing a rollback. All per-cert logs
// use the certsRoot-relative path for a stable, non-leaky identifier.
func (sw *scanWalk) convertEntry(ctx context.Context, rel string) conversionStatus {
	// Both sibling names come from layout, so this package and internal/watch
	// derive the pairing rule from one place instead of two copies that can drift.
	keyRel := layout.KeyFor(rel)

	inputs, outcome := sw.readPair(ctx, rel, keyRel)
	if outcome != statusUnset {
		return outcome
	}
	certPEM, keyPEM := inputs.certPEM, inputs.keyPEM
	fingerprint := pairFingerprint(certPEM, keyPEM)

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
	observations := analysis.Observations()
	current, cause, err := sw.out.isCurrent(ctx, pfxRel, &analysis, sw.enc, sw.password)
	if err != nil {
		// Only shutdown gets here: isCurrent resolves every unreadable-output case to
		// "stale" itself and reserves an error for cancellation, which is neither
		// current nor stale. failEntry logs it at Debug, and visit's post-conversion
		// context check turns it into the walk-level cancellation the caller reports,
		// so this entry's statusFailed never reaches the health marker.
		return failEntry(rel, "failed to inspect existing pfx", err)
	}
	if current {
		// The observations describe the INPUT, so a semantically equivalent input
		// edit still has to be named once even though the bundle on disk stays
		// correct; observationLog.note owns that once-per-change rule.
		sw.observations.note(rel, fingerprint, observations)
		slog.Debug("skipping unchanged cert pair", "path", rel)
		return statusUnchanged
	}

	slog.Debug("converting cert pair", "path", rel)
	pfxData, err := convert.Encode(&analysis, sw.enc, sw.password)
	if err != nil {
		logConversionObservations(rel, observations)
		return failEntry(rel, "conversion failed", err)
	}
	if err := sw.out.write(ctx, pfxRel, pfxData); err != nil {
		outcome := sw.noteWriteFailure(rel, pfxRel, cause, err)
		if outcome == statusUnwritable {
			// The bundle on disk already holds the bytes these inputs produce and the
			// refusal is steady state (no restart grants the UID ownership), so the
			// observations describe an input that will be re-analysed on every scan for
			// as long as the operator leaves /output as it is. note emits them once per
			// CHANGE and commits the signature, exactly as the unchanged path does:
			// re-emitting per attempt is reserved for statusFailed, where the bundle
			// those inputs produce is genuinely not on disk. That is why the emission
			// waits for the write outcome instead of running before it — a persistently
			// foreign-owned bundle is non-current on every scan, so an unconditional
			// emission there repeated the input WARN on every scan forever.
			// unwritableBundleMsg remains the standing per-scan diagnostic for the
			// condition itself.
			sw.observations.note(rel, fingerprint, observations)
			return outcome
		}
		logConversionObservations(rel, observations)
		return outcome
	}
	logConversionObservations(rel, observations)
	sw.observations.record(rel, fingerprint, observations)

	slog.Info("wrote pfx", "path", pfxRel)
	return statusConverted
}

// unwritableBundleMsg is the standing WARN for the one /output write refusal that is
// NOT a conversion failure: a prior bundle whose bytes are already correct, whose mode
// is laxer than policy, whose chmod the filesystem refused, and whose repairing
// rewrite it refused too. It is its own message rather than a variant of
// modeRepairRefusedMsg because that line announces an attempt this one reports the
// outcome of, and an operator correlating a permanently-lax private key with a log
// query must find the standing condition rather than the attempt.
const unwritableBundleMsg = "prior pfx is more permissive than policy and neither the mode repair nor the replacing write was permitted; leaving the existing bundle in place, health is unaffected"

// noteWriteFailure classifies a failed PFX write and returns the outcome the entry
// must propagate, with the failure already logged.
//
// The general rule is unchanged and stays the default: a PFX this app could not write
// is a conversion failure, logged at ERROR, counted in ScanResult.Failed, and health
// goes unhealthy — which is right, because the bundle those inputs produce is not on
// disk. The single exception is the one condition where nothing is missing: the rewrite
// was scheduled ONLY to repair a mode a refused chmod could not
// (staleModeRepairRefused, which store.isCurrent reports only after the content
// comparison confirmed the bytes on disk already match), and the write was refused
// for a permission reason too. The bundle on disk still holds exactly the bytes these
// inputs produce, so the operator's
// PFX is neither stale nor absent; what is wrong is ownership of /output, which no
// restart can change. Counting that in Failed made the container restart-loop on a
// condition a restart cannot clear — the same mistake statusUnreadable exists to avoid
// on the /input side, and the more likely half of the deployment this arm exists for,
// since a UID that does not own the bundle plausibly does not own its directory either.
//
// A NON-permission failure of that same rewrite (EROFS, ENOSPC, a symlink refusal, an
// occupied path) stays a conversion failure: it is not evidence about ownership, and it
// is exactly the class where a rewrite might genuinely be able to land later.
//
// The WARN is emitted once per bundle per scan, because the entry is written at most
// once per scan: there is no retry loop behind it.
func (sw *scanWalk) noteWriteFailure(logRel, pfxRel string, cause staleCause, err error) conversionStatus {
	if cause == staleModeRepairRefused && isPermissionRefusal(err) {
		slog.Warn(unwritableBundleMsg,
			"path", logRel, "output_path", pfxRel, "error", err,
			"remediation", outputPermRemediation)
		return statusUnwritable
	}
	// The message is unchanged (an operator's log query keys on it); the
	// remediation names the two steady-state output-side causes.
	return failEntry(logRel, "conversion failed", err, "output_path", pfxRel,
		"remediation", "check /output ownership and permissions for the UID in user:, "+
			"and that no symlink is planted at the output path")
}

// logConversionObservations surfaces Analyse's non-fatal findings about a pair's
// input. Every one of them is a CONVERTIBLE condition, so none flips health:
// health tracks conversion failures, and these all converted. They are logged at
// WARN because each names something the operator probably did not intend, except
// the duplicate-block artefact, which is noise at that level.
//
// Observations are emitted on the conversion path, and on the unchanged path only
// when the pair's observation signature (input bytes plus the observations derived
// from them) differs from the last one observed, which is what keeps them from
// becoming noise: an odd-but-convertible input, or a newly derived expiry over
// unchanged bytes, is reported on the scan that introduced it rather than on every
// scan for the life of the deployment.
// A pair that keeps FAILING re-emits per attempt, matching how the failure itself is
// logged.
// Detail is already bounded by convert, so it needs no further truncation here.
func logConversionObservations(rel string, observations []convert.Observation) {
	for _, o := range observations {
		if o.Kind.Noise() {
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
//
// statusVanished and statusUnwritable each keep their own count instead; see
// ScanResult's field comments for why.
func countResults(results []conversionStatus, walkUnreadable, walkUnresolved, walkVanished int) ScanResult {
	var counts [statusCount]int
	for _, r := range results {
		counts[r]++ // every outcome, including a future one, lands somewhere
	}
	return ScanResult{
		Total:      len(results),
		Converted:  counts[statusConverted],
		Unchanged:  counts[statusUnchanged],
		Orphan:     counts[statusOrphan],
		Failed:     counts[statusFailed],
		Unreadable: walkUnreadable + counts[statusUnreadable],
		Unresolved: walkUnresolved,
		Vanished:   walkVanished + counts[statusVanished],
		Unwritable: counts[statusUnwritable],
	}
}
