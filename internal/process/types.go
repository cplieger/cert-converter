package process

// conversionStatus represents the outcome of a single cert/key pair conversion.
// It is a Scanner implementation detail — ScanResult is the package's exported
// outcome surface — so the enum stays package-private.
type conversionStatus int

// statusUnset is the zero value and is deliberately NOT an outcome: a helper
// that resolved no outcome for an entry (readPair on its success path) returns
// it, so a value propagated by mistake can never read as a successful
// conversion. It never reaches countResults.
//
// statusConverted, statusUnchanged, statusFailed, statusOrphan, statusUnreadable,
// statusVanished and statusUnwritable enumerate the possible outcomes of converting
// a single cert/key pair.
//
// statusUnreadable is health-neutral and exists to keep the health marker honest.
// An /input path the app cannot read — a symlink the confined root refuses because
// it escapes the mount, a permission denial, a directory or FIFO in a cert's place —
// is a steady-state layout or ownership condition, and health answers only "should an
// orchestrator restart this container?". Counting those as statusFailed made the
// container restart-loop forever on a configuration a restart cannot fix; the
// certbot live/ -> archive/ symlink layout is the common shape that triggers it.
//
// It is a distinct status rather than statusOrphan because an unreadable cert is not
// "a certificate with no key" — reporting it as an orphan would misdescribe the
// condition in the scan summary and in the all-orphan diagnostic.
//
// One TRANSIENT case is deliberately routed here rather than to statusVanished: a
// read cancelled by shutdown (noteUnreadableInput's IsShutdown arm). It is logged at
// Debug so the documented WARN never pages for a normal SIGTERM, and it takes this
// status because an interrupted read leaves the tree unproven exactly as an
// unreadable path does — health-neutral and reap-vetoing — while statusVanished
// stays reserved for the ENOENT renewal race. The scan it counts toward is itself
// aborted, so the count never reaches the unreadable WARN aggregate
// (logInputCoverageWarnings returns early on a non-nil walk error).
//
// statusVanished is the TRANSIENT sibling of statusUnreadable: the entry was there a
// moment ago and is gone now — it existed at readdir and was gone by the bounded read,
// or its sibling key was read whole by an earlier scan of this process and is gone by
// this scan's stat — which is what an ordinary renewal replacing a cert or a key looks
// like from inside the scan. It is health-neutral and it
// still blocks orphan reaping (an input tree the scan could not fully read cannot
// prove an output orphaned), but it is deliberately NOT folded into
// ScanResult.Unreadable: that count drives the documented `unreadable=` Loki alert
// and its permissions remediation, and the next scan converts the replacement, so
// naming the renewal race there would alert an operator on exactly the activity this
// daemon exists to process.
//
// statusUnwritable is the /output-side member of the same health-neutral family, and its
// promise is stated here exactly, because it is the promise health rests on: this app
// could not replace a bundle at the output path, it never PROVED that bundle wrong, and
// the refusal ITSELF said no restart changes what it refused. That last fact is not
// re-derived anywhere: every refusal of an /output write carries its own classification,
// assigned by the site that refused (store.write's three refusal sites, via
// writeRefusalCause), and a site cannot compile without stating one. The classes those
// sites state are a permission denial, an /output layout this app cannot publish through
// — a symlinked output tree, a component that is not a directory, a regular file
// occupying a directory component of the output path, or a component another writer
// replaced — a read-only mount, a full volume, and an exhausted quota. The single
// exception is stated only by the bounded atomic write reading its own error: anything
// THAT site cannot attribute to one of those classes becomes refusalTransient, and that
// class keeps the loud statusFailed. Its members are enumerated in ONE place, its own doc
// in store.go — a genuinely transient I/O error, a symlink at the output name, a bundle
// above the write cap — and only the first is restart-clearable in its own right; for the
// other two inspect has already classified the bundle before the cause is ever read (a
// non-regular occupant at the output name is contentVerifiedStale, and this app never
// emits a bundle over the cap), so writeOutcome's state gate decides them. The two
// directory steps (create and pin) deliberately take the other direction with their
// residuals — an errno they cannot attribute is the shape of the operator's output tree
// (refusalOutputLayout), so even a transient EIO there is restart-unclearable by
// construction; store.write's MkdirAll arm documents why.
//
// "Never proved it wrong" means this app could not verify the content AT ALL: a bundle
// above the readable bound, unreadable, un-stat-able, or refused by the codec's preflight.
// Nobody compared the bytes, so nothing here claims the operator's bundle is wrong. The
// realistic deployment behind it is "the operator changed PUID and left root-owned output
// behind". That shape used to be counted in statusFailed, because the two arms that could
// not read a bundle overwrote the reason the rewrite was scheduled: that pinned the
// container unhealthy on every scan over an /output permission state no restart can clear,
// which is the same restart-loop statusUnreadable exists to prevent on the /input side.
//
// Which write failures take this status instead of statusFailed is derived in exactly
// one place — writeOutcome, whose doc carries the carve-outs in full. In short: a bundle
// this app compared and found stale stays statusFailed however the write failed, and a
// bundle it compared and MATCHED is never written at all (contentState.upToDate), so a
// lax mode alone can never produce a refusal to classify. Like the two /input members,
// this status is health-neutral, reported by its own standing WARN, and it blocks
// orphan reaping.
const (
	statusUnset conversionStatus = iota
	statusConverted
	statusUnchanged
	statusFailed
	statusOrphan
	statusUnreadable
	statusVanished
	statusUnwritable

	// statusCount is the enum's LENGTH, not an outcome. It is last so that a status
	// added above it is counted by construction: countResults indexes a
	// [statusCount]int by the status itself, where the switch it replaced counted a
	// new member as nothing at all, silently, with no compile error.
	statusCount
)
