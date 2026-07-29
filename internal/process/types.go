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
// statusUnwritable is the /output-side member of the same health-neutral family, and
// it covers exactly one shape: a prior bundle whose CONTENT is already correct, whose
// mode is laxer than policy, whose chmod the filesystem refused, and whose repairing
// rewrite the filesystem refused too — the "operator changed PUID and left root-owned
// output behind" deployment, where the file and its directory are both foreign-owned.
// Nothing about the operator's PFX is missing or out of date, and no restart can grant
// a permission the UID does not have, so counting it as statusFailed would restart-loop
// the container over a condition a restart cannot clear. Every OTHER failed PFX write
// stays statusFailed and still flips health. Like the two /input members it is
// health-neutral, reported by its own standing WARN, and it blocks orphan reaping.
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
