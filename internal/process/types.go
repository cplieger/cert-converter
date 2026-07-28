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
// statusConverted, statusUnchanged, statusFailed, statusOrphan,
// statusUnreadable, and statusVanished enumerate the possible outcomes of
// converting a single cert/key pair.
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
// statusVanished is the TRANSIENT sibling of statusUnreadable: the entry existed at
// readdir and was gone by the bounded read, which is what an ordinary renewal
// replacing a cert looks like from inside the scan. It is health-neutral and it
// still blocks orphan reaping (an input tree the scan could not fully read cannot
// prove an output orphaned), but it is deliberately NOT folded into
// ScanResult.Unreadable: that count drives the documented `unreadable=` Loki alert
// and its permissions remediation, and the next scan converts the replacement, so
// naming the renewal race there would alert an operator on exactly the activity this
// daemon exists to process.
const (
	statusUnset conversionStatus = iota
	statusConverted
	statusUnchanged
	statusFailed
	statusOrphan
	statusUnreadable
	statusVanished
)
