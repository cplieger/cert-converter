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
// statusConverted, statusUnchanged, statusFailed, statusOrphan, and
// statusUnreadable enumerate the possible outcomes of converting a single
// cert/key pair.
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
const (
	statusUnset conversionStatus = iota
	statusConverted
	statusUnchanged
	statusFailed
	statusOrphan
	statusUnreadable
)
