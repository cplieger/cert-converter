package process

// conversionStatus represents the outcome of a single cert/key pair conversion.
type conversionStatus int

// statusUnset is the zero value and is deliberately NOT an outcome: a helper
// that resolved no outcome for an entry (readPair on its success path) returns
// it, so a value propagated by mistake can never read as a successful
// conversion.
const (
	statusUnset conversionStatus = iota
	statusConverted
	statusUnchanged
	statusFailed
	statusOrphan
	statusUnreadable
	statusVanished
	statusUnwritable
	// statusCollided marks a flat-layout source whose output name another source
	// also claims this scan; nothing was converted for the contested name and
	// the container goes unhealthy until the operator resolves the ambiguity.
	statusCollided

	// statusCount is the enum's LENGTH, not an outcome.
	statusCount
)
