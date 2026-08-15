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

	// statusCount is the enum's LENGTH, not an outcome.
	statusCount
)
