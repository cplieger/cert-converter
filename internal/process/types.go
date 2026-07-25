package process

// conversionStatus represents the outcome of a single cert/key pair conversion.
// It is a Scanner implementation detail — ScanResult is the package's exported
// outcome surface — so the enum stays package-private.
type conversionStatus int

// statusConverted, statusUnchanged, statusFailed, and statusOrphan enumerate
// the possible outcomes of converting a single cert/key pair.
const (
	statusConverted conversionStatus = iota
	statusUnchanged
	statusFailed
	statusOrphan
)
