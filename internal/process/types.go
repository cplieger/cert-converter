package process

// ConversionStatus represents the outcome of a single cert/key pair conversion.
type ConversionStatus int

// StatusConverted, StatusUnchanged, StatusFailed, and StatusOrphan enumerate
// the possible outcomes of converting a single cert/key pair.
const (
	StatusConverted ConversionStatus = iota
	StatusUnchanged
	StatusFailed
	StatusOrphan
)
