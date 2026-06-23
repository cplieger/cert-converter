package convert

// CertPair identifies a certificate and its matching private key.
type CertPair struct {
	CertPath string
	KeyPath  string
	RelPath  string // relative to certsRoot
}

// ConversionStatus represents the outcome of a single pair conversion.
type ConversionStatus int

// StatusConverted, StatusUnchanged, StatusFailed, and StatusOrphan enumerate the possible outcomes of a single CertPair conversion.
const (
	StatusConverted ConversionStatus = iota
	StatusUnchanged
	StatusFailed
	StatusOrphan
)

// ConversionResult captures the outcome of converting a single CertPair.
type ConversionResult struct {
	Err     error
	Pair    CertPair
	PFXPath string
	Status  ConversionStatus
}
