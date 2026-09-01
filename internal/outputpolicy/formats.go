package outputpolicy

import (
	"slices"
	"strings"
)

// Format names one artifact family a conversion emits.
type Format string

// The two output formats.
const (
	// FormatPFX emits the PKCS#12 bundle, <stem>.pfx.
	FormatPFX Format = "pfx"
	// FormatPEM emits the PEM pair, <stem>.crt and <stem>.key. The key file is a
	// plaintext private key, which is why this format is opt-in.
	FormatPEM Format = "pem"
)

// formatNames is the accepted OUTPUT_FORMATS value domain, stated ONCE, for the
// same one-sided-edit reason lifecycleModes records.
var formatNames = [...]Format{FormatPFX, FormatPEM}

// Formats is the set of output families one scan produces.
type Formats struct {
	PFX bool
	PEM bool
}

// DefaultFormats is the unset-value behavior: PFX only, exactly what every
// deployment produced before OUTPUT_FORMATS existed.
func DefaultFormats() Formats { return Formats{PFX: true} }

// ParseFormats normalises a raw OUTPUT_FORMATS value: a comma-separated subset of
// the format names, case-insensitive, duplicates folded. It returns the parsed set
// and the tokens it rejected; when no accepted token remains it returns the
// default so a typo can never leave a scan producing nothing.
func ParseFormats(raw string) (formats Formats, rejected []string) {
	formats, rejected, _ = parseFormats(raw)
	return formats, rejected
}

// FormatsExplicit reports whether raw contains at least one accepted format.
// Lifecycle cleanup uses it to distinguish a legacy unset default from an
// operator who deliberately changed the desired format set.
func FormatsExplicit(raw string) bool {
	_, _, explicit := parseFormats(raw)
	return explicit
}

func parseFormats(raw string) (formats Formats, rejected []string, explicit bool) {
	if strings.TrimSpace(raw) == "" {
		return DefaultFormats(), nil, false
	}
	for token := range strings.SplitSeq(raw, ",") {
		token = strings.TrimSpace(token)
		switch Format(strings.ToLower(token)) {
		case FormatPFX:
			formats.PFX = true
			explicit = true
		case FormatPEM:
			formats.PEM = true
			explicit = true
		case "":
			// "pfx,,pem" carries no intent in the empty slot; nothing to reject.
		default:
			rejected = append(rejected, token)
		}
	}
	if !formats.PFX && !formats.PEM {
		return DefaultFormats(), rejected, false
	}
	return formats, rejected, explicit
}

// Names returns the enabled format names, in the domain's order.
func (f Formats) Names() []string {
	names := make([]string, 0, len(formatNames))
	for _, name := range formatNames {
		if (name == FormatPFX && f.PFX) || (name == FormatPEM && f.PEM) {
			names = append(names, string(name))
		}
	}
	return names
}

// FormatNames returns the accepted OUTPUT_FORMATS values, for the caller that
// read the environment variable to name in its warning.
func FormatNames() []Format {
	return slices.Clone(formatNames[:])
}

// Layout decides where an artifact lands under /output relative to its source's
// place under /input.
type Layout string

// The two layout modes.
const (
	// LayoutMirror reproduces the source's whole relative path.
	LayoutMirror Layout = "mirror"
	// LayoutFlat keeps only the source's own directory name, so consumers
	// reference issuer-independent paths. The default: certificate exporters
	// conventionally key output on the certificate identity, not on the issuing
	// store's internal layout.
	LayoutFlat Layout = "flat"
)

// layoutModes is the accepted OUTPUT_LAYOUT value domain, stated ONCE.
var layoutModes = [...]Layout{LayoutMirror, LayoutFlat}

// DefaultLayout is the unset-value behavior.
func DefaultLayout() Layout { return LayoutFlat }

// ParseLayout normalises a raw OUTPUT_LAYOUT value. The second result reports
// whether raw itself named a mode: an unset value resolves to the default
// without being "unknown", while an unrecognised one falls back to the default
// AND reports false so the caller can warn and disarm destructive cleanup.
func ParseLayout(raw string) (mode Layout, known bool) {
	normalized := Layout(strings.ToLower(strings.TrimSpace(raw)))
	if normalized == "" {
		return DefaultLayout(), true // unset means the default, not an unrecognised value
	}
	if slices.Contains(layoutModes[:], normalized) {
		return normalized, true
	}
	return DefaultLayout(), false
}

// LayoutExplicit reports whether raw names a recognised layout mode, so
// lifecycle cleanup can distinguish the unset default from an operator who
// deliberately selected a layout.
func LayoutExplicit(raw string) bool {
	normalized := Layout(strings.ToLower(strings.TrimSpace(raw)))
	return normalized != "" && slices.Contains(layoutModes[:], normalized)
}

// LayoutModes returns the accepted OUTPUT_LAYOUT values.
func LayoutModes() []Layout {
	return slices.Clone(layoutModes[:])
}
