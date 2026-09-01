package config

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/cplieger/cert-converter/internal/outputpolicy"
	"github.com/cplieger/envx/v2"
)

// resolveFormats reads OUTPUT_FORMATS and reports every token the parser had to
// reject.
func resolveFormats() (formats outputpolicy.Formats, explicit, valid bool) {
	raw := os.Getenv("OUTPUT_FORMATS")
	formats, rejected := outputpolicy.ParseFormats(raw)
	valid = len(rejected) == 0
	if !valid {
		slog.Warn("OUTPUT_FORMATS contains unrecognized formats; ignoring them",
			"rejected", rejectedValue(strings.Join(rejected, ",")),
			"using", strings.Join(formats.Names(), ","),
			"expected", outputpolicy.FormatNames())
	}
	explicit = valid && outputpolicy.FormatsExplicit(raw)
	return formats, explicit, valid
}

// resolveLayout reads OUTPUT_LAYOUT. An unrecognised value falls back to the
// default layout and forces the non-deleting lifecycle: a scan must never
// delete under a layout the operator did not choose.
func resolveLayout(lifecycle outputpolicy.Lifecycle) (outputpolicy.Layout, bool, outputpolicy.Lifecycle) {
	raw := os.Getenv("OUTPUT_LAYOUT")
	layoutMode, known := outputpolicy.ParseLayout(raw)
	if !known {
		slog.Warn("unknown OUTPUT_LAYOUT, using the default layout with report-only lifecycle",
			"value", rejectedValue(raw), "using", string(layoutMode), "expected", outputpolicy.LayoutModes())
		lifecycle = outputpolicy.LifecycleWarn
	}
	return layoutMode, outputpolicy.LayoutExplicit(raw), lifecycle
}

// ErrEmptyInputPassword reports an explicitly configured blank input-bundle
// password without the opt-in that acknowledges empty-password PFX decoding.
var ErrEmptyInputPassword = errors.New("the configured input PFX password is empty or blank; set INPUT_PFX_PASSWORD or write a non-blank secret to INPUT_PFX_PASSWORD_FILE")

type resolvedInputPassword struct {
	Value string
	Ready bool
}

// resolveInputPassword resolves the password used to DECODE PKCS#12 input
// bundles. An unset password leaves bundle input disabled while PEM conversion
// remains available. A configured password must be non-blank: go-pkcs12 verifies
// the bundle MAC before parsing certificates and keys, so that secret is the
// trust boundary around parser work the dependency cannot preflight itself.
func resolveInputPassword() (resolvedInputPassword, error) {
	warnBlankInputPasswordFilePointer()
	password, source, secretErr := envx.SecretWithSource("INPUT_PFX_PASSWORD")
	warnBothInputPasswordChannels(source)
	_, envSet := os.LookupEnv("INPUT_PFX_PASSWORD")
	configured := envSet || source == envx.SourceFile
	var blankSecretFile error
	if secretErr != nil {
		var missing *envx.MissingError
		switch {
		case errors.As(secretErr, &missing):
			password = ""
			configured = envSet
		case errors.Is(secretErr, envx.ErrBlankSecretFile):
			password, blankSecretFile = "", secretErr
			configured = true
		default:
			return resolvedInputPassword{}, secretErr
		}
	}
	status := classifyPassword(password)
	if encErr := checkPasswordEncodable(password); encErr != nil {
		return resolvedInputPassword{}, fmt.Errorf("%w (supplied via %s)", encErr, inputPasswordChannel(source))
	}
	if status != PasswordConfigured {
		if !configured {
			return resolvedInputPassword{}, nil
		}
		if blankSecretFile != nil {
			return resolvedInputPassword{}, fmt.Errorf("%w: %w", ErrEmptyInputPassword, blankSecretFile)
		}
		return resolvedInputPassword{}, ErrEmptyInputPassword
	}
	if source == envx.SourceFile {
		slog.Info("input bundle password configured", "source", inputPasswordChannel(source))
	}
	return resolvedInputPassword{Value: password, Ready: true}, nil
}

// warnBothInputPasswordChannels mirrors warnBothPasswordChannels for the input
// channel pair.
func warnBothInputPasswordChannels(source envx.SecretSource) {
	if source != envx.SourceFile || os.Getenv("INPUT_PFX_PASSWORD") == "" {
		return
	}
	slog.Warn("both INPUT_PFX_PASSWORD and INPUT_PFX_PASSWORD_FILE are set; the file wins and INPUT_PFX_PASSWORD is ignored",
		"source", inputPasswordChannel(source),
		"remediation", "remove INPUT_PFX_PASSWORD from the environment so there is one place to change the secret")
}

// warnBlankInputPasswordFilePointer mirrors warnBlankPasswordFilePointer for the
// input channel.
func warnBlankInputPasswordFilePointer() {
	if !envx.IsBlankSecretFilePath("INPUT_PFX_PASSWORD") {
		return
	}
	outcome := "the input bundle password is taken from INPUT_PFX_PASSWORD instead"
	if os.Getenv("INPUT_PFX_PASSWORD_FILE") != "" {
		outcome = "the whitespace value is treated as a filename instead of falling back to INPUT_PFX_PASSWORD"
	}
	slog.Warn("INPUT_PFX_PASSWORD_FILE is set but blank; "+outcome,
		"remediation", "unset INPUT_PFX_PASSWORD_FILE to configure the secret through INPUT_PFX_PASSWORD, "+
			"or point it at the mounted secret file")
}

// inputPasswordChannel names the variable an operator must edit to change the
// input bundle password.
func inputPasswordChannel(source envx.SecretSource) string {
	if source == envx.SourceFile {
		return "INPUT_PFX_PASSWORD_FILE"
	}
	return "INPUT_PFX_PASSWORD"
}
