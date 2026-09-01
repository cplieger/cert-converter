package config

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/cplieger/cert-converter/internal/outputpolicy"
	"github.com/cplieger/slogx/capture"
)

func TestLoad_wiresOutputFormatsAndLayout(t *testing.T) {
	for _, tc := range []struct {
		name               string
		formats            string
		layout             string
		lifecycle          string
		wantFormats        outputpolicy.Formats
		wantExplicit       bool
		wantLayout         outputpolicy.Layout
		wantLayoutExplicit bool
		wantLifecycle      outputpolicy.Lifecycle
		wantWarning        string
	}{
		{
			name: "unset defaults to pfx flat warn", wantFormats: outputpolicy.Formats{PFX: true},
			wantLayout: outputpolicy.LayoutFlat, wantLifecycle: outputpolicy.LifecycleWarn,
		},
		{
			name: "full matrix in mirror layout", formats: "pfx,pem", layout: "mirror", lifecycle: "sync",
			wantFormats: outputpolicy.Formats{PFX: true, PEM: true}, wantExplicit: true, wantLayout: outputpolicy.LayoutMirror,
			wantLayoutExplicit: true, wantLifecycle: outputpolicy.LifecycleSync,
		},
		{
			name: "pem only in flat layout", formats: "pem", layout: "flat", lifecycle: "warn",
			wantFormats: outputpolicy.Formats{PEM: true}, wantExplicit: true, wantLayout: outputpolicy.LayoutFlat,
			wantLayoutExplicit: true, wantLifecycle: outputpolicy.LifecycleWarn,
		},
		{
			name: "flat sync stays sync", layout: "flat", lifecycle: "sync",
			wantFormats: outputpolicy.Formats{PFX: true}, wantLayout: outputpolicy.LayoutFlat,
			wantLayoutExplicit: true, wantLifecycle: outputpolicy.LifecycleSync,
		},
		{
			name: "unknown formats are ignored", formats: "jks,pem", wantFormats: outputpolicy.Formats{PEM: true},
			wantLayout: outputpolicy.LayoutFlat, wantLifecycle: outputpolicy.LifecycleWarn,
			wantWarning: "OUTPUT_FORMATS contains unrecognized formats",
		},
		{
			name: "unknown layout falls back to the default", layout: "tree", wantFormats: outputpolicy.Formats{PFX: true},
			wantLayout: outputpolicy.LayoutFlat, wantLifecycle: outputpolicy.LifecycleWarn,
			wantWarning: "unknown OUTPUT_LAYOUT",
		},
		{
			name: "unknown formats disable sync cleanup", formats: "pfx,pme", lifecycle: "sync",
			wantFormats: outputpolicy.Formats{PFX: true}, wantLayout: outputpolicy.LayoutFlat,
			wantLifecycle: outputpolicy.LifecycleWarn,
			wantWarning:   "OUTPUT_LIFECYCLE=sync is disabled because OUTPUT_FORMATS is invalid",
		},
		{
			name: "unknown layout disables sync cleanup", formats: "pfx", layout: "flta", lifecycle: "sync",
			wantFormats: outputpolicy.Formats{PFX: true}, wantExplicit: true, wantLayout: outputpolicy.LayoutFlat,
			wantLifecycle: outputpolicy.LifecycleWarn,
			wantWarning:   "unknown OUTPUT_LAYOUT",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateFormatConfig(t)
			t.Setenv("OUTPUT_FORMATS", tc.formats)
			t.Setenv("OUTPUT_LAYOUT", tc.layout)
			t.Setenv("OUTPUT_LIFECYCLE", tc.lifecycle)
			logs := capture.Default(t)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() = %v, want nil", err)
			}
			if cfg.Formats != tc.wantFormats {
				t.Errorf("Load() Formats = %+v, want %+v", cfg.Formats, tc.wantFormats)
			}
			if cfg.FormatsExplicit != tc.wantExplicit {
				t.Errorf("Load() FormatsExplicit = %v, want %v", cfg.FormatsExplicit, tc.wantExplicit)
			}
			if cfg.Layout != tc.wantLayout {
				t.Errorf("Load() Layout = %q, want %q", cfg.Layout, tc.wantLayout)
			}
			if cfg.LayoutExplicit != tc.wantLayoutExplicit {
				t.Errorf("Load() LayoutExplicit = %v, want %v", cfg.LayoutExplicit, tc.wantLayoutExplicit)
			}
			if cfg.Lifecycle != tc.wantLifecycle {
				t.Errorf("Load() Lifecycle = %q, want %q", cfg.Lifecycle, tc.wantLifecycle)
			}
			if tc.wantWarning == "" {
				return
			}
			if count := logs.CountLevel(slog.LevelWarn, tc.wantWarning); count != 1 {
				t.Errorf("Load() logged %q %d times, want 1 (logs %v)", tc.wantWarning, count, logs.Messages())
			}
		})
	}
}

func TestLoad_wiresInputExcludePaths(t *testing.T) {
	for _, tc := range []struct {
		name        string
		raw         string
		wantPaths   []string
		wantExclude []string
		wantKeep    []string
		wantWarning string
	}{
		{name: "unset excludes nothing", wantKeep: []string{"clients/identity.crt"}},
		{
			name: "a directory covers what is beneath it", raw: "clients",
			wantPaths:   []string{"clients"},
			wantExclude: []string{"clients", "clients/identity.crt", "clients/eu/a.pfx"},
			wantKeep:    []string{"server/site.crt", "clientsx/site.crt"},
		},
		{
			name: "entries are trimmed, cleaned, deduplicated and sorted", raw: " z/ , ./a , a ,, m/n ",
			wantPaths:   []string{"a", "m/n", "z"},
			wantExclude: []string{"a/x.crt", "m/n/x.crt", "z/x.crt"},
			wantKeep:    []string{"b/x.crt"},
		},
		{
			name: "an absolute entry is refused", raw: "/etc/ssl,clients",
			wantPaths:   []string{"clients"},
			wantExclude: []string{"clients/identity.crt"},
			wantKeep:    []string{"etc/ssl/site.crt"},
			wantWarning: "INPUT_EXCLUDE_PATHS contains entries that are not usable relative paths",
		},
		{
			name: "a traversing entry is refused", raw: "../outside,clients/eu",
			wantPaths:   []string{"clients/eu"},
			wantExclude: []string{"clients/eu/identity.crt"},
			wantKeep:    []string{"clients/us/identity.crt"},
			wantWarning: "INPUT_EXCLUDE_PATHS contains entries that are not usable relative paths",
		},
		{
			name: "a self-referential entry is refused rather than excluding the whole tree", raw: ".",
			wantKeep:    []string{"server/site.crt"},
			wantWarning: "INPUT_EXCLUDE_PATHS contains entries that are not usable relative paths",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateFormatConfig(t)
			t.Setenv("INPUT_EXCLUDE_PATHS", tc.raw)
			logs := capture.Default(t)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() = %v, want nil", err)
			}
			if got := cfg.Exclude.Paths(); !slices.Equal(got, tc.wantPaths) {
				t.Errorf("Load() Exclude.Paths() = %v, want %v", got, tc.wantPaths)
			}
			for _, rel := range tc.wantExclude {
				if !cfg.Exclude.Excludes(rel) {
					t.Errorf("Load(INPUT_EXCLUDE_PATHS=%q) Exclude.Excludes(%q) = false, want true", tc.raw, rel)
				}
			}
			for _, rel := range tc.wantKeep {
				if cfg.Exclude.Excludes(rel) {
					t.Errorf("Load(INPUT_EXCLUDE_PATHS=%q) Exclude.Excludes(%q) = true, want false", tc.raw, rel)
				}
			}
			if tc.wantWarning == "" {
				return
			}
			if count := logs.CountLevel(slog.LevelWarn, tc.wantWarning); count != 1 {
				t.Errorf("Load() logged %q %d times, want 1 (logs %v)", tc.wantWarning, count, logs.Messages())
			}
		})
	}
}

func TestLoad_wiresInputBundlePassword(t *testing.T) {
	for _, tc := range []struct {
		name      string
		env       string
		fileBytes []byte
		want      string
		wantReady bool
	}{
		{name: "unset leaves bundle input disabled"},
		{name: "environment value is verbatim", env: " input secret ", want: " input secret ", wantReady: true},
		{name: "file wins and loses one trailing newline", env: "ignored", fileBytes: []byte("from-file\n"), want: "from-file", wantReady: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateFormatConfig(t)
			if tc.env != "" {
				t.Setenv("INPUT_PFX_PASSWORD", tc.env)
			}
			if tc.fileBytes != nil {
				file := filepath.Join(t.TempDir(), "input-pfx-password")
				if err := os.WriteFile(file, tc.fileBytes, 0o600); err != nil {
					t.Fatalf("setup: write input password file: %v", err)
				}
				t.Setenv("INPUT_PFX_PASSWORD_FILE", file)
			}

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() = %v, want nil", err)
			}
			if cfg.InputPassword != tc.want {
				t.Errorf("Load() InputPassword = %q, want %q", cfg.InputPassword, tc.want)
			}
			if cfg.InputPasswordReady != tc.wantReady {
				t.Errorf("Load() InputPasswordReady = %v, want %v", cfg.InputPasswordReady, tc.wantReady)
			}
		})
	}
}

func TestLoad_refusesUnusableInputBundlePassword(t *testing.T) {
	for _, tc := range []struct {
		name  string
		env   string
		file  string
		cause error
	}{
		{name: "missing secret file", file: filepath.Join(t.TempDir(), "absent")},
		{name: "explicit blank environment password", env: "", cause: ErrEmptyInputPassword},
		{name: "unencodable environment password", env: "supplementary \U0001F600", cause: ErrUnencodablePassword},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateFormatConfig(t)
			t.Setenv("INPUT_PFX_PASSWORD", tc.env)
			if tc.file != "" {
				t.Setenv("INPUT_PFX_PASSWORD_FILE", tc.file)
			}
			_, err := Load()
			if err == nil {
				t.Fatal("Load() = nil error, want input password refusal")
			}
			if tc.cause != nil && !errors.Is(err, tc.cause) {
				t.Errorf("Load() error = %v, want errors.Is(..., %v)", err, tc.cause)
			}
		})
	}
}

// isolateFormatConfig prevents the host environment from supplying either secret
// file and gives the required OUTPUT PFX channel one stable value.
func isolateFormatConfig(t *testing.T) {
	t.Helper()
	unsetEnv(t, "PFX_PASSWORD_FILE")
	unsetEnv(t, "INPUT_PFX_PASSWORD_FILE")
	t.Setenv("PFX_PASSWORD", "output-password")
	t.Setenv("PFX_ALLOW_EMPTY_PASSWORD", "false")
	t.Setenv("PFX_ENCODER", "modern2023")
	t.Setenv("FALLBACK_SCAN_HOURS", "6")
	t.Setenv("MAX_SCAN_ENTRIES", "10000")
	unsetEnv(t, "INPUT_PFX_PASSWORD")
	unsetEnv(t, "INPUT_EXCLUDE_PATHS")
}

func unsetEnv(t *testing.T, name string) {
	t.Helper()
	prior, existed := os.LookupEnv(name)
	if err := os.Unsetenv(name); err != nil {
		t.Fatalf("setup: unset %s: %v", name, err)
	}
	t.Cleanup(func() {
		if existed {
			_ = os.Setenv(name, prior)
			return
		}
		_ = os.Unsetenv(name)
	})
}

func TestLoad_refusesBlankInputPasswordFile(t *testing.T) {
	isolateFormatConfig(t)
	file := filepath.Join(t.TempDir(), "input-password")
	if err := os.WriteFile(file, []byte("\n"), 0o600); err != nil {
		t.Fatalf("setup: write blank input password file: %v", err)
	}
	t.Setenv("INPUT_PFX_PASSWORD_FILE", file)

	_, err := Load()
	if !errors.Is(err, ErrEmptyInputPassword) {
		t.Errorf("Load(blank INPUT_PFX_PASSWORD_FILE) = %v, want ErrEmptyInputPassword", err)
	}
}
