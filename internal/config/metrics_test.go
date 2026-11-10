package config

import "testing"

// TestLoad_trims_invisible_edges_of_METRICS_LISTEN_ADDR pins the one permitted
// normalisation of the bind address: edge whitespace and invisible runes go, so
// " :9468" binds :9468 instead of crash-looping on a host name lookup, and an
// unset or blank value opens no listener.
func TestLoad_trims_invisible_edges_of_METRICS_LISTEN_ADDR(t *testing.T) {
	for _, tc := range []struct {
		name, raw, want string
	}{
		{name: "unset", raw: "", want: ""},
		{name: "blank", raw: " \t", want: ""},
		{name: "leading space", raw: " :9468", want: ":9468"},
		{name: "zero-width edges", raw: "\u200b127.0.0.1:9468\ufeff\n", want: "127.0.0.1:9468"},
		{name: "inner bytes kept", raw: "host name:9468", want: "host name:9468"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PFX_PASSWORD", "pw")
			t.Setenv("METRICS_LISTEN_ADDR", tc.raw)
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load = %v", err)
			}
			if cfg.MetricsListenAddr != tc.want {
				t.Errorf("METRICS_LISTEN_ADDR=%q loaded as %q, want %q", tc.raw, cfg.MetricsListenAddr, tc.want)
			}
		})
	}
}
