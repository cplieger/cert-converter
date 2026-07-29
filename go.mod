module github.com/cplieger/cert-converter

go 1.26.5

require (
	github.com/cplieger/atomicfile/v2 v2.4.0
	github.com/cplieger/envx v1.4.0
	github.com/cplieger/health v1.4.0
	github.com/cplieger/runesafe v1.2.1
	github.com/cplieger/slogx v1.4.0
	github.com/fsnotify/fsnotify v1.10.1
	pgregory.net/rapid v1.3.0
	software.sslmate.com/src/go-pkcs12 v0.7.3
)

require (
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

// LOCAL WIRING ONLY - MUST NOT BE MERGED.
// cert-converter adopts primitives added to these libraries in the same review
// (runesafe cap-and-mark, atomicfile ProbeWritable). Drop both lines and bump
// the pinned versions once runesafe and atomicfile release.
replace github.com/cplieger/runesafe => ../runesafe

replace github.com/cplieger/atomicfile/v2 => ../atomicfile
