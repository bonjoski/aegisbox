package fuzz

import (
	"testing"

	"github.com/bonjoski/aegisbox/pkg/argus"
)

// FuzzLockfileParsers fuzzes all lockfile parsing engines with random byte sequences.
func FuzzLockfileParsers(f *testing.F) {
	f.Add([]byte(`{"packages":{"node_modules/pkg":{"version":"1.0","integrity":"sha512-abc"}}}`))
	f.Add([]byte(`[[package]]\nname = "test"\nversion = "1.0"\nchecksum = "hash"`))
	f.Add([]byte(`golang.org/x/sys v0.1.0 h1:hash=`))
	f.Add([]byte(``))
	f.Add([]byte{0x00, 0xff, 0xfe, 0x12, 0x34})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must not panic
		_, _ = argus.ParseNpmLock(data)
		_, _ = argus.ParseCargoLock(data)
		_, _ = argus.ParseGoSum(data)
	})
}
