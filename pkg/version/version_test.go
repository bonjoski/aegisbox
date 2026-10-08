package version_test

import (
	"strings"
	"testing"

	"github.com/bonjoski/aegisbox/pkg/version"
)

func TestVersion_Format(t *testing.T) {
	if version.Current == "" {
		t.Fatal("expected non-empty version.Current")
	}
	if version.Version != version.Current {
		t.Errorf("expected Version to match Current by default, got %s vs %s", version.Version, version.Current)
	}

	full := version.Full()
	if !strings.Contains(full, version.Current) {
		t.Errorf("expected full version string to contain %s, got: %s", version.Current, full)
	}
}
