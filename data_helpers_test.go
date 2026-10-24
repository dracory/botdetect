package botdetect

import (
	"strings"
	"testing"
)

func checkLowerUnique(t *testing.T, name string, entries []string) {
	t.Helper()
	seen := map[string]bool{}
	for _, e := range entries {
		if e == "" {
			t.Errorf("%s: empty entry", name)
		}
		if e != strings.ToLower(e) {
			t.Errorf("%s: entry %q must be lowercase", name, e)
		}
		if seen[e] {
			t.Errorf("%s: duplicate entry %q", name, e)
		}
		seen[e] = true
	}
}
