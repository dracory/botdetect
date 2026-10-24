package botdetect

import (
	"strings"
	"testing"
)

// Data integrity rules for botClassifications — see docs/maintaining-data.md.
func TestBotClassifications_Integrity(t *testing.T) {
	seen := map[string]bool{}
	for i, c := range botClassifications {
		if c.token == "" {
			t.Errorf("entry %d has empty token", i)
		}
		if c.token != strings.ToLower(c.token) {
			t.Errorf("token %q is not lowercase", c.token)
		}
		if c.name == "" {
			t.Errorf("entry %d (%q) has empty name", i, c.token)
		}
		if c.class == "" {
			t.Errorf("entry %d (%q) has empty class", i, c.token)
		}
		if seen[c.token] {
			t.Errorf("duplicate token %q", c.token)
		}
		seen[c.token] = true
	}
}

// Entries are matched linearly via strings.Contains, so an earlier token
// that is a substring of a later one shadows the later entry entirely.
// This check catches ordering bugs like "curl" shadowing "libcurl-agent".
func TestBotClassifications_NoShadowedTokens(t *testing.T) {
	for i, earlier := range botClassifications {
		for j := i + 1; j < len(botClassifications); j++ {
			later := botClassifications[j]
			if strings.Contains(later.token, earlier.token) {
				t.Errorf("token %q (index %d) is a substring of %q (index %d) and shadows it — reorder so the more specific token comes first",
					earlier.token, i, later.token, j)
			}
		}
	}
}
