package botdetect

import (
	"slices"
	"testing"
)

func TestMatchesPathBlocklist_PrefixBoundary(t *testing.T) {
	patterns := []string{"/wp"}
	cases := map[string]bool{
		"/wp":        true,
		"/wp/":       true,
		"/wp-admin":  true,
		"/wp/x":      true,
		"/wpxyz":     false, // boundary: 'x' continues the token
		"/blog/wp/1": false, // prefix only — mid-path not matched
	}
	for path, want := range cases {
		if got := MatchesPathBlocklist(path, patterns); got != want {
			t.Errorf("MatchesPathBlocklist(%q, [/wp]) = %v, want %v", path, got, want)
		}
	}
}

func TestMatchesPathBlocklist_BareSegment(t *testing.T) {
	patterns := []string{"wp"}
	cases := map[string]bool{
		"/wp":        true,
		"/wp/login":  true,
		"/a/wp/b":    true,
		"/newspaper": false, // segment must match whole
		"/wp-admin":  false, // segment is "wp-admin", not "wp"
	}
	for path, want := range cases {
		if got := MatchesPathBlocklist(path, patterns); got != want {
			t.Errorf("MatchesPathBlocklist(%q, [wp]) = %v, want %v", path, got, want)
		}
	}
}

func TestMatchesPathBlocklist_Substring(t *testing.T) {
	patterns := []string{"cgi-bin", "config.json"}
	cases := map[string]bool{
		"/cgi-bin/test":        true,
		"/x/cgi-bin/y":         true,
		"/app/config.json":     true,
		"/app/config.jsons":    true, // substring — variant suffixes still match
		"/app/config.json.bak": true,
		"/config.xml":          false,
	}
	for path, want := range cases {
		if got := MatchesPathBlocklist(path, patterns); got != want {
			t.Errorf("MatchesPathBlocklist(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestMatchesPathBlocklist_CaseInsensitive(t *testing.T) {
	if !MatchesPathBlocklist("/WP-admin/setup.php", DefaultPathBlocklist()) {
		t.Error("expected case-insensitive match on /WP-admin")
	}
	if !MatchesPathBlocklist("/.DS_Store", DefaultPathBlocklist()) {
		t.Error("expected .ds_store token to match /.DS_Store")
	}
}

// The boundary rules fix the classic rtr false positive: "/new" must
// not jail a real /news route (and "/old" must not jail "/older").
func TestMatchesPathBlocklist_NoNewsFalsePositive(t *testing.T) {
	list := DefaultPathBlocklist()
	for _, path := range []string{"/news", "/news/latest", "/newspaper", "/older-posts", "/maintenance-guide"} {
		if MatchesPathBlocklist(path, list) {
			t.Errorf("false positive: %q matched default blocklist", path)
		}
	}
	// But the probes themselves still match.
	for _, path := range []string{"/new", "/new.tar.gz", "/old", "/main", "/backup/site.zip", "/wp-login.php", "/.env", "/.git/config"} {
		if !MatchesPathBlocklist(path, list) {
			t.Errorf("missed probe: %q should match default blocklist", path)
		}
	}
}

func TestDefaultPathBlocklist_ReturnsFreshCopy(t *testing.T) {
	a := DefaultPathBlocklist()
	b := DefaultPathBlocklist()
	if len(a) == 0 || len(a) != len(b) {
		t.Fatalf("unexpected lengths %d vs %d", len(a), len(b))
	}
	a[0] = "mutated"
	if b[0] == "mutated" || stackPathBlocklist[0] == "mutated" {
		t.Error("DefaultPathBlocklist must return an independent copy")
	}
}

func TestMatchesPathBlocklist_Empty(t *testing.T) {
	if MatchesPathBlocklist("", []string{"/wp"}) {
		t.Error("empty path must not match")
	}
	if MatchesPathBlocklist("/wp", nil) {
		t.Error("nil patterns must not match")
	}
	if MatchesPathBlocklist("/wp", []string{""}) {
		t.Error("empty pattern must not match")
	}
}

// Every default token should match at least one representative path —
// guards against dead entries after edits.
func TestDefaultPathBlocklist_EachTokenMatches(t *testing.T) {
	list := DefaultPathBlocklist()
	for _, token := range list {
		probe := token
		if !slices.ContainsFunc([]rune(token), func(r rune) bool { return r == '/' }) {
			probe = "/x/" + token // bare segment needs a real segment
		}
		if !MatchesPathBlocklist(probe, []string{token}) {
			t.Errorf("token %q does not match its own probe %q", token, probe)
		}
	}
}
