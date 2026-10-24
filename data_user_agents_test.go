package botdetect

import (
	"strings"
	"testing"
)

func TestUserAgentPatternsAreLowercaseAndUnique(t *testing.T) {
	checkLowerUnique(t, "botUserAgentBroadPatterns", botUserAgentBroadPatterns)
}

func TestBotClassificationsAreValidAndUnshadowed(t *testing.T) {
	validClasses := map[BotClass]bool{
		ClassSearch:  true,
		ClassSocial:  true,
		ClassAI:      true,
		ClassAIUser:  true,
		ClassSEOTool: true,
		ClassMonitor: true,
		ClassScraper: true,
		ClassScanner: true,
		ClassOther:   true,
	}

	tokens := make([]string, 0, len(botClassifications))
	for i, c := range botClassifications {
		tokens = append(tokens, c.token)
		if c.name == "" || c.name != strings.ToLower(c.name) {
			t.Errorf("botClassifications[%d] (%q): name %q must be non-empty lowercase", i, c.token, c.name)
		}
		if !validClasses[c.class] {
			t.Errorf("botClassifications[%d] (%q): invalid class %q", i, c.token, c.class)
		}
		for j := 0; j < i; j++ {
			earlier := botClassifications[j].token
			if earlier != "" && strings.Contains(c.token, earlier) {
				t.Errorf("botClassifications[%d] token %q is shadowed by earlier botClassifications[%d] token %q", i, c.token, j, earlier)
			}
		}
	}
	checkLowerUnique(t, "botClassifications.token", tokens)
}
