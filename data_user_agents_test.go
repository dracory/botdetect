package botdetect

import "testing"

func TestUserAgentPatternsAreLowercaseAndUnique(t *testing.T) {
	checkLowerUnique(t, "botUserAgentBroadPatterns", botUserAgentBroadPatterns)
	checkLowerUnique(t, "botUserAgentSpecificPatterns", botUserAgentSpecificPatterns)
}
