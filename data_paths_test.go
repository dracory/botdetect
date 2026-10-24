package botdetect

import "testing"

func TestPathPatternsAreLowercaseAndUnique(t *testing.T) {
	checkLowerUnique(t, "botPathPatterns", botPathPatterns)
	checkLowerUnique(t, "maliciousPathPatterns", maliciousPathPatterns)
}
