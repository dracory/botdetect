package botdetect

import "testing"

func TestReferrerSpamDomainsAreLowercase(t *testing.T) {
	domains := make([]string, 0, len(referrerSpamDomains))
	for d := range referrerSpamDomains {
		domains = append(domains, d)
	}
	checkLowerUnique(t, "referrerSpamDomains", domains)
}
