package botdetect

import (
	"net/netip"
	"testing"
)

func TestDataCenterCIDRsAreValidAndUnique(t *testing.T) {
	seen := map[netip.Prefix]bool{}
	for _, c := range dataCenterCIDRs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			t.Errorf("invalid CIDR %q: %v", c, err)
			continue
		}
		if p != p.Masked() {
			t.Errorf("CIDR %q has host bits set (want %s)", c, p.Masked())
		}
		if seen[p] {
			t.Errorf("duplicate CIDR %q", c)
		}
		seen[p] = true
	}
	if len(parsedDataCenterCIDRs) != len(dataCenterCIDRs) {
		t.Errorf("parsed %d of %d CIDRs", len(parsedDataCenterCIDRs), len(dataCenterCIDRs))
	}
}
