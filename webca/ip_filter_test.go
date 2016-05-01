package webca

import (
	"net"
	"testing"
)

var testIPv4 = net.ParseIP("192.168.17.1")
var testIPv6 = net.ParseIP("fe80::a288:b4ff:fef1:2be8")

var matchingIP4 = []string{
	"192.168.17.1",
	"192.168.17.1/32",
	"192.168.17.0/24",
}

var nonMatchingIP4 = []string{
	"192.168.18.1",
	"192.168.18.1/32",
	"192.168.18.0/24",
}

func TestIpMatcher(t *testing.T) {

	if !IpMatch(testIPv4, matchingIP4) {
		t.Error("test failed: matching not detected")
	}
	if IpMatch(testIPv4, nonMatchingIP4) {
		t.Error("test failed: non matcing not detected")
	}

}
