package webca

import (
	"net"
)

// returns trye if ip address matches one from the allowed list
func IpMatch(ip net.IP, allowed []string) bool {

	for i := range allowed {
		addr, network, err := net.ParseCIDR(allowed[i])
		if err == nil {
			if network != nil && network.Contains(ip) {
				return true
			}
		} else {
			addr = net.ParseIP(allowed[i])
			if addr.Equal(ip) {
				return true
			}
		}
	}

	return false
}
