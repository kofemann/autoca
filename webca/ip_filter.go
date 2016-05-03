package webca

import (
	"net"
)

// returns trye if ip address matches one from the allowed list
func IpMatch(ip net.IP, allowed []string) bool {

	for _, v := range allowed {
		addr, network, err := net.ParseCIDR(v)
		if err == nil {
			if network != nil && network.Contains(ip) {
				return true
			}
		} else {
			addr = net.ParseIP(v)
			if addr.Equal(ip) {
				return true
			}
		}
	}

	return false
}
