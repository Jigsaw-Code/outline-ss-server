package shadowsocks

import "net"

var lanSubnets []*net.IPNet

func init() {
	for _, cidr := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7",
	} {
		_, subnet, _ := net.ParseCIDR(cidr)
		lanSubnets = append(lanSubnets, subnet)
	}
}

// IsLanAddress returns whether an IP address belongs to the LAN.
func IsLanAddress(ip net.IP) bool {
	for _, subnet := range lanSubnets {
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}
