package service

import (
	"fmt"
	"net"
)

var privateNetworks []*net.IPNet

func init() {
	for _, cidr := range []string{
		// RFC 1918: private IPv4 networks
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		// RFC 4193: IPv6 ULAs
		"fc00::/7",
		// RFC 6598: reserved prefix for CGNAT
		"100.64.0.0/10",
	} {
		_, subnet, _ := net.ParseCIDR(cidr)
		privateNetworks = append(privateNetworks, subnet)
	}
}

// IsPrivateAddress returns whether an IP address belongs to the LAN.
func IsPrivateAddress(ip net.IP) bool {
	for _, network := range privateNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// TargetIPValidator is a type alias for checking if an IP is allowed.
type TargetIPValidator = func(net.IP) *ConnectionError

// RequirePublicIP returns an error if the destination IP is not a
// standard public IP.
func RequirePublicIP(ip net.IP) *ConnectionError {
	if !ip.IsGlobalUnicast() {
		return NewConnectionError("ERR_ADDRESS_INVALID", fmt.Sprintf("Address is not global unicast: %s", ip.String()), nil)
	}
	if IsPrivateAddress(ip) {
		return NewConnectionError("ERR_ADDRESS_PRIVATE", fmt.Sprintf("Address is private: %s", ip.String()), nil)
	}
	return nil
}
