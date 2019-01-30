// Copyright 2019 Jigsaw Operations LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
