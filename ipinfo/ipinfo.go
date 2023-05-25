// Copyright 2023 Jigsaw Operations LLC
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

package ipinfo

import (
	"errors"
	"fmt"
	"net"
)

type IPInfoMap interface {
	GetIPInfo(net.IP) (IPInfo, error)
}

type IPInfo struct {
	CountryCode CountryCode
	ASN         int
}

type CountryCode string

func (cc CountryCode) String() string {
	return string(cc)
}

const (
	errParseAddr     CountryCode = "XA"
	localLocation    CountryCode = "XL"
	errDbLookupError CountryCode = "XD"
	unknownLocation  CountryCode = "ZZ"
)

// GetIPInfoFromAddr is a helper function to extract the IP address from the [net.Addr]
// and call [IPInfoMap].GetIPInfo.
// It uses special country codes to indicate errors:
// - "XA": failed to extract the IP from the address
// - "XL": IP is not global.
// - "XD": error lookip up the country code
// - "ZZ": lookup returned an empty country code.
func GetIPInfoFromAddr(ip2info IPInfoMap, addr net.Addr) (IPInfo, error) {
	var info IPInfo
	if ip2info == nil {
		// Location is disabled. return empty info.
		return info, nil
	}

	hostname, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		info.CountryCode = errParseAddr
		return info, fmt.Errorf("failed to split hostname and port: %w", err)
	}
	ip := net.ParseIP(hostname)
	if ip == nil {
		info.CountryCode = errParseAddr
		return info, errors.New("failed to parse address as IP")
	}

	if ip.IsLoopback() || ip.IsGlobalUnicast() {
		info.CountryCode = localLocation
		return info, nil
	}
	info, err = ip2info.GetIPInfo(ip)
	if err != nil {
		info.CountryCode = errDbLookupError
	}
	if info.CountryCode == "" {
		info.CountryCode = unknownLocation
	}
	return info, err
}
