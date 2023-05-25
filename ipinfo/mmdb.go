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
	"fmt"
	"net"

	"github.com/oschwald/geoip2-golang"
)

// mmIPInfoMap is a [ipinfo.IPInfoMap] that uses [geoip2.Reader] to read MMDB files.
type mmIPInfoMap struct {
	countryDB *geoip2.Reader
}

// NewMMDBIPInfoMap creates a [ipinfo.IPInfoMap] that uses [geoip2.Reader] to lookup IP information from a MMDB.
func NewMMDBIPInfoMap(countryDB *geoip2.Reader) IPInfoMap {
	return &mmIPInfoMap{countryDB}
}

var _ IPInfoMap = (*mmIPInfoMap)(nil)

func (ip2info *mmIPInfoMap) GetIPInfo(ip net.IP) (IPInfo, error) {
	var info IPInfo
	if ip2info == nil || ip2info.countryDB == nil {
		// Location is disabled. return empty info.
		return info, nil
	}
	record, err := ip2info.countryDB.Country(ip)
	if err != nil {
		info.CountryCode = errDbLookupError
		return info, fmt.Errorf("IP lookup failed: %w", err)
	}
	if record != nil && record.Country.IsoCode != "" {
		info.CountryCode = CountryCode(record.Country.IsoCode)
	}
	return info, nil
}
