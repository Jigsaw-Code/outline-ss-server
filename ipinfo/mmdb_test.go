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
	"net"
	"os"
	"testing"

	"github.com/oschwald/geoip2-golang"
	"github.com/stretchr/testify/require"
)

func ensureTestData(tb testing.TB, dbPath string) {
	_, err := os.Stat(dbPath)
	if os.IsNotExist(err) {
		tb.Skip("Test MMDB not found. Run git submodule update --init --depth=1")
	}
	require.NoError(tb, err)
}

func TestIPInfoMap(t *testing.T) {
	// The test data is in a git submodule that must be initialized before running the test.
	dbPath := "../third_party/maxmind/test-data/GeoLite2-Country-Test.mmdb"
	ensureTestData(t, dbPath)
	ipCountryDB, err := geoip2.Open(dbPath)
	require.NoError(t, err, "Could not open geoip database at %v: %v", dbPath, err)
	defer ipCountryDB.Close()
	ip2info := NewMMDBIPInfoMap(ipCountryDB)

	info, err := ip2info.GetIPInfo(net.ParseIP("217.65.48.1"))
	require.NoError(t, err)
	require.Equal(t, IPInfo{CountryCode: "GI"}, info)

	info, err = ip2info.GetIPInfo(net.ParseIP("127.0.0.1"))
	require.NoError(t, err)
	require.Equal(t, IPInfo{CountryCode: ""}, info)

	info, err = ip2info.GetIPInfo(net.ParseIP("2001:250::"))
	require.NoError(t, err)
	require.Equal(t, IPInfo{CountryCode: "CN"}, info)
}

func BenchmarkNewMMDBIPInfoMap(b *testing.B) {
	// The test data is in a git submodule that must be initialized before running the test.
	dbPath := "../third_party/maxmind/test-data/GeoLite2-Country-Test.mmdb"
	ensureTestData(b, dbPath)
	ipCountryDB, err := geoip2.Open(dbPath)
	require.NoError(b, err, "Could not open geoip database at %v: %v", dbPath, err)
	defer ipCountryDB.Close()
	ip2info := NewMMDBIPInfoMap(ipCountryDB)

	// testIP := net.ParseIP("127.0.0.1")
	testIP := net.ParseIP("217.65.48.1")
	b.ResetTimer()
	// Repeatedly check the country for the same address.  This is realistic, because
	// servers call this method for each new connection, but typically many connections
	// come from a single user in succession.
	for i := 0; i < b.N; i++ {
		ip2info.GetIPInfo(testIP)
	}
}
