// Copyright 2023 Jigsaw Operations LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ipinfo

import (
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

type noopMap struct{}

func (*noopMap) GetIPInfo(ip net.IP) (IPInfo, error) {
	return IPInfo{}, nil
}

type badMap struct{}

func (*badMap) GetIPInfo(ip net.IP) (IPInfo, error) {
	return IPInfo{}, errors.New("bad map")
}

type badAddr struct {
	address string
}

func (a *badAddr) String() string {
	return a.address
}

func (a *badAddr) Network() string {
	return "bad"
}

func TestGetIPInfoFromAddr(t *testing.T) {
	var emptyInfo IPInfo
	noInfoMap := &noopMap{}

	// IP info disabled
	info, err := GetIPInfoFromAddr(nil, nil)
	require.Equal(t, emptyInfo, info)
	require.NoError(t, err)

	// Nil address
	info, err = GetIPInfoFromAddr(noInfoMap, nil)
	require.Error(t, err)
	require.Equal(t, errParseAddr, info.CountryCode)

	// Can't split host:port in address
	info, err = GetIPInfoFromAddr(noInfoMap, &badAddr{"host-no-port"})
	require.Error(t, err)
	require.Equal(t, errParseAddr, info.CountryCode)

	// Host is not an IP
	info, err = GetIPInfoFromAddr(noInfoMap, &badAddr{"host-is-not-ip:port"})
	require.Error(t, err)
	require.Equal(t, errParseAddr, info.CountryCode)

	// Localhost address
	info, err = GetIPInfoFromAddr(noInfoMap, &badAddr{"127.0.0.1:port"})
	require.NoError(t, err)
	require.Equal(t, localLocation, info.CountryCode)

	// Local network address
	info, err = GetIPInfoFromAddr(noInfoMap, &badAddr{"10.0.0.1:port"})
	require.NoError(t, err)
	require.Equal(t, unknownLocation, info.CountryCode)

	// No country found
	info, err = GetIPInfoFromAddr(noInfoMap, &badAddr{"8.8.8.8:port"})
	require.NoError(t, err)
	require.Equal(t, unknownLocation, info.CountryCode)

	// Failed DB lookup
	info, err = GetIPInfoFromAddr(&badMap{}, &badAddr{"8.8.8.8:port"})
	require.Error(t, err)
	require.Equal(t, errDbLookupError, info.CountryCode)
}

func TestCountryCode(t *testing.T) {
	require.Equal(t, "BR", CountryCode("BR").String())
}

func BenchmarkGetIPInfoFromAddr(b *testing.B) {
	ip2info := &noopMap{}
	testAddr := &net.TCPAddr{IP: net.ParseIP("217.65.48.1"), Port: 12345}

	b.ResetTimer()
	// Repeatedly check the country for the same address.  This is realistic, because
	// servers call this method for each new connection, but typically many connections
	// come from a single user in succession.
	for i := 0; i < b.N; i++ {
		GetIPInfoFromAddr(ip2info, testAddr)
	}
}
