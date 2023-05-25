package ipinfo

import (
	"net"
	"testing"
)

type noopMap struct{}

func (*noopMap) GetIPInfo(ip net.IP) (IPInfo, error) {
	return IPInfo{}, nil
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
