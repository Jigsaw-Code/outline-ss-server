package proxy

import (
	"io"

	"github.com/shadowsocks/go-shadowsocks2/socks"
)

func ParseShadowsocks(reader io.Reader) (string, error) {
	tgtAddr, err := socks.ReadAddr(reader)
	if err != nil {
		return "", err
	}
	return tgtAddr.String(), nil
}
