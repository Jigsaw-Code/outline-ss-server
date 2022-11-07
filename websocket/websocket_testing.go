package websocket

import (
	"path"
	"path/filepath"
	"runtime"
)

var (
	TestCert string
	TestKey  string
)

func init() {
	_, filename, _, _ := runtime.Caller(0)
	cwd := filepath.Dir(filepath.Dir(filename))
	TestCert = path.Join(cwd, "ssl.crt")
	TestKey = path.Join(cwd, "ssl.key")
}
