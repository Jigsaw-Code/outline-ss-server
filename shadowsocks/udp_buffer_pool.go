package shadowsocks

import "sync"

// maxUDPBufferSize is the maximum UDP packet size in bytes.
const maxUDPBufferSize = 16 * 1024

var pool = sync.Pool{
	New: func() interface{} {
		return make([]byte, maxUDPBufferSize)
	},
}

// newBuffer retrieves a UDP buffer from the pool.
func newUDPBuffer() []byte {
	return pool.Get().([]byte)
}

// freeBuffer returns a UDP buffer to the pool.
func freeUDPBuffer(b []byte) {
	pool.Put(b)
}
