package client

import (
	"bytes"
	"io"
	"testing"
)

const (
	testPassword   = "testPassword"
	testTargetAddr = "test.local:1111"
)

// Writes `payload` to `conn` and reads it into `buf`, which we take as a parameter to avoid
// reallocations in benchmarks and memory profiles. Fails the test if the read payload does not match.
func expectEchoPayload(conn io.ReadWriter, payload, buf []byte, t testing.TB) {
	_, err := conn.Write(payload)
	if err != nil {
		t.Fatalf("Failed to write payload: %v", err)
	}
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read payload: %v", err)
	}
	if !bytes.Equal(payload, buf[:n]) {
		t.Fatalf("Expected output '%v'. Got '%v'", payload, buf[:n])
	}
}
