package shadowsocks

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

func init() {
	// Reduce chunk size boost trigger amount to capture the transition behavior without
	// having to send many megabytes of data.
	chunkSizeBoostTriggerBytes = 20_000
}

func newTestCipher(t *testing.T) *Cipher {
	cipher, err := NewCipher("chacha20-ietf-poly1305", "test secret")
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}

// Overhead for cipher chacha20poly1305
const testCipherOverhead = 16

func TestCipherReaderAuthenticationFailure(t *testing.T) {
	cipher := newTestCipher(t)

	clientReader := strings.NewReader("Fails Authentication")
	reader := NewShadowsocksReader(clientReader, cipher)
	_, err := reader.Read(make([]byte, 1))
	if err == nil {
		t.Fatalf("Expected authentication failure, got %v", err)
	}
}

func TestCipherReaderUnexpectedEOF(t *testing.T) {
	cipher := newTestCipher(t)

	clientReader := strings.NewReader("short")
	server := NewShadowsocksReader(clientReader, cipher)
	_, err := server.Read(make([]byte, 10))
	if err != io.ErrUnexpectedEOF {
		t.Fatalf("Expected ErrUnexpectedEOF, got %v", err)
	}
}

func TestCipherReaderEOF(t *testing.T) {
	cipher := newTestCipher(t)

	clientReader := strings.NewReader("")
	server := NewShadowsocksReader(clientReader, cipher)
	_, err := server.Read(make([]byte, 10))
	if err != io.EOF {
		t.Fatalf("Expected EOF, got %v", err)
	}
	_, err = server.Read([]byte{})
	if err != io.EOF {
		t.Fatalf("Expected EOF, got %v", err)
	}
}

func encryptBlocks(cipher *Cipher, salt []byte, blocks [][]byte) (io.Reader, error) {
	var ssText bytes.Buffer
	aead, err := cipher.NewAEAD(salt)
	if err != nil {
		return nil, fmt.Errorf("Failed to create AEAD: %v", err)
	}
	ssText.Write(salt)
	// buf must fit the larges block ciphertext
	buf := make([]byte, 2+100+testCipherOverhead)
	var expectedCipherSize int
	nonce := make([]byte, chacha20poly1305.NonceSize)
	for _, block := range blocks {
		ssText.Write(aead.Seal(buf[:0], nonce, []byte{0, byte(len(block))}, nil))
		nonce[0]++
		expectedCipherSize += 2 + testCipherOverhead
		ssText.Write(aead.Seal(buf[:0], nonce, block, nil))
		nonce[0]++
		expectedCipherSize += len(block) + testCipherOverhead
	}
	if ssText.Len() != cipher.SaltSize()+expectedCipherSize {
		return nil, fmt.Errorf("cipherText has size %v. Expected %v", ssText.Len(), cipher.SaltSize()+expectedCipherSize)
	}
	return &ssText, nil
}

func TestCipherReaderGoodReads(t *testing.T) {
	cipher := newTestCipher(t)

	salt := []byte("12345678901234567890123456789012")
	if len(salt) != cipher.SaltSize() {
		t.Fatalf("Salt has size %v. Expected %v", len(salt), cipher.SaltSize())
	}
	ssText, err := encryptBlocks(cipher, salt, [][]byte{
		[]byte("[First Block]"),
		[]byte(""), // Corner case: empty block
		[]byte("[Third Block]")})
	if err != nil {
		t.Fatal(err)
	}

	reader := NewShadowsocksReader(ssText, cipher)
	plainText := make([]byte, len("[First Block]")+len("[Third Block]"))
	n, err := io.ReadFull(reader, plainText)
	if err != nil {
		t.Fatalf("Failed to fully read plain text. Got %v bytes: %v", n, err)
	}
	_, err = reader.Read([]byte{})
	if err != io.EOF {
		t.Fatalf("Expected EOF, got %v", err)
	}
	_, err = reader.Read(make([]byte, 1))
	if err != io.EOF {
		t.Fatalf("Expected EOF, got %v", err)
	}
}

func TestCipherReaderClose(t *testing.T) {
	cipher := newTestCipher(t)

	pipeReader, pipeWriter := io.Pipe()
	server := NewShadowsocksReader(pipeReader, cipher)
	result := make(chan error)
	go func() {
		_, err := server.Read(make([]byte, 10))
		result <- err
	}()
	pipeWriter.Close()
	err := <-result
	if err != io.EOF {
		t.Fatalf("Expected ErrUnexpectedEOF, got %v", err)
	}
}

func TestCipherReaderCloseError(t *testing.T) {
	cipher := newTestCipher(t)

	pipeReader, pipeWriter := io.Pipe()
	server := NewShadowsocksReader(pipeReader, cipher)
	result := make(chan error)
	go func() {
		_, err := server.Read(make([]byte, 10))
		result <- err
	}()
	pipeWriter.CloseWithError(fmt.Errorf("xx!!ERROR!!xx"))
	err := <-result
	if err == nil || !strings.Contains(err.Error(), "xx!!ERROR!!xx") {
		t.Fatalf("Unexpected error: %v", err)
	}
}

func TestEndToEnd(t *testing.T) {
	cipher := newTestCipher(t)

	connReader, connWriter := io.Pipe()
	writer := NewShadowsocksWriter(connWriter, cipher)
	reader := NewShadowsocksReader(connReader, cipher)
	expected := "Test"
	go func() {
		defer connWriter.Close()
		_, err := writer.Write([]byte(expected))
		if err != nil {
			t.Fatalf("Failed Write: %v", err)
		}
	}()
	var output bytes.Buffer
	_, err := reader.WriteTo(&output)
	if err != nil {
		t.Fatalf("Failed WriteTo: %v", err)
	}
	if output.String() != expected {
		t.Fatalf("Expected output '%v'. Got '%v'", expected, output.String())
	}
}

func TestLazyWriteFlush(t *testing.T) {
	cipher := newTestCipher(t)
	buf := new(bytes.Buffer)
	writer := NewShadowsocksWriter(buf, cipher)
	header := []byte{1, 2, 3, 4}
	n, err := writer.LazyWrite(header)
	if n != len(header) {
		t.Errorf("Wrong write size: %d", n)
	}
	if err != nil {
		t.Errorf("LazyWrite failed: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("LazyWrite isn't lazy: %v", buf.Bytes())
	}
	if err = writer.Flush(); err != nil {
		t.Errorf("Flush failed: %v", err)
	}
	len1 := buf.Len()
	if len1 <= len(header) {
		t.Errorf("Not enough bytes flushed: %d", len1)
	}

	// Check that normal writes now work
	body := []byte{5, 6, 7}
	n, err = writer.Write(body)
	if n != len(body) {
		t.Errorf("Wrong write size: %d", n)
	}
	if err != nil {
		t.Errorf("Write failed: %v", err)
	}
	if buf.Len() == len1 {
		t.Errorf("No write observed")
	}

	// Verify content arrives in two blocks
	reader := NewShadowsocksReader(buf, cipher)
	decrypted := make([]byte, len(header)+len(body))
	n, err = reader.Read(decrypted)
	if n != len(header) {
		t.Errorf("Wrong number of bytes out: %d", n)
	}
	if err != nil {
		t.Errorf("Read failed: %v", err)
	}
	if !bytes.Equal(decrypted[:n], header) {
		t.Errorf("Wrong final content: %v", decrypted)
	}
	n, err = reader.Read(decrypted[n:])
	if n != len(body) {
		t.Errorf("Wrong number of bytes out: %d", n)
	}
	if err != nil {
		t.Errorf("Read failed: %v", err)
	}
	if !bytes.Equal(decrypted[len(header):], body) {
		t.Errorf("Wrong final content: %v", decrypted)
	}
}

func TestLazyWriteConcat(t *testing.T) {
	cipher := newTestCipher(t)
	buf := new(bytes.Buffer)
	writer := NewShadowsocksWriter(buf, cipher)
	header := []byte{1, 2, 3, 4}
	n, err := writer.LazyWrite(header)
	if n != len(header) {
		t.Errorf("Wrong write size: %d", n)
	}
	if err != nil {
		t.Errorf("LazyWrite failed: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("LazyWrite isn't lazy: %v", buf.Bytes())
	}

	// Write additional data and flush the header.
	body := []byte{5, 6, 7}
	n, err = writer.Write(body)
	if n != len(body) {
		t.Errorf("Wrong write size: %d", n)
	}
	if err != nil {
		t.Errorf("Write failed: %v", err)
	}
	len1 := buf.Len()
	if len1 <= len(body)+len(header) {
		t.Errorf("Not enough bytes flushed: %d", len1)
	}

	// Flush after write should have no effect
	if err = writer.Flush(); err != nil {
		t.Errorf("Flush failed: %v", err)
	}
	if buf.Len() != len1 {
		t.Errorf("Flush should have no effect")
	}

	// Verify content arrives in one block
	reader := NewShadowsocksReader(buf, cipher)
	decrypted := make([]byte, len(body)+len(header))
	n, err = reader.Read(decrypted)
	if n != len(decrypted) {
		t.Errorf("Wrong number of bytes out: %d", n)
	}
	if err != nil {
		t.Errorf("Read failed: %v", err)
	}
	if !bytes.Equal(decrypted[:len(header)], header) ||
		!bytes.Equal(decrypted[len(header):], body) {
		t.Errorf("Wrong final content: %v", decrypted)
	}
}

func TestLazyWriteOversize(t *testing.T) {
	cipher := newTestCipher(t)
	buf := new(bytes.Buffer)
	writer := NewShadowsocksWriter(buf, cipher)
	N := 25000 // More than one block, less than two.
	data := make([]byte, N)
	for i := range data {
		data[i] = byte(i)
	}
	n, err := writer.LazyWrite(data)
	if n != len(data) {
		t.Errorf("Wrong write size: %d", n)
	}
	if err != nil {
		t.Errorf("LazyWrite failed: %v", err)
	}
	if buf.Len() >= N {
		t.Errorf("Too much data in first block: %d", buf.Len())
	}
	if err = writer.Flush(); err != nil {
		t.Errorf("Flush failed: %v", err)
	}
	if buf.Len() <= N {
		t.Errorf("Not enough data written after flush: %d", buf.Len())
	}

	// Verify content
	reader := NewShadowsocksReader(buf, cipher)
	decrypted, err := ioutil.ReadAll(reader)
	if len(decrypted) != N {
		t.Errorf("Wrong number of bytes out: %d", len(decrypted))
	}
	if err != nil {
		t.Errorf("Read failed: %v", err)
	}
	if !bytes.Equal(decrypted, data) {
		t.Errorf("Wrong final content: %v", decrypted)
	}
}

func TestLazyWriteConcurrentFlush(t *testing.T) {
	cipher := newTestCipher(t)
	buf := new(bytes.Buffer)
	writer := NewShadowsocksWriter(buf, cipher)
	header := []byte{1, 2, 3, 4}
	n, err := writer.LazyWrite(header)
	if n != len(header) {
		t.Errorf("Wrong write size: %d", n)
	}
	if err != nil {
		t.Errorf("LazyWrite failed: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("LazyWrite isn't lazy: %v", buf.Bytes())
	}

	body := []byte{5, 6, 7}
	r, w := io.Pipe()
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		n, err := writer.ReadFrom(r)
		if n != int64(len(body)) {
			t.Errorf("ReadFrom: Wrong read size %d", n)
		}
		if err != nil {
			t.Errorf("ReadFrom: %v", err)
		}
		wg.Done()
	}()

	// Wait for ReadFrom to start and get blocked.
	time.Sleep(20 * time.Millisecond)

	// Flush while ReadFrom is blocked.
	if err := writer.Flush(); err != nil {
		t.Errorf("Flush error: %v", err)
	}
	len1 := buf.Len()
	if len1 == 0 {
		t.Errorf("No bytes flushed")
	}

	// Check that normal writes now work
	n, err = w.Write(body)
	if n != len(body) {
		t.Errorf("Wrong write size: %d", n)
	}
	if err != nil {
		t.Errorf("Write failed: %v", err)
	}
	w.Close()
	wg.Wait()
	if buf.Len() == len1 {
		t.Errorf("No write observed")
	}

	// Verify content arrives in two blocks
	reader := NewShadowsocksReader(buf, cipher)
	decrypted := make([]byte, len(header)+len(body))
	n, err = reader.Read(decrypted)
	if n != len(header) {
		t.Errorf("Wrong number of bytes out: %d", n)
	}
	if err != nil {
		t.Errorf("Read failed: %v", err)
	}
	if !bytes.Equal(decrypted[:len(header)], header) {
		t.Errorf("Wrong final content: %v", decrypted)
	}
	n, err = reader.Read(decrypted[len(header):])
	if n != len(body) {
		t.Errorf("Wrong number of bytes out: %d", n)
	}
	if err != nil {
		t.Errorf("Read failed: %v", err)
	}
	if !bytes.Equal(decrypted[len(header):], body) {
		t.Errorf("Wrong final content: %v", decrypted)
	}
}

func TestMSSEndToEnd(t *testing.T) {
	t.Parallel()
	cipher := newTestCipher(t)

	// Test values near the default (0), minimum (35), typical (600, 1500), and maximum.
	testMSSValues := []int{
		-1, 0, 1, 2, 32, 33, 34, 35, 36, 500, 600, 1500, 16415, 16416, 16417, 16418, 32768,
	}

	input := make([]byte, 2*chunkSizeBoostTriggerBytes)
	for i := range input {
		input[i] = byte(i) // Arbitrary test contents
	}

	for _, mss := range testMSSValues {
		mss := mss
		t.Run(fmt.Sprintf("MSS=%d", mss), func(t *testing.T) {
			t.Parallel()
			connReader, connWriter := io.Pipe()
			writer := NewShadowsocksWriter(connWriter, cipher)
			writer.SetMSS(mss)
			reader := NewShadowsocksReader(connReader, cipher)
			go func() {
				defer connWriter.Close()
				_, err := writer.Write(input)
				if err != nil {
					t.Errorf("Failed Write: %v", err)
				}
			}()
			output, err := ioutil.ReadAll(reader)
			if err != nil {
				t.Errorf("ReadAll failed: %v", err)
			} else if !bytes.Equal(input, output) {
				t.Errorf("Data mismatch (lengths %d, %d, mss=%d)", len(input), len(output), mss)
			}
		})
	}
}

func TestMSSSizeCheck(t *testing.T) {
	t.Parallel()
	cipher := newTestCipher(t)

	testPayloadSize := []int{
		1, 2, 3, 500, 1500, 16382, 16383,
	}

	input := make([]byte, 2*chunkSizeBoostTriggerBytes)

	for _, payloadSize := range testPayloadSize {
		payloadSize := payloadSize
		t.Run(fmt.Sprintf("payloadSize=%d", payloadSize), func(t *testing.T) {
			t.Parallel()
			connReader, connWriter := io.Pipe()
			writer := NewShadowsocksWriter(connWriter, cipher)
			writer.SetMSS(payloadSize + 2 + 2*cipher.TagSize())
			reader := NewShadowsocksReader(connReader, cipher)
			go func() {
				_, err := writer.Write(input)
				if err != nil {
					t.Errorf("Failed Write: %v", err)
				}
				connWriter.Close()
			}()
			outputBuf := make([]byte, 32768)
			var total int64 = 0
			for {
				n, err := reader.Read(outputBuf)
				if err != nil {
					t.Fatal(err)
				}
				prevTotal := total
				total += int64(n)
				if int(total) == len(input) {
					break
				}
				var expectedN int
				if prevTotal <= chunkSizeBoostTriggerBytes {
					expectedN = payloadSize
				} else {
					expectedN = payloadSizeMask
				}

				if n != expectedN {
					t.Errorf("Expected %d payload bytes, got %d", expectedN, n)
				}
			}
		})
	}
}
