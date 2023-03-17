// Copyright 2022 Jigsaw Operations LLC
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

package shadowsocks

import (
	"testing"
	"time"
)

// Microbenchmark for the performance of Shadowsocks UDP encryption.
func BenchmarkPack(b *testing.B) {
	b.StopTimer()
	b.ResetTimer()

	cipher := newTestCipher(b)
	MTU := 1500
	pkt := make([]byte, MTU)
	plaintextBuf := pkt[cipher.SaltSize() : len(pkt)-cipher.TagSize()]

	start := time.Now()
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		Pack(pkt, plaintextBuf, cipher)
	}
	b.StopTimer()
	elapsed := time.Now().Sub(start)

	megabits := float64(8*len(plaintextBuf)*b.N) * 1e-6
	b.ReportMetric(megabits/(elapsed.Seconds()), "mbps")
}
