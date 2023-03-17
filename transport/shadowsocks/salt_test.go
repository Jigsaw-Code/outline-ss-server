// Copyright 2020 Jigsaw Operations LLC
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
	"bytes"
	"testing"
)

func TestRandomSaltGenerator(t *testing.T) {
	if err := RandomSaltGenerator.GetSalt(nil); err != nil {
		t.Error(err)
	}
	salt := make([]byte, 16)
	if err := RandomSaltGenerator.GetSalt(salt); err != nil {
		t.Error(err)
	}
	if bytes.Equal(salt, make([]byte, 16)) {
		t.Error("Salt is all zeros")
	}
}

func BenchmarkRandomSaltGenerator(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		salt := make([]byte, 32)
		for pb.Next() {
			if err := RandomSaltGenerator.GetSalt(salt); err != nil {
				b.Fatal(err)
			}
		}
	})
}
