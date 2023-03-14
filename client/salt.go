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

package client

import (
	ss "github.com/Jigsaw-Code/outline-ss-server/shadowsocks"
	ss_client "github.com/Jigsaw-Code/outline-ss-server/shadowsocks/client"
)

// Deprecated: Prefer github.com/Jigsaw-Code/outline-ss-server/shadowsocks/client.NewPrefixSaltGenerator
func NewPrefixSaltGenerator(prefix []byte) ss.SaltGenerator {
	return ss_client.NewPrefixSaltGenerator(prefix)
}
