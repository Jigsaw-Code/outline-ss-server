// Copyright 2018 Jigsaw Operations LLC
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

package service

import (
	"net"
	"time"
)

func MakeTestTrafficLimiterConfig(ciphers CipherList) TrafficLimiterConfig {
	elts := ciphers.SnapshotForClientIP(net.IP{})
	keyLimits := KeyLimits{
		LargeScalePeriod: 1000 * time.Hour,
		LargeScaleLimit:  1 << 30,
		SmallScalePeriod: 1000 * time.Hour,
		SmallScaleLimit:  1 << 30,
	}
	keyToLimits := make(map[string]KeyLimits)
	for _, elt := range elts {
		entry := elt.Value.(*CipherEntry)
		keyToLimits[entry.ID] = keyLimits
	}
	return TrafficLimiterConfig{KeyToLimits: keyToLimits}
}
