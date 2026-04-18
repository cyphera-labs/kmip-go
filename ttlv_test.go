// Copyright 2026 Horizon Digital Engineering LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package kmip

import (
	"bytes"
	"testing"
)

func TestEncodesAndDecodesInteger(t *testing.T) {
	encoded := EncodeInteger(0x42006A, 1)
	decoded, err := DecodeTTLV(encoded, 0)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Tag != 0x42006A {
		t.Errorf("tag = 0x%06X, want 0x42006A", decoded.Tag)
	}
	if decoded.Type != TypeInteger {
		t.Errorf("type = %d, want %d", decoded.Type, TypeInteger)
	}
	if decoded.IntValue() != 1 {
		t.Errorf("value = %d, want 1", decoded.IntValue())
	}
}

func TestEncodesAndDecodesEnumeration(t *testing.T) {
	encoded := EncodeEnum(0x42005C, 0x0000000A)
	decoded, err := DecodeTTLV(encoded, 0)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Tag != 0x42005C {
		t.Errorf("tag = 0x%06X, want 0x42005C", decoded.Tag)
	}
	if decoded.Type != TypeEnumeration {
		t.Errorf("type = %d, want %d", decoded.Type, TypeEnumeration)
	}
	if decoded.IntValue() != 0x0000000A {
		t.Errorf("value = 0x%08X, want 0x0000000A", decoded.IntValue())
	}
}

func TestEncodesAndDecodesTextString(t *testing.T) {
	encoded := EncodeTextString(0x420055, "my-key")
	decoded, err := DecodeTTLV(encoded, 0)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Tag != 0x420055 {
		t.Errorf("tag = 0x%06X, want 0x420055", decoded.Tag)
	}
	if decoded.Type != TypeTextString {
		t.Errorf("type = %d, want %d", decoded.Type, TypeTextString)
	}
	if decoded.StringValue() != "my-key" {
		t.Errorf("value = %q, want %q", decoded.StringValue(), "my-key")
	}
}

func TestEncodesAndDecodesByteString(t *testing.T) {
	key := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	encoded := EncodeByteString(0x420043, key)
	decoded, err := DecodeTTLV(encoded, 0)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Tag != 0x420043 {
		t.Errorf("tag = 0x%06X, want 0x420043", decoded.Tag)
	}
	if decoded.Type != TypeByteString {
		t.Errorf("type = %d, want %d", decoded.Type, TypeByteString)
	}
	if !bytes.Equal(decoded.BytesValue(), key) {
		t.Errorf("value = %x, want %x", decoded.BytesValue(), key)
	}
}

func TestEncodesAndDecodesBoolean(t *testing.T) {
	encoded := EncodeBoolean(0x420008, true)
	decoded, err := DecodeTTLV(encoded, 0)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Type != TypeBoolean {
		t.Errorf("type = %d, want %d", decoded.Type, TypeBoolean)
	}
	if !decoded.BoolValue() {
		t.Error("value = false, want true")
	}
}

func TestEncodesAndDecodesStructureWithChildren(t *testing.T) {
	encoded := EncodeStructure(0x420069,
		EncodeInteger(0x42006A, 1),
		EncodeInteger(0x42006B, 4),
	)
	decoded, err := DecodeTTLV(encoded, 0)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Tag != 0x420069 {
		t.Errorf("tag = 0x%06X, want 0x420069", decoded.Tag)
	}
	if decoded.Type != TypeStructure {
		t.Errorf("type = %d, want %d", decoded.Type, TypeStructure)
	}
	children := decoded.Children()
	if len(children) != 2 {
		t.Fatalf("children count = %d, want 2", len(children))
	}
	if children[0].IntValue() != 1 {
		t.Errorf("child[0] = %d, want 1", children[0].IntValue())
	}
	if children[1].IntValue() != 4 {
		t.Errorf("child[1] = %d, want 4", children[1].IntValue())
	}
}

func TestFindChildLocatesChildByTag(t *testing.T) {
	encoded := EncodeStructure(0x420069,
		EncodeInteger(0x42006A, 1),
		EncodeInteger(0x42006B, 4),
	)
	decoded, err := DecodeTTLV(encoded, 0)
	if err != nil {
		t.Fatal(err)
	}
	child := FindChild(decoded, 0x42006B)
	if child == nil {
		t.Fatal("child not found")
	}
	if child.IntValue() != 4 {
		t.Errorf("child value = %d, want 4", child.IntValue())
	}
}

func TestPadsTextStringsToEightByteAlignment(t *testing.T) {
	// "hello" = 5 bytes -> padded to 8 bytes -> total TTLV = 16 bytes
	encoded := EncodeTextString(0x420055, "hello")
	if len(encoded) != 16 {
		t.Errorf("length = %d, want 16 (8 header + 8 padded value)", len(encoded))
	}
}

func TestHandlesEmptyTextString(t *testing.T) {
	encoded := EncodeTextString(0x420055, "")
	decoded, err := DecodeTTLV(encoded, 0)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.StringValue() != "" {
		t.Errorf("value = %q, want empty string", decoded.StringValue())
	}
}

func TestRoundTripsNestedStructures(t *testing.T) {
	encoded := EncodeStructure(0x420078,
		EncodeStructure(0x420077,
			EncodeStructure(0x420069,
				EncodeInteger(0x42006A, 1),
				EncodeInteger(0x42006B, 4),
			),
			EncodeInteger(0x42000D, 1),
		),
	)
	decoded, err := DecodeTTLV(encoded, 0)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Tag != 0x420078 {
		t.Errorf("tag = 0x%06X, want 0x420078", decoded.Tag)
	}
	header := FindChild(decoded, 0x420077)
	if header == nil {
		t.Fatal("header not found")
	}
	version := FindChild(header, 0x420069)
	if version == nil {
		t.Fatal("version not found")
	}
	major := FindChild(version, 0x42006A)
	if major == nil {
		t.Fatal("major not found")
	}
	if major.IntValue() != 1 {
		t.Errorf("major = %d, want 1", major.IntValue())
	}
}
