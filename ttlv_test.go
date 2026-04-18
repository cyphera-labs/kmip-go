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
	"encoding/binary"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Primitive encode / decode round-trips
// ---------------------------------------------------------------------------

func TestPrimitives(t *testing.T) {
	t.Run("encodes and decodes an integer", func(t *testing.T) {
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
	})

	t.Run("encodes and decodes a negative integer", func(t *testing.T) {
		encoded := EncodeInteger(0x42006A, -42)
		decoded, err := DecodeTTLV(encoded, 0)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.IntValue() != -42 {
			t.Errorf("value = %d, want -42", decoded.IntValue())
		}
	})

	t.Run("encodes and decodes max 32-bit integer", func(t *testing.T) {
		encoded := EncodeInteger(0x42006A, 0x7FFFFFFF)
		decoded, err := DecodeTTLV(encoded, 0)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.IntValue() != 0x7FFFFFFF {
			t.Errorf("value = %d, want %d", decoded.IntValue(), int32(0x7FFFFFFF))
		}
	})

	t.Run("encodes and decodes min 32-bit integer", func(t *testing.T) {
		encoded := EncodeInteger(0x42006A, -0x80000000)
		decoded, err := DecodeTTLV(encoded, 0)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.IntValue() != -0x80000000 {
			t.Errorf("value = %d, want %d", decoded.IntValue(), int32(-0x80000000))
		}
	})

	t.Run("encodes and decodes zero integer", func(t *testing.T) {
		encoded := EncodeInteger(0x42006A, 0)
		decoded, err := DecodeTTLV(encoded, 0)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.IntValue() != 0 {
			t.Errorf("value = %d, want 0", decoded.IntValue())
		}
	})

	t.Run("encodes and decodes an enumeration", func(t *testing.T) {
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
	})

	t.Run("encodes and decodes a long integer", func(t *testing.T) {
		encoded := EncodeLongInteger(0x42006A, 1234567890123)
		decoded, err := DecodeTTLV(encoded, 0)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.Tag != 0x42006A {
			t.Errorf("tag = 0x%06X, want 0x42006A", decoded.Tag)
		}
		if decoded.Type != TypeLongInteger {
			t.Errorf("type = %d, want %d", decoded.Type, TypeLongInteger)
		}
		if decoded.LongValue() != 1234567890123 {
			t.Errorf("value = %d, want 1234567890123", decoded.LongValue())
		}
	})

	t.Run("encodes and decodes a negative long integer", func(t *testing.T) {
		encoded := EncodeLongInteger(0x42006A, -9999999999)
		decoded, err := DecodeTTLV(encoded, 0)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.LongValue() != -9999999999 {
			t.Errorf("value = %d, want -9999999999", decoded.LongValue())
		}
	})

	t.Run("encodes and decodes a text string", func(t *testing.T) {
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
	})

	t.Run("encodes and decodes a byte string", func(t *testing.T) {
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
	})

	t.Run("encodes and decodes boolean true", func(t *testing.T) {
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
	})

	t.Run("encodes and decodes boolean false", func(t *testing.T) {
		encoded := EncodeBoolean(0x420008, false)
		decoded, err := DecodeTTLV(encoded, 0)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.Type != TypeBoolean {
			t.Errorf("type = %d, want %d", decoded.Type, TypeBoolean)
		}
		if decoded.BoolValue() {
			t.Error("value = true, want false")
		}
	})

	t.Run("encodes and decodes a date-time", func(t *testing.T) {
		// 2026-04-18T12:00:00Z in epoch seconds
		var epochSec int64 = 1776600000
		encoded := EncodeDateTime(0x420008, epochSec)
		decoded, err := DecodeTTLV(encoded, 0)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.Type != TypeDateTime {
			t.Errorf("type = %d, want %d", decoded.Type, TypeDateTime)
		}
		if decoded.LongValue() != epochSec {
			t.Errorf("value = %d, want %d", decoded.LongValue(), epochSec)
		}
	})

	t.Run("encodes and decodes epoch zero date-time", func(t *testing.T) {
		encoded := EncodeDateTime(0x420008, 0)
		decoded, err := DecodeTTLV(encoded, 0)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.LongValue() != 0 {
			t.Errorf("value = %d, want 0", decoded.LongValue())
		}
	})
}

// ---------------------------------------------------------------------------
// Padding and alignment
// ---------------------------------------------------------------------------

func TestPadding(t *testing.T) {
	t.Run("integer occupies 16 bytes total (8 header + 4 value + 4 padding)", func(t *testing.T) {
		encoded := EncodeInteger(0x42006A, 1)
		if len(encoded) != 16 {
			t.Errorf("length = %d, want 16", len(encoded))
		}
		// Length field should say 4
		if binary.BigEndian.Uint32(encoded[4:8]) != 4 {
			t.Errorf("length field = %d, want 4", binary.BigEndian.Uint32(encoded[4:8]))
		}
	})

	t.Run("enum occupies 16 bytes total (8 header + 4 value + 4 padding)", func(t *testing.T) {
		encoded := EncodeEnum(0x42005C, 1)
		if len(encoded) != 16 {
			t.Errorf("length = %d, want 16", len(encoded))
		}
		if binary.BigEndian.Uint32(encoded[4:8]) != 4 {
			t.Errorf("length field = %d, want 4", binary.BigEndian.Uint32(encoded[4:8]))
		}
	})

	t.Run("boolean uses exactly 16 bytes (8 header + 8 value)", func(t *testing.T) {
		encoded := EncodeBoolean(0x420008, true)
		if len(encoded) != 16 {
			t.Errorf("length = %d, want 16", len(encoded))
		}
		if binary.BigEndian.Uint32(encoded[4:8]) != 8 {
			t.Errorf("length field = %d, want 8", binary.BigEndian.Uint32(encoded[4:8]))
		}
	})

	t.Run("long integer uses exactly 16 bytes (8 header + 8 value)", func(t *testing.T) {
		encoded := EncodeLongInteger(0x42006A, 42)
		if len(encoded) != 16 {
			t.Errorf("length = %d, want 16", len(encoded))
		}
		if binary.BigEndian.Uint32(encoded[4:8]) != 8 {
			t.Errorf("length field = %d, want 8", binary.BigEndian.Uint32(encoded[4:8]))
		}
	})

	t.Run("pads text strings to 8-byte alignment (5 bytes -> 8)", func(t *testing.T) {
		encoded := EncodeTextString(0x420055, "hello")
		if len(encoded) != 16 {
			t.Errorf("length = %d, want 16 (8 header + 8 padded value)", len(encoded))
		}
	})

	t.Run("text string exactly 8 bytes needs no padding", func(t *testing.T) {
		encoded := EncodeTextString(0x420055, "12345678")
		if len(encoded) != 16 {
			t.Errorf("length = %d, want 16 (8 header + 8 value)", len(encoded))
		}
	})

	t.Run("text string 9 bytes pads to 16", func(t *testing.T) {
		encoded := EncodeTextString(0x420055, "123456789")
		if len(encoded) != 24 {
			t.Errorf("length = %d, want 24 (8 header + 16 padded)", len(encoded))
		}
	})

	t.Run("handles empty text string (0 bytes, no padding)", func(t *testing.T) {
		encoded := EncodeTextString(0x420055, "")
		if len(encoded) != 8 {
			t.Errorf("length = %d, want 8 (header only)", len(encoded))
		}
		decoded, err := DecodeTTLV(encoded, 0)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.StringValue() != "" {
			t.Errorf("value = %q, want empty string", decoded.StringValue())
		}
	})

	t.Run("byte string with exact 8-byte alignment needs no padding", func(t *testing.T) {
		data := make([]byte, 16)
		for i := range data {
			data[i] = 0xAB
		}
		encoded := EncodeByteString(0x420043, data)
		if len(encoded) != 24 {
			t.Errorf("length = %d, want 24 (8 header + 16 value)", len(encoded))
		}
	})

	t.Run("byte string with 1 extra byte pads to next 8", func(t *testing.T) {
		data := make([]byte, 17)
		for i := range data {
			data[i] = 0xAB
		}
		encoded := EncodeByteString(0x420043, data)
		if len(encoded) != 32 {
			t.Errorf("length = %d, want 32 (8 header + 24 padded)", len(encoded))
		}
	})

	t.Run("empty byte string", func(t *testing.T) {
		encoded := EncodeByteString(0x420043, []byte{})
		if len(encoded) != 8 {
			t.Errorf("length = %d, want 8", len(encoded))
		}
		decoded, err := DecodeTTLV(encoded, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(decoded.BytesValue()) != 0 {
			t.Errorf("value length = %d, want 0", len(decoded.BytesValue()))
		}
	})

	t.Run("32-byte key material round-trips correctly (AES-256)", func(t *testing.T) {
		key := []byte{
			0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
			0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
			0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
			0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		}
		encoded := EncodeByteString(0x420043, key)
		if len(encoded) != 40 {
			t.Errorf("length = %d, want 40 (8 header + 32 value)", len(encoded))
		}
		decoded, err := DecodeTTLV(encoded, 0)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(decoded.BytesValue(), key) {
			t.Errorf("value = %x, want %x", decoded.BytesValue(), key)
		}
	})
}

// ---------------------------------------------------------------------------
// Structures and tree navigation
// ---------------------------------------------------------------------------

func TestStructures(t *testing.T) {
	t.Run("encodes and decodes a structure with children", func(t *testing.T) {
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
	})

	t.Run("empty structure with no children", func(t *testing.T) {
		encoded := EncodeStructure(0x420069)
		decoded, err := DecodeTTLV(encoded, 0)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.Type != TypeStructure {
			t.Errorf("type = %d, want %d", decoded.Type, TypeStructure)
		}
		children := decoded.Children()
		if len(children) != 0 {
			t.Errorf("children count = %d, want 0", len(children))
		}
	})

	t.Run("structure with mixed types", func(t *testing.T) {
		encoded := EncodeStructure(0x420069,
			EncodeInteger(0x42006A, 42),
			EncodeTextString(0x420055, "hello"),
			EncodeBoolean(0x420008, true),
			EncodeByteString(0x420043, []byte{0xCA, 0xFE}),
			EncodeEnum(0x42005C, 0x0A),
		)
		decoded, err := DecodeTTLV(encoded, 0)
		if err != nil {
			t.Fatal(err)
		}
		children := decoded.Children()
		if len(children) != 5 {
			t.Fatalf("children count = %d, want 5", len(children))
		}
		if children[0].IntValue() != 42 {
			t.Errorf("child[0] = %d, want 42", children[0].IntValue())
		}
		if children[1].StringValue() != "hello" {
			t.Errorf("child[1] = %q, want %q", children[1].StringValue(), "hello")
		}
		if !children[2].BoolValue() {
			t.Error("child[2] = false, want true")
		}
		if !bytes.Equal(children[3].BytesValue(), []byte{0xCA, 0xFE}) {
			t.Errorf("child[3] = %x, want cafe", children[3].BytesValue())
		}
		if children[4].IntValue() != 0x0A {
			t.Errorf("child[4] = 0x%X, want 0x0A", children[4].IntValue())
		}
	})

	t.Run("FindChild locates a child by tag", func(t *testing.T) {
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
	})

	t.Run("FindChild returns nil for missing tag", func(t *testing.T) {
		encoded := EncodeStructure(0x420069,
			EncodeInteger(0x42006A, 1),
		)
		decoded, err := DecodeTTLV(encoded, 0)
		if err != nil {
			t.Fatal(err)
		}
		if FindChild(decoded, 0x42FFFF) != nil {
			t.Error("expected nil for missing tag")
		}
	})

	t.Run("FindChild returns nil for non-structure", func(t *testing.T) {
		encoded := EncodeInteger(0x42006A, 1)
		decoded, err := DecodeTTLV(encoded, 0)
		if err != nil {
			t.Fatal(err)
		}
		if FindChild(decoded, 0x42006A) != nil {
			t.Error("expected nil for non-structure")
		}
	})

	t.Run("FindChildren returns all matching children", func(t *testing.T) {
		encoded := EncodeStructure(0x420069,
			EncodeTextString(0x420094, "id-1"),
			EncodeTextString(0x420094, "id-2"),
			EncodeTextString(0x420094, "id-3"),
			EncodeInteger(0x42006A, 99),
		)
		decoded, err := DecodeTTLV(encoded, 0)
		if err != nil {
			t.Fatal(err)
		}
		ids := FindChildren(decoded, 0x420094)
		if len(ids) != 3 {
			t.Fatalf("count = %d, want 3", len(ids))
		}
		if ids[0].StringValue() != "id-1" {
			t.Errorf("ids[0] = %q, want %q", ids[0].StringValue(), "id-1")
		}
		if ids[1].StringValue() != "id-2" {
			t.Errorf("ids[1] = %q, want %q", ids[1].StringValue(), "id-2")
		}
		if ids[2].StringValue() != "id-3" {
			t.Errorf("ids[2] = %q, want %q", ids[2].StringValue(), "id-3")
		}
	})

	t.Run("FindChildren returns empty slice for non-structure", func(t *testing.T) {
		encoded := EncodeInteger(0x42006A, 1)
		decoded, err := DecodeTTLV(encoded, 0)
		if err != nil {
			t.Fatal(err)
		}
		result := FindChildren(decoded, 0x42006A)
		if len(result) != 0 {
			t.Errorf("count = %d, want 0", len(result))
		}
	})

	t.Run("round-trips deeply nested structures", func(t *testing.T) {
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
		minor := FindChild(version, 0x42006B)
		if minor == nil {
			t.Fatal("minor not found")
		}
		if minor.IntValue() != 4 {
			t.Errorf("minor = %d, want 4", minor.IntValue())
		}
	})

	t.Run("structure containing structure containing structure (3 levels)", func(t *testing.T) {
		encoded := EncodeStructure(0x420001,
			EncodeStructure(0x420002,
				EncodeStructure(0x420003,
					EncodeTextString(0x420055, "deep"),
				),
			),
		)
		decoded, err := DecodeTTLV(encoded, 0)
		if err != nil {
			t.Fatal(err)
		}
		lvl1 := FindChild(decoded, 0x420002)
		if lvl1 == nil {
			t.Fatal("level 1 not found")
		}
		lvl2 := FindChild(lvl1, 0x420003)
		if lvl2 == nil {
			t.Fatal("level 2 not found")
		}
		leaf := FindChild(lvl2, 0x420055)
		if leaf == nil {
			t.Fatal("leaf not found")
		}
		if leaf.StringValue() != "deep" {
			t.Errorf("leaf = %q, want %q", leaf.StringValue(), "deep")
		}
	})
}

// ---------------------------------------------------------------------------
// Wire format verification
// ---------------------------------------------------------------------------

func TestWireFormat(t *testing.T) {
	t.Run("tag is encoded as 3 bytes big-endian", func(t *testing.T) {
		encoded := EncodeInteger(0x420069, 0)
		if encoded[0] != 0x42 {
			t.Errorf("byte[0] = 0x%02X, want 0x42", encoded[0])
		}
		if encoded[1] != 0x00 {
			t.Errorf("byte[1] = 0x%02X, want 0x00", encoded[1])
		}
		if encoded[2] != 0x69 {
			t.Errorf("byte[2] = 0x%02X, want 0x69", encoded[2])
		}
	})

	t.Run("type byte is correct for each type", func(t *testing.T) {
		cases := []struct {
			name    string
			encoded []byte
			want    byte
		}{
			{"Integer", EncodeInteger(0x420001, 0), TypeInteger},
			{"LongInteger", EncodeLongInteger(0x420001, 0), TypeLongInteger},
			{"Enumeration", EncodeEnum(0x420001, 0), TypeEnumeration},
			{"Boolean", EncodeBoolean(0x420001, true), TypeBoolean},
			{"TextString", EncodeTextString(0x420001, "x"), TypeTextString},
			{"ByteString", EncodeByteString(0x420001, []byte{1}), TypeByteString},
			{"Structure", EncodeStructure(0x420001), TypeStructure},
			{"DateTime", EncodeDateTime(0x420001, 0), TypeDateTime},
		}
		for _, tc := range cases {
			if tc.encoded[3] != byte(tc.want) {
				t.Errorf("%s: type byte = 0x%02X, want 0x%02X", tc.name, tc.encoded[3], tc.want)
			}
		}
	})

	t.Run("length field is 4 bytes big-endian at offset 4", func(t *testing.T) {
		encoded := EncodeTextString(0x420055, "AB") // 2 bytes
		length := binary.BigEndian.Uint32(encoded[4:8])
		if length != 2 {
			t.Errorf("length = %d, want 2", length)
		}
	})

	t.Run("padding bytes are zero-filled", func(t *testing.T) {
		encoded := EncodeTextString(0x420055, "AB") // 2 bytes -> padded to 8
		// Value starts at offset 8, length 2, padding at bytes 10-15
		for i := 10; i < 16; i++ {
			if encoded[i] != 0 {
				t.Errorf("padding byte at %d = 0x%02X, want 0x00", i, encoded[i])
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

func TestErrorHandling(t *testing.T) {
	t.Run("returns error on buffer too short for header", func(t *testing.T) {
		_, err := DecodeTTLV(make([]byte, 4), 0)
		if err == nil {
			t.Fatal("expected error for short buffer")
		}
		if !strings.Contains(err.Error(), "too short") {
			t.Errorf("error = %q, want message containing 'too short'", err.Error())
		}
	})

	t.Run("returns error on empty buffer", func(t *testing.T) {
		_, err := DecodeTTLV([]byte{}, 0)
		if err == nil {
			t.Fatal("expected error for empty buffer")
		}
		if !strings.Contains(err.Error(), "too short") {
			t.Errorf("error = %q, want message containing 'too short'", err.Error())
		}
	})
}

// ---------------------------------------------------------------------------
// Unicode and special strings
// ---------------------------------------------------------------------------

func TestUnicodeStrings(t *testing.T) {
	t.Run("handles UTF-8 multi-byte characters", func(t *testing.T) {
		encoded := EncodeTextString(0x420055, "caf\u00e9")
		decoded, err := DecodeTTLV(encoded, 0)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.StringValue() != "caf\u00e9" {
			t.Errorf("value = %q, want %q", decoded.StringValue(), "caf\u00e9")
		}
	})

	t.Run("handles emoji", func(t *testing.T) {
		encoded := EncodeTextString(0x420055, "key-\U0001F511")
		decoded, err := DecodeTTLV(encoded, 0)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.StringValue() != "key-\U0001F511" {
			t.Errorf("value = %q, want %q", decoded.StringValue(), "key-\U0001F511")
		}
	})

	t.Run("handles long text string crossing multiple 8-byte boundaries", func(t *testing.T) {
		longStr := strings.Repeat("a]", 100) // 200 bytes
		encoded := EncodeTextString(0x420055, longStr)
		decoded, err := DecodeTTLV(encoded, 0)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.StringValue() != longStr {
			t.Errorf("value length = %d, want %d", len(decoded.StringValue()), len(longStr))
		}
	})
}
