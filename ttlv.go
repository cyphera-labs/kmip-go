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

// Package kmip implements a KMIP 1.4 client with TTLV binary encoding.
package kmip

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// KMIP data types.
const (
	TypeStructure   = 0x01
	TypeInteger     = 0x02
	TypeLongInteger = 0x03
	TypeBigInteger  = 0x04
	TypeEnumeration = 0x05
	TypeBoolean     = 0x06
	TypeTextString  = 0x07
	TypeByteString  = 0x08
	TypeDateTime    = 0x09
	TypeInterval    = 0x0A
)

// Item represents a decoded TTLV item.
type Item struct {
	Tag         int
	Type        int
	Value       interface{}
	Length      int
	TotalLength int
}

// Children returns the child items if this is a Structure, or nil otherwise.
func (it *Item) Children() []*Item {
	if it.Type != TypeStructure {
		return nil
	}
	if children, ok := it.Value.([]*Item); ok {
		return children
	}
	return nil
}

// IntValue returns the value as an int32.
func (it *Item) IntValue() int32 {
	if v, ok := it.Value.(int32); ok {
		return v
	}
	return 0
}

// LongValue returns the value as an int64.
func (it *Item) LongValue() int64 {
	if v, ok := it.Value.(int64); ok {
		return v
	}
	return 0
}

// BoolValue returns the value as a bool.
func (it *Item) BoolValue() bool {
	if v, ok := it.Value.(bool); ok {
		return v
	}
	return false
}

// StringValue returns the value as a string.
func (it *Item) StringValue() string {
	if v, ok := it.Value.(string); ok {
		return v
	}
	return ""
}

// BytesValue returns the value as a byte slice.
func (it *Item) BytesValue() []byte {
	if v, ok := it.Value.([]byte); ok {
		return v
	}
	return nil
}

// --- Encoding ---

// EncodeTTLV encodes a TTLV item to a byte slice.
func EncodeTTLV(tag int, typ int, value []byte) []byte {
	valueLen := len(value)
	padded := int(math.Ceil(float64(valueLen)/8.0)) * 8
	buf := make([]byte, 8+padded)

	// Tag: 3 bytes big-endian
	buf[0] = byte((tag >> 16) & 0xFF)
	buf[1] = byte((tag >> 8) & 0xFF)
	buf[2] = byte(tag & 0xFF)

	// Type: 1 byte
	buf[3] = byte(typ)

	// Length: 4 bytes big-endian
	binary.BigEndian.PutUint32(buf[4:8], uint32(valueLen))

	// Value + padding (padding bytes are already zero)
	copy(buf[8:], value)

	return buf
}

// EncodeStructure encodes a Structure (type 0x01) containing child TTLV items.
func EncodeStructure(tag int, children ...[]byte) []byte {
	totalLen := 0
	for _, child := range children {
		totalLen += len(child)
	}
	inner := make([]byte, 0, totalLen)
	for _, child := range children {
		inner = append(inner, child...)
	}
	return EncodeTTLV(tag, TypeStructure, inner)
}

// EncodeInteger encodes a 32-bit integer.
func EncodeInteger(tag int, value int32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(value))
	return EncodeTTLV(tag, TypeInteger, buf)
}

// EncodeLongInteger encodes a 64-bit long integer.
func EncodeLongInteger(tag int, value int64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(value))
	return EncodeTTLV(tag, TypeLongInteger, buf)
}

// EncodeEnum encodes an enumeration (32-bit).
func EncodeEnum(tag int, value int) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(value))
	return EncodeTTLV(tag, TypeEnumeration, buf)
}

// EncodeBoolean encodes a boolean.
func EncodeBoolean(tag int, value bool) []byte {
	buf := make([]byte, 8)
	if value {
		binary.BigEndian.PutUint64(buf, 1)
	}
	return EncodeTTLV(tag, TypeBoolean, buf)
}

// EncodeTextString encodes a text string (UTF-8).
func EncodeTextString(tag int, value string) []byte {
	return EncodeTTLV(tag, TypeTextString, []byte(value))
}

// EncodeByteString encodes a byte string (raw bytes).
func EncodeByteString(tag int, value []byte) []byte {
	return EncodeTTLV(tag, TypeByteString, value)
}

// EncodeDateTime encodes a DateTime (64-bit POSIX time in seconds).
func EncodeDateTime(tag int, epochSeconds int64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(epochSeconds))
	return EncodeTTLV(tag, TypeDateTime, buf)
}

// --- Decoding ---

// Maximum nesting depth for TTLV structures.
const maxDecodeDepth = 32

// DecodeTTLV decodes a TTLV buffer into a parsed tree.
func DecodeTTLV(data []byte, offset int) (*Item, error) {
	return decodeTTLVDepth(data, offset, 0)
}

func decodeTTLVDepth(data []byte, offset int, depth int) (*Item, error) {
	if depth > maxDecodeDepth {
		return nil, errors.New("TTLV: maximum nesting depth exceeded")
	}
	if len(data)-offset < 8 {
		return nil, errors.New("TTLV buffer too short for header")
	}

	tag := (int(data[offset]) << 16) | (int(data[offset+1]) << 8) | int(data[offset+2])
	typ := int(data[offset+3])
	length := int(binary.BigEndian.Uint32(data[offset+4 : offset+8]))
	padded := int(math.Ceil(float64(length)/8.0)) * 8
	totalLength := 8 + padded
	valueStart := offset + 8

	// Bounds check: ensure declared length fits within buffer.
	if valueStart+padded > len(data) {
		return nil, fmt.Errorf("TTLV: declared length %d exceeds buffer (have %d bytes)", length, len(data)-valueStart)
	}

	var value interface{}
	switch typ {
	case TypeStructure:
		var children []*Item
		pos := valueStart
		end := valueStart + length
		for pos < end {
			child, err := decodeTTLVDepth(data, pos, depth+1)
			if err != nil {
				return nil, err
			}
			children = append(children, child)
			pos += child.TotalLength
		}
		value = children
	case TypeInteger:
		value = int32(binary.BigEndian.Uint32(data[valueStart : valueStart+4]))
	case TypeLongInteger:
		value = int64(binary.BigEndian.Uint64(data[valueStart : valueStart+8]))
	case TypeEnumeration:
		value = int32(binary.BigEndian.Uint32(data[valueStart : valueStart+4]))
	case TypeBoolean:
		value = binary.BigEndian.Uint64(data[valueStart:valueStart+8]) != 0
	case TypeTextString:
		value = string(data[valueStart : valueStart+length])
	case TypeByteString:
		b := make([]byte, length)
		copy(b, data[valueStart:valueStart+length])
		value = b
	case TypeDateTime:
		value = int64(binary.BigEndian.Uint64(data[valueStart : valueStart+8]))
	case TypeBigInteger:
		b := make([]byte, length)
		copy(b, data[valueStart:valueStart+length])
		value = b
	case TypeInterval:
		value = int32(binary.BigEndian.Uint32(data[valueStart : valueStart+4]))
	default:
		b := make([]byte, length)
		copy(b, data[valueStart:valueStart+length])
		value = b
	}

	return &Item{
		Tag:         tag,
		Type:        typ,
		Value:       value,
		Length:      length,
		TotalLength: totalLength,
	}, nil
}

// FindChild finds a child item by tag within a decoded structure.
func FindChild(decoded *Item, tag int) *Item {
	if decoded.Type != TypeStructure {
		return nil
	}
	for _, child := range decoded.Children() {
		if child.Tag == tag {
			return child
		}
	}
	return nil
}

// FindChildren finds all children by tag within a decoded structure.
func FindChildren(decoded *Item, tag int) []*Item {
	var result []*Item
	if decoded.Type != TypeStructure {
		return result
	}
	for _, child := range decoded.Children() {
		if child.Tag == tag {
			result = append(result, child)
		}
	}
	return result
}
