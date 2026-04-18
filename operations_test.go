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
	"errors"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Request building
// ---------------------------------------------------------------------------

func TestRequestBuilding(t *testing.T) {
	t.Run("BuildLocateRequest produces valid TTLV structure", func(t *testing.T) {
		request := BuildLocateRequest("test-key")
		decoded, err := DecodeTTLV(request, 0)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.Tag != TagRequestMessage {
			t.Errorf("tag = 0x%06X, want 0x%06X", decoded.Tag, TagRequestMessage)
		}
		if decoded.Type != TypeStructure {
			t.Errorf("type = %d, want %d", decoded.Type, TypeStructure)
		}
	})

	t.Run("BuildLocateRequest contains protocol version 1.4", func(t *testing.T) {
		decoded, err := DecodeTTLV(BuildLocateRequest("k"), 0)
		if err != nil {
			t.Fatal(err)
		}
		header := FindChild(decoded, TagRequestHeader)
		if header == nil {
			t.Fatal("request header not found")
		}
		version := FindChild(header, TagProtocolVersion)
		if version == nil {
			t.Fatal("protocol version not found")
		}
		major := FindChild(version, TagProtocolVersionMajor)
		minor := FindChild(version, TagProtocolVersionMinor)
		if major == nil || minor == nil {
			t.Fatal("major or minor version not found")
		}
		if major.IntValue() != int32(ProtocolMajor) {
			t.Errorf("major = %d, want %d", major.IntValue(), ProtocolMajor)
		}
		if minor.IntValue() != int32(ProtocolMinor) {
			t.Errorf("minor = %d, want %d", minor.IntValue(), ProtocolMinor)
		}
	})

	t.Run("BuildLocateRequest has batch count 1", func(t *testing.T) {
		decoded, err := DecodeTTLV(BuildLocateRequest("k"), 0)
		if err != nil {
			t.Fatal(err)
		}
		header := FindChild(decoded, TagRequestHeader)
		count := FindChild(header, TagBatchCount)
		if count == nil {
			t.Fatal("batch count not found")
		}
		if count.IntValue() != 1 {
			t.Errorf("batch count = %d, want 1", count.IntValue())
		}
	})

	t.Run("BuildLocateRequest has Locate operation", func(t *testing.T) {
		decoded, err := DecodeTTLV(BuildLocateRequest("k"), 0)
		if err != nil {
			t.Fatal(err)
		}
		batch := FindChild(decoded, TagBatchItem)
		op := FindChild(batch, TagOperation)
		if op == nil {
			t.Fatal("operation not found")
		}
		if int(op.IntValue()) != OperationLocate {
			t.Errorf("operation = 0x%X, want 0x%X", op.IntValue(), OperationLocate)
		}
	})

	t.Run("BuildLocateRequest contains name attribute with correct value", func(t *testing.T) {
		decoded, err := DecodeTTLV(BuildLocateRequest("my-key"), 0)
		if err != nil {
			t.Fatal(err)
		}
		batch := FindChild(decoded, TagBatchItem)
		payload := FindChild(batch, TagRequestPayload)
		attr := FindChild(payload, TagAttribute)
		attrName := FindChild(attr, TagAttributeName)
		if attrName == nil {
			t.Fatal("attribute name not found")
		}
		if attrName.StringValue() != "Name" {
			t.Errorf("attribute name = %q, want %q", attrName.StringValue(), "Name")
		}
		attrValue := FindChild(attr, TagAttributeValue)
		nameValue := FindChild(attrValue, TagNameValue)
		if nameValue == nil {
			t.Fatal("name value not found")
		}
		if nameValue.StringValue() != "my-key" {
			t.Errorf("name value = %q, want %q", nameValue.StringValue(), "my-key")
		}
	})

	t.Run("BuildGetRequest produces valid TTLV structure", func(t *testing.T) {
		request := BuildGetRequest("unique-id-123")
		decoded, err := DecodeTTLV(request, 0)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.Tag != TagRequestMessage {
			t.Errorf("tag = 0x%06X, want 0x%06X", decoded.Tag, TagRequestMessage)
		}
	})

	t.Run("BuildGetRequest has Get operation", func(t *testing.T) {
		decoded, err := DecodeTTLV(BuildGetRequest("uid"), 0)
		if err != nil {
			t.Fatal(err)
		}
		batch := FindChild(decoded, TagBatchItem)
		op := FindChild(batch, TagOperation)
		if op == nil {
			t.Fatal("operation not found")
		}
		if int(op.IntValue()) != OperationGet {
			t.Errorf("operation = 0x%X, want 0x%X", op.IntValue(), OperationGet)
		}
	})

	t.Run("BuildGetRequest contains unique identifier", func(t *testing.T) {
		decoded, err := DecodeTTLV(BuildGetRequest("uid-456"), 0)
		if err != nil {
			t.Fatal(err)
		}
		batch := FindChild(decoded, TagBatchItem)
		payload := FindChild(batch, TagRequestPayload)
		uid := FindChild(payload, TagUniqueIdentifier)
		if uid == nil {
			t.Fatal("unique identifier not found")
		}
		if uid.StringValue() != "uid-456" {
			t.Errorf("uid = %q, want %q", uid.StringValue(), "uid-456")
		}
	})

	t.Run("BuildCreateRequest produces valid TTLV structure", func(t *testing.T) {
		request := BuildCreateRequest("new-key", AlgorithmAES, 256)
		decoded, err := DecodeTTLV(request, 0)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.Tag != TagRequestMessage {
			t.Errorf("tag = 0x%06X, want 0x%06X", decoded.Tag, TagRequestMessage)
		}
	})

	t.Run("BuildCreateRequest has Create operation", func(t *testing.T) {
		decoded, err := DecodeTTLV(BuildCreateRequest("k", AlgorithmAES, 256), 0)
		if err != nil {
			t.Fatal(err)
		}
		batch := FindChild(decoded, TagBatchItem)
		op := FindChild(batch, TagOperation)
		if op == nil {
			t.Fatal("operation not found")
		}
		if int(op.IntValue()) != OperationCreate {
			t.Errorf("operation = 0x%X, want 0x%X", op.IntValue(), OperationCreate)
		}
	})

	t.Run("BuildCreateRequest uses SymmetricKey object type", func(t *testing.T) {
		decoded, err := DecodeTTLV(BuildCreateRequest("k", AlgorithmAES, 256), 0)
		if err != nil {
			t.Fatal(err)
		}
		batch := FindChild(decoded, TagBatchItem)
		payload := FindChild(batch, TagRequestPayload)
		objType := FindChild(payload, TagObjectType)
		if objType == nil {
			t.Fatal("object type not found")
		}
		if int(objType.IntValue()) != ObjectTypeSymmetricKey {
			t.Errorf("object type = 0x%X, want 0x%X", objType.IntValue(), ObjectTypeSymmetricKey)
		}
	})

	t.Run("BuildCreateRequest uses AES algorithm", func(t *testing.T) {
		decoded, err := DecodeTTLV(BuildCreateRequest("k", AlgorithmAES, 256), 0)
		if err != nil {
			t.Fatal(err)
		}
		batch := FindChild(decoded, TagBatchItem)
		payload := FindChild(batch, TagRequestPayload)
		tmpl := FindChild(payload, TagTemplateAttribute)
		algoAttr := findAttributeByName(tmpl, "Cryptographic Algorithm")
		if algoAttr == nil {
			t.Fatal("Cryptographic Algorithm attribute not found")
		}
		algoValue := FindChild(algoAttr, TagAttributeValue)
		if int(algoValue.IntValue()) != AlgorithmAES {
			t.Errorf("algorithm = 0x%X, want 0x%X", algoValue.IntValue(), AlgorithmAES)
		}
	})

	t.Run("BuildCreateRequest uses 256-bit length", func(t *testing.T) {
		decoded, err := DecodeTTLV(BuildCreateRequest("k", AlgorithmAES, 256), 0)
		if err != nil {
			t.Fatal(err)
		}
		batch := FindChild(decoded, TagBatchItem)
		payload := FindChild(batch, TagRequestPayload)
		tmpl := FindChild(payload, TagTemplateAttribute)
		lenAttr := findAttributeByName(tmpl, "Cryptographic Length")
		if lenAttr == nil {
			t.Fatal("Cryptographic Length attribute not found")
		}
		lenValue := FindChild(lenAttr, TagAttributeValue)
		if lenValue.IntValue() != 256 {
			t.Errorf("length = %d, want 256", lenValue.IntValue())
		}
	})

	t.Run("BuildCreateRequest includes encrypt+decrypt usage mask", func(t *testing.T) {
		decoded, err := DecodeTTLV(BuildCreateRequest("k", AlgorithmAES, 256), 0)
		if err != nil {
			t.Fatal(err)
		}
		batch := FindChild(decoded, TagBatchItem)
		payload := FindChild(batch, TagRequestPayload)
		tmpl := FindChild(payload, TagTemplateAttribute)
		usageAttr := findAttributeByName(tmpl, "Cryptographic Usage Mask")
		if usageAttr == nil {
			t.Fatal("Cryptographic Usage Mask attribute not found")
		}
		usageValue := FindChild(usageAttr, TagAttributeValue)
		expected := int32(UsageMaskEncrypt | UsageMaskDecrypt)
		if usageValue.IntValue() != expected {
			t.Errorf("usage mask = 0x%X, want 0x%X", usageValue.IntValue(), expected)
		}
	})

	t.Run("BuildCreateRequest includes key name in template", func(t *testing.T) {
		decoded, err := DecodeTTLV(BuildCreateRequest("prod-key", AlgorithmAES, 256), 0)
		if err != nil {
			t.Fatal(err)
		}
		batch := FindChild(decoded, TagBatchItem)
		payload := FindChild(batch, TagRequestPayload)
		tmpl := FindChild(payload, TagTemplateAttribute)
		nameAttr := findAttributeByName(tmpl, "Name")
		if nameAttr == nil {
			t.Fatal("Name attribute not found")
		}
		nameStruct := FindChild(nameAttr, TagAttributeValue)
		nameValue := FindChild(nameStruct, TagNameValue)
		if nameValue == nil {
			t.Fatal("name value not found")
		}
		if nameValue.StringValue() != "prod-key" {
			t.Errorf("name = %q, want %q", nameValue.StringValue(), "prod-key")
		}
	})

	t.Run("BuildCreateRequest accepts custom algorithm and length", func(t *testing.T) {
		decoded, err := DecodeTTLV(BuildCreateRequest("k", AlgorithmTripleDES, 192), 0)
		if err != nil {
			t.Fatal(err)
		}
		batch := FindChild(decoded, TagBatchItem)
		payload := FindChild(batch, TagRequestPayload)
		tmpl := FindChild(payload, TagTemplateAttribute)

		algoAttr := findAttributeByName(tmpl, "Cryptographic Algorithm")
		algoValue := FindChild(algoAttr, TagAttributeValue)
		if int(algoValue.IntValue()) != AlgorithmTripleDES {
			t.Errorf("algorithm = 0x%X, want 0x%X", algoValue.IntValue(), AlgorithmTripleDES)
		}

		lenAttr := findAttributeByName(tmpl, "Cryptographic Length")
		lenValue := FindChild(lenAttr, TagAttributeValue)
		if lenValue.IntValue() != 192 {
			t.Errorf("length = %d, want 192", lenValue.IntValue())
		}
	})
}

// ---------------------------------------------------------------------------
// Response parsing
// ---------------------------------------------------------------------------

// buildMockResponse constructs a mock KMIP response message for testing.
func buildMockResponse(operation, status int, payloadChildren ...[]byte) []byte {
	batchChildren := [][]byte{
		EncodeEnum(TagOperation, operation),
		EncodeEnum(TagResultStatus, status),
	}
	if len(payloadChildren) > 0 {
		// Build payload with the provided children
		payloadArgs := make([][]byte, 0, len(payloadChildren))
		payloadArgs = append(payloadArgs, payloadChildren...)
		batchChildren = append(batchChildren, EncodeStructure(TagResponsePayload, payloadArgs...))
	}

	return EncodeStructure(TagResponseMessage,
		EncodeStructure(TagResponseHeader,
			EncodeStructure(TagProtocolVersion,
				EncodeInteger(TagProtocolVersionMajor, 1),
				EncodeInteger(TagProtocolVersionMinor, 4),
			),
			EncodeInteger(TagBatchCount, 1),
		),
		EncodeStructure(TagBatchItem, batchChildren...),
	)
}

func TestResponseParsing(t *testing.T) {
	t.Run("ParseResponse extracts operation and status on success", func(t *testing.T) {
		response := buildMockResponse(OperationLocate, ResultStatusSuccess,
			EncodeTextString(TagUniqueIdentifier, "id-1"),
		)
		result, err := ParseResponse(response)
		if err != nil {
			t.Fatal(err)
		}
		if result.Operation != OperationLocate {
			t.Errorf("operation = 0x%X, want 0x%X", result.Operation, OperationLocate)
		}
		if result.ResultStatus != ResultStatusSuccess {
			t.Errorf("status = %d, want %d", result.ResultStatus, ResultStatusSuccess)
		}
	})

	t.Run("ParseResponse returns error on operation failure", func(t *testing.T) {
		batchChildren := [][]byte{
			EncodeEnum(TagOperation, OperationGet),
			EncodeEnum(TagResultStatus, ResultStatusOperationFailed),
			EncodeTextString(TagResultMessage, "Item Not Found"),
		}
		response := EncodeStructure(TagResponseMessage,
			EncodeStructure(TagResponseHeader,
				EncodeStructure(TagProtocolVersion,
					EncodeInteger(TagProtocolVersionMajor, 1),
					EncodeInteger(TagProtocolVersionMinor, 4),
				),
				EncodeInteger(TagBatchCount, 1),
			),
			EncodeStructure(TagBatchItem, batchChildren...),
		)
		_, err := ParseResponse(response)
		if err == nil {
			t.Fatal("expected error for failed operation")
		}
		if !strings.Contains(err.Error(), "Item Not Found") {
			t.Errorf("error = %q, want message containing 'Item Not Found'", err.Error())
		}
		var kmipErr *KmipError
		if !errors.As(err, &kmipErr) {
			t.Fatal("expected KmipError type")
		}
	})

	t.Run("ParseResponse returns error on non-ResponseMessage tag", func(t *testing.T) {
		badMsg := EncodeStructure(TagRequestMessage)
		_, err := ParseResponse(badMsg)
		if err == nil {
			t.Fatal("expected error for wrong message tag")
		}
		if !strings.Contains(err.Error(), "ResponseMessage") {
			t.Errorf("error = %q, want message containing 'ResponseMessage'", err.Error())
		}
	})

	t.Run("ParseLocatePayload extracts unique identifiers", func(t *testing.T) {
		payloadBytes := EncodeStructure(TagResponsePayload,
			EncodeTextString(TagUniqueIdentifier, "uid-1"),
			EncodeTextString(TagUniqueIdentifier, "uid-2"),
			EncodeTextString(TagUniqueIdentifier, "uid-3"),
		)
		payload, err := DecodeTTLV(payloadBytes, 0)
		if err != nil {
			t.Fatal(err)
		}
		result := ParseLocatePayload(payload)
		if len(result.UniqueIdentifiers) != 3 {
			t.Fatalf("count = %d, want 3", len(result.UniqueIdentifiers))
		}
		expected := []string{"uid-1", "uid-2", "uid-3"}
		for i, want := range expected {
			if result.UniqueIdentifiers[i] != want {
				t.Errorf("uid[%d] = %q, want %q", i, result.UniqueIdentifiers[i], want)
			}
		}
	})

	t.Run("ParseLocatePayload handles empty result", func(t *testing.T) {
		payloadBytes := EncodeStructure(TagResponsePayload)
		payload, err := DecodeTTLV(payloadBytes, 0)
		if err != nil {
			t.Fatal(err)
		}
		result := ParseLocatePayload(payload)
		if len(result.UniqueIdentifiers) != 0 {
			t.Errorf("count = %d, want 0", len(result.UniqueIdentifiers))
		}
	})

	t.Run("ParseLocatePayload handles single result", func(t *testing.T) {
		payloadBytes := EncodeStructure(TagResponsePayload,
			EncodeTextString(TagUniqueIdentifier, "only-one"),
		)
		payload, err := DecodeTTLV(payloadBytes, 0)
		if err != nil {
			t.Fatal(err)
		}
		result := ParseLocatePayload(payload)
		if len(result.UniqueIdentifiers) != 1 {
			t.Fatalf("count = %d, want 1", len(result.UniqueIdentifiers))
		}
		if result.UniqueIdentifiers[0] != "only-one" {
			t.Errorf("uid = %q, want %q", result.UniqueIdentifiers[0], "only-one")
		}
	})

	t.Run("ParseGetPayload extracts key material from nested structure", func(t *testing.T) {
		keyBytes := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
			0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}
		payloadBytes := EncodeStructure(TagResponsePayload,
			EncodeTextString(TagUniqueIdentifier, "uid-99"),
			EncodeEnum(TagObjectType, ObjectTypeSymmetricKey),
			EncodeStructure(TagSymmetricKey,
				EncodeStructure(TagKeyBlock,
					EncodeEnum(TagKeyFormatType, KeyFormatRaw),
					EncodeStructure(TagKeyValue,
						EncodeByteString(TagKeyMaterial, keyBytes),
					),
				),
			),
		)
		payload, err := DecodeTTLV(payloadBytes, 0)
		if err != nil {
			t.Fatal(err)
		}
		result := ParseGetPayload(payload)
		if result.UniqueIdentifier != "uid-99" {
			t.Errorf("uid = %q, want %q", result.UniqueIdentifier, "uid-99")
		}
		if result.ObjectType != ObjectTypeSymmetricKey {
			t.Errorf("object type = 0x%X, want 0x%X", result.ObjectType, ObjectTypeSymmetricKey)
		}
		if !bytes.Equal(result.KeyMaterial, keyBytes) {
			t.Errorf("key material = %x, want %x", result.KeyMaterial, keyBytes)
		}
	})

	t.Run("ParseGetPayload returns nil key material when no SymmetricKey", func(t *testing.T) {
		payloadBytes := EncodeStructure(TagResponsePayload,
			EncodeTextString(TagUniqueIdentifier, "uid-50"),
			EncodeEnum(TagObjectType, ObjectTypeCertificate),
		)
		payload, err := DecodeTTLV(payloadBytes, 0)
		if err != nil {
			t.Fatal(err)
		}
		result := ParseGetPayload(payload)
		if result.UniqueIdentifier != "uid-50" {
			t.Errorf("uid = %q, want %q", result.UniqueIdentifier, "uid-50")
		}
		if result.KeyMaterial != nil {
			t.Errorf("key material = %x, want nil", result.KeyMaterial)
		}
	})

	t.Run("ParseCreatePayload extracts object type and unique ID", func(t *testing.T) {
		payloadBytes := EncodeStructure(TagResponsePayload,
			EncodeEnum(TagObjectType, ObjectTypeSymmetricKey),
			EncodeTextString(TagUniqueIdentifier, "new-uid-7"),
		)
		payload, err := DecodeTTLV(payloadBytes, 0)
		if err != nil {
			t.Fatal(err)
		}
		result := ParseCreatePayload(payload)
		if result.ObjectType != ObjectTypeSymmetricKey {
			t.Errorf("object type = 0x%X, want 0x%X", result.ObjectType, ObjectTypeSymmetricKey)
		}
		if result.UniqueIdentifier != "new-uid-7" {
			t.Errorf("uid = %q, want %q", result.UniqueIdentifier, "new-uid-7")
		}
	})
}

// ---------------------------------------------------------------------------
// Round-trip: build -> encode -> decode -> verify
// ---------------------------------------------------------------------------

func TestRoundTrip(t *testing.T) {
	t.Run("Locate request round-trips through TTLV encoding", func(t *testing.T) {
		request := BuildLocateRequest("round-trip-key")
		reEncoded := BuildLocateRequest("round-trip-key")
		if !bytes.Equal(request, reEncoded) {
			t.Error("Locate request is not deterministic")
		}
	})

	t.Run("Get request round-trips through TTLV encoding", func(t *testing.T) {
		request := BuildGetRequest("uid-abc")
		decoded, err := DecodeTTLV(request, 0)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.Tag != TagRequestMessage {
			t.Errorf("tag = 0x%06X, want 0x%06X", decoded.Tag, TagRequestMessage)
		}
		batch := FindChild(decoded, TagBatchItem)
		payload := FindChild(batch, TagRequestPayload)
		uid := FindChild(payload, TagUniqueIdentifier)
		if uid.StringValue() != "uid-abc" {
			t.Errorf("uid = %q, want %q", uid.StringValue(), "uid-abc")
		}
	})

	t.Run("Create request round-trips through TTLV encoding", func(t *testing.T) {
		request := BuildCreateRequest("rt-key", AlgorithmAES, 128)
		decoded, err := DecodeTTLV(request, 0)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.Tag != TagRequestMessage {
			t.Errorf("tag = 0x%06X, want 0x%06X", decoded.Tag, TagRequestMessage)
		}
		batch := FindChild(decoded, TagBatchItem)
		op := FindChild(batch, TagOperation)
		if int(op.IntValue()) != OperationCreate {
			t.Errorf("operation = 0x%X, want 0x%X", op.IntValue(), OperationCreate)
		}
	})
}

// ---------------------------------------------------------------------------
// Helper: find an attribute structure by its AttributeName value
// ---------------------------------------------------------------------------

func findAttributeByName(tmpl *Item, name string) *Item {
	attrs := FindChildren(tmpl, TagAttribute)
	for _, attr := range attrs {
		attrName := FindChild(attr, TagAttributeName)
		if attrName != nil && attrName.StringValue() == name {
			return attr
		}
	}
	return nil
}
