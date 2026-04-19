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

// ---------------------------------------------------------------------------
// Helper: decode a request and extract the batch item's operation + payload
// ---------------------------------------------------------------------------

func decodeRequest(t *testing.T, request []byte) (operation int, payload *Item) {
	t.Helper()
	decoded, err := DecodeTTLV(request, 0)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Tag != TagRequestMessage {
		t.Fatalf("tag = 0x%06X, want 0x%06X (RequestMessage)", decoded.Tag, TagRequestMessage)
	}
	batch := FindChild(decoded, TagBatchItem)
	if batch == nil {
		t.Fatal("BatchItem not found")
	}
	op := FindChild(batch, TagOperation)
	if op == nil {
		t.Fatal("Operation not found")
	}
	payload = FindChild(batch, TagRequestPayload)
	return int(op.IntValue()), payload
}

// ---------------------------------------------------------------------------
// New request builder tests
// ---------------------------------------------------------------------------

func TestBuildCreateKeyPairRequest(t *testing.T) {
	t.Run("valid TTLV with CreateKeyPair operation", func(t *testing.T) {
		op, payload := decodeRequest(t, BuildCreateKeyPairRequest("kp-1", AlgorithmRSA, 2048))
		if op != OperationCreateKeyPair {
			t.Errorf("operation = 0x%X, want 0x%X", op, OperationCreateKeyPair)
		}
		if payload == nil {
			t.Fatal("payload is nil")
		}
	})

	t.Run("template contains algorithm and length", func(t *testing.T) {
		_, payload := decodeRequest(t, BuildCreateKeyPairRequest("kp-2", AlgorithmRSA, 4096))
		tmpl := FindChild(payload, TagTemplateAttribute)
		if tmpl == nil {
			t.Fatal("TemplateAttribute not found")
		}
		algoAttr := findAttributeByName(tmpl, "Cryptographic Algorithm")
		if algoAttr == nil {
			t.Fatal("Cryptographic Algorithm not found")
		}
		algoVal := FindChild(algoAttr, TagAttributeValue)
		if int(algoVal.IntValue()) != AlgorithmRSA {
			t.Errorf("algorithm = 0x%X, want 0x%X", algoVal.IntValue(), AlgorithmRSA)
		}
		lenAttr := findAttributeByName(tmpl, "Cryptographic Length")
		if lenAttr == nil {
			t.Fatal("Cryptographic Length not found")
		}
		lenVal := FindChild(lenAttr, TagAttributeValue)
		if lenVal.IntValue() != 4096 {
			t.Errorf("length = %d, want 4096", lenVal.IntValue())
		}
	})

	t.Run("template contains sign+verify usage mask", func(t *testing.T) {
		_, payload := decodeRequest(t, BuildCreateKeyPairRequest("kp-3", AlgorithmRSA, 2048))
		tmpl := FindChild(payload, TagTemplateAttribute)
		usageAttr := findAttributeByName(tmpl, "Cryptographic Usage Mask")
		if usageAttr == nil {
			t.Fatal("Cryptographic Usage Mask not found")
		}
		usageVal := FindChild(usageAttr, TagAttributeValue)
		expected := int32(UsageMaskSign | UsageMaskVerify)
		if usageVal.IntValue() != expected {
			t.Errorf("usage mask = 0x%X, want 0x%X", usageVal.IntValue(), expected)
		}
	})

	t.Run("template contains name", func(t *testing.T) {
		_, payload := decodeRequest(t, BuildCreateKeyPairRequest("my-keypair", AlgorithmECDSA, 256))
		tmpl := FindChild(payload, TagTemplateAttribute)
		nameAttr := findAttributeByName(tmpl, "Name")
		if nameAttr == nil {
			t.Fatal("Name attribute not found")
		}
		nameStruct := FindChild(nameAttr, TagAttributeValue)
		nameValue := FindChild(nameStruct, TagNameValue)
		if nameValue.StringValue() != "my-keypair" {
			t.Errorf("name = %q, want %q", nameValue.StringValue(), "my-keypair")
		}
	})
}

func TestBuildRegisterRequest(t *testing.T) {
	material := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04}

	t.Run("valid TTLV with Register operation", func(t *testing.T) {
		op, payload := decodeRequest(t, BuildRegisterRequest(ObjectTypeSymmetricKey, material, "reg-key", AlgorithmAES, 128))
		if op != OperationRegister {
			t.Errorf("operation = 0x%X, want 0x%X", op, OperationRegister)
		}
		if payload == nil {
			t.Fatal("payload is nil")
		}
	})

	t.Run("payload contains ObjectType", func(t *testing.T) {
		_, payload := decodeRequest(t, BuildRegisterRequest(ObjectTypeSymmetricKey, material, "reg-key", AlgorithmAES, 128))
		objType := FindChild(payload, TagObjectType)
		if objType == nil {
			t.Fatal("ObjectType not found")
		}
		if int(objType.IntValue()) != ObjectTypeSymmetricKey {
			t.Errorf("ObjectType = 0x%X, want 0x%X", objType.IntValue(), ObjectTypeSymmetricKey)
		}
	})

	t.Run("payload contains key material in SymmetricKey structure", func(t *testing.T) {
		_, payload := decodeRequest(t, BuildRegisterRequest(ObjectTypeSymmetricKey, material, "reg-key", AlgorithmAES, 128))
		symKey := FindChild(payload, TagSymmetricKey)
		if symKey == nil {
			t.Fatal("SymmetricKey not found")
		}
		keyBlock := FindChild(symKey, TagKeyBlock)
		if keyBlock == nil {
			t.Fatal("KeyBlock not found")
		}
		keyValue := FindChild(keyBlock, TagKeyValue)
		if keyValue == nil {
			t.Fatal("KeyValue not found")
		}
		keyMat := FindChild(keyValue, TagKeyMaterial)
		if keyMat == nil {
			t.Fatal("KeyMaterial not found")
		}
		if !bytes.Equal(keyMat.BytesValue(), material) {
			t.Errorf("KeyMaterial = %x, want %x", keyMat.BytesValue(), material)
		}
	})

	t.Run("includes name in template when provided", func(t *testing.T) {
		_, payload := decodeRequest(t, BuildRegisterRequest(ObjectTypeSymmetricKey, material, "named-key", AlgorithmAES, 256))
		tmpl := FindChild(payload, TagTemplateAttribute)
		if tmpl == nil {
			t.Fatal("TemplateAttribute not found when name is provided")
		}
		nameAttr := findAttributeByName(tmpl, "Name")
		if nameAttr == nil {
			t.Fatal("Name attribute not found")
		}
	})

	t.Run("omits template when name is empty", func(t *testing.T) {
		_, payload := decodeRequest(t, BuildRegisterRequest(ObjectTypeSymmetricKey, material, "", AlgorithmAES, 256))
		tmpl := FindChild(payload, TagTemplateAttribute)
		if tmpl != nil {
			t.Error("TemplateAttribute should not be present when name is empty")
		}
	})
}

func TestBuildReKeyRequest(t *testing.T) {
	t.Run("valid TTLV with ReKey operation", func(t *testing.T) {
		op, payload := decodeRequest(t, BuildReKeyRequest("rekey-uid"))
		if op != OperationReKey {
			t.Errorf("operation = 0x%X, want 0x%X", op, OperationReKey)
		}
		uid := FindChild(payload, TagUniqueIdentifier)
		if uid == nil {
			t.Fatal("UniqueIdentifier not found")
		}
		if uid.StringValue() != "rekey-uid" {
			t.Errorf("uid = %q, want %q", uid.StringValue(), "rekey-uid")
		}
	})
}

func TestBuildDeriveKeyRequest(t *testing.T) {
	derivData := []byte{0x01, 0x02, 0x03, 0x04}

	t.Run("valid TTLV with DeriveKey operation", func(t *testing.T) {
		op, payload := decodeRequest(t, BuildDeriveKeyRequest("dk-uid", derivData, "derived-key", 256))
		if op != OperationDeriveKey {
			t.Errorf("operation = 0x%X, want 0x%X", op, OperationDeriveKey)
		}
		if payload == nil {
			t.Fatal("payload is nil")
		}
	})

	t.Run("contains UID", func(t *testing.T) {
		_, payload := decodeRequest(t, BuildDeriveKeyRequest("dk-uid", derivData, "derived-key", 256))
		uid := FindChild(payload, TagUniqueIdentifier)
		if uid == nil || uid.StringValue() != "dk-uid" {
			t.Errorf("uid = %v, want %q", uid, "dk-uid")
		}
	})

	t.Run("contains derivation data", func(t *testing.T) {
		_, payload := decodeRequest(t, BuildDeriveKeyRequest("dk-uid", derivData, "derived-key", 256))
		derivParams := FindChild(payload, TagDerivationParameters)
		if derivParams == nil {
			t.Fatal("DerivationParameters not found")
		}
		data := FindChild(derivParams, TagDerivationData)
		if data == nil {
			t.Fatal("DerivationData not found")
		}
		if !bytes.Equal(data.BytesValue(), derivData) {
			t.Errorf("derivation data = %x, want %x", data.BytesValue(), derivData)
		}
	})
}

func TestBuildCheckRequest(t *testing.T) {
	t.Run("valid TTLV with Check operation and UID", func(t *testing.T) {
		op, payload := decodeRequest(t, BuildCheckRequest("check-uid"))
		if op != OperationCheck {
			t.Errorf("operation = 0x%X, want 0x%X", op, OperationCheck)
		}
		uid := FindChild(payload, TagUniqueIdentifier)
		if uid == nil || uid.StringValue() != "check-uid" {
			t.Errorf("uid = %v, want %q", uid, "check-uid")
		}
	})
}

func TestBuildGetAttributesRequest(t *testing.T) {
	t.Run("valid TTLV with GetAttributes operation and UID", func(t *testing.T) {
		op, payload := decodeRequest(t, BuildGetAttributesRequest("ga-uid"))
		if op != OperationGetAttributes {
			t.Errorf("operation = 0x%X, want 0x%X", op, OperationGetAttributes)
		}
		uid := FindChild(payload, TagUniqueIdentifier)
		if uid == nil || uid.StringValue() != "ga-uid" {
			t.Errorf("uid = %v, want %q", uid, "ga-uid")
		}
	})
}

func TestBuildGetAttributeListRequest(t *testing.T) {
	t.Run("valid TTLV with GetAttributeList operation and UID", func(t *testing.T) {
		op, payload := decodeRequest(t, BuildGetAttributeListRequest("gal-uid"))
		if op != OperationGetAttributeList {
			t.Errorf("operation = 0x%X, want 0x%X", op, OperationGetAttributeList)
		}
		uid := FindChild(payload, TagUniqueIdentifier)
		if uid == nil || uid.StringValue() != "gal-uid" {
			t.Errorf("uid = %v, want %q", uid, "gal-uid")
		}
	})
}

func TestBuildAddAttributeRequest(t *testing.T) {
	t.Run("valid TTLV with AddAttribute operation", func(t *testing.T) {
		op, payload := decodeRequest(t, BuildAddAttributeRequest("aa-uid", "x-custom", "value-1"))
		if op != OperationAddAttribute {
			t.Errorf("operation = 0x%X, want 0x%X", op, OperationAddAttribute)
		}
		uid := FindChild(payload, TagUniqueIdentifier)
		if uid == nil || uid.StringValue() != "aa-uid" {
			t.Errorf("uid = %v, want %q", uid, "aa-uid")
		}
	})

	t.Run("contains attribute name and value", func(t *testing.T) {
		_, payload := decodeRequest(t, BuildAddAttributeRequest("aa-uid", "x-custom", "value-1"))
		attr := FindChild(payload, TagAttribute)
		if attr == nil {
			t.Fatal("Attribute not found")
		}
		attrName := FindChild(attr, TagAttributeName)
		if attrName == nil || attrName.StringValue() != "x-custom" {
			t.Errorf("attribute name = %v, want %q", attrName, "x-custom")
		}
		attrValue := FindChild(attr, TagAttributeValue)
		if attrValue == nil || attrValue.StringValue() != "value-1" {
			t.Errorf("attribute value = %v, want %q", attrValue, "value-1")
		}
	})
}

func TestBuildModifyAttributeRequest(t *testing.T) {
	t.Run("valid TTLV with ModifyAttribute operation", func(t *testing.T) {
		op, payload := decodeRequest(t, BuildModifyAttributeRequest("ma-uid", "x-label", "new-value"))
		if op != OperationModifyAttribute {
			t.Errorf("operation = 0x%X, want 0x%X", op, OperationModifyAttribute)
		}
		uid := FindChild(payload, TagUniqueIdentifier)
		if uid == nil || uid.StringValue() != "ma-uid" {
			t.Errorf("uid = %v, want %q", uid, "ma-uid")
		}
		attr := FindChild(payload, TagAttribute)
		if attr == nil {
			t.Fatal("Attribute not found")
		}
		attrName := FindChild(attr, TagAttributeName)
		if attrName.StringValue() != "x-label" {
			t.Errorf("attr name = %q, want %q", attrName.StringValue(), "x-label")
		}
		attrValue := FindChild(attr, TagAttributeValue)
		if attrValue.StringValue() != "new-value" {
			t.Errorf("attr value = %q, want %q", attrValue.StringValue(), "new-value")
		}
	})
}

func TestBuildDeleteAttributeRequest(t *testing.T) {
	t.Run("valid TTLV with DeleteAttribute operation", func(t *testing.T) {
		op, payload := decodeRequest(t, BuildDeleteAttributeRequest("da-uid", "x-old"))
		if op != OperationDeleteAttribute {
			t.Errorf("operation = 0x%X, want 0x%X", op, OperationDeleteAttribute)
		}
		uid := FindChild(payload, TagUniqueIdentifier)
		if uid == nil || uid.StringValue() != "da-uid" {
			t.Errorf("uid = %v, want %q", uid, "da-uid")
		}
		attr := FindChild(payload, TagAttribute)
		if attr == nil {
			t.Fatal("Attribute not found")
		}
		attrName := FindChild(attr, TagAttributeName)
		if attrName.StringValue() != "x-old" {
			t.Errorf("attr name = %q, want %q", attrName.StringValue(), "x-old")
		}
	})
}

func TestBuildObtainLeaseRequest(t *testing.T) {
	t.Run("valid TTLV with ObtainLease operation and UID", func(t *testing.T) {
		op, payload := decodeRequest(t, BuildObtainLeaseRequest("ol-uid"))
		if op != OperationObtainLease {
			t.Errorf("operation = 0x%X, want 0x%X", op, OperationObtainLease)
		}
		uid := FindChild(payload, TagUniqueIdentifier)
		if uid == nil || uid.StringValue() != "ol-uid" {
			t.Errorf("uid = %v, want %q", uid, "ol-uid")
		}
	})
}

func TestBuildRevokeRequest(t *testing.T) {
	t.Run("valid TTLV with Revoke operation", func(t *testing.T) {
		op, payload := decodeRequest(t, BuildRevokeRequest("rev-uid", 1))
		if op != OperationRevoke {
			t.Errorf("operation = 0x%X, want 0x%X", op, OperationRevoke)
		}
		uid := FindChild(payload, TagUniqueIdentifier)
		if uid == nil || uid.StringValue() != "rev-uid" {
			t.Errorf("uid = %v, want %q", uid, "rev-uid")
		}
	})

	t.Run("contains revocation reason", func(t *testing.T) {
		_, payload := decodeRequest(t, BuildRevokeRequest("rev-uid", 5))
		revReason := FindChild(payload, TagRevocationReason)
		if revReason == nil {
			t.Fatal("RevocationReason not found")
		}
		code := FindChild(revReason, TagRevocationReasonCode)
		if code == nil {
			t.Fatal("RevocationReasonCode not found")
		}
		if int(code.IntValue()) != 5 {
			t.Errorf("reason code = %d, want 5", code.IntValue())
		}
	})
}

func TestBuildArchiveRequest(t *testing.T) {
	t.Run("valid TTLV with Archive operation and UID", func(t *testing.T) {
		op, payload := decodeRequest(t, BuildArchiveRequest("arc-uid"))
		if op != OperationArchive {
			t.Errorf("operation = 0x%X, want 0x%X", op, OperationArchive)
		}
		uid := FindChild(payload, TagUniqueIdentifier)
		if uid == nil || uid.StringValue() != "arc-uid" {
			t.Errorf("uid = %v, want %q", uid, "arc-uid")
		}
	})
}

func TestBuildRecoverRequest(t *testing.T) {
	t.Run("valid TTLV with Recover operation and UID", func(t *testing.T) {
		op, payload := decodeRequest(t, BuildRecoverRequest("rec-uid"))
		if op != OperationRecover {
			t.Errorf("operation = 0x%X, want 0x%X", op, OperationRecover)
		}
		uid := FindChild(payload, TagUniqueIdentifier)
		if uid == nil || uid.StringValue() != "rec-uid" {
			t.Errorf("uid = %v, want %q", uid, "rec-uid")
		}
	})
}

func TestBuildQueryRequest(t *testing.T) {
	t.Run("valid TTLV with Query operation", func(t *testing.T) {
		op, payload := decodeRequest(t, BuildQueryRequest())
		if op != OperationQuery {
			t.Errorf("operation = 0x%X, want 0x%X", op, OperationQuery)
		}
		if payload == nil {
			t.Fatal("payload is nil")
		}
	})
}

func TestBuildPollRequest(t *testing.T) {
	t.Run("valid TTLV with Poll operation", func(t *testing.T) {
		op, payload := decodeRequest(t, BuildPollRequest())
		if op != OperationPoll {
			t.Errorf("operation = 0x%X, want 0x%X", op, OperationPoll)
		}
		if payload == nil {
			t.Fatal("payload is nil")
		}
	})
}

func TestBuildDiscoverVersionsRequest(t *testing.T) {
	t.Run("valid TTLV with DiscoverVersions operation", func(t *testing.T) {
		op, payload := decodeRequest(t, BuildDiscoverVersionsRequest())
		if op != OperationDiscoverVersions {
			t.Errorf("operation = 0x%X, want 0x%X", op, OperationDiscoverVersions)
		}
		if payload == nil {
			t.Fatal("payload is nil")
		}
	})
}

func TestBuildEncryptRequest(t *testing.T) {
	t.Run("valid TTLV with Encrypt operation", func(t *testing.T) {
		op, payload := decodeRequest(t, BuildEncryptRequest("enc-uid", []byte("plaintext")))
		if op != OperationEncrypt {
			t.Errorf("operation = 0x%X, want 0x%X", op, OperationEncrypt)
		}
		uid := FindChild(payload, TagUniqueIdentifier)
		if uid == nil || uid.StringValue() != "enc-uid" {
			t.Errorf("uid = %v, want %q", uid, "enc-uid")
		}
	})

	t.Run("contains Data field", func(t *testing.T) {
		_, payload := decodeRequest(t, BuildEncryptRequest("enc-uid", []byte("hello")))
		data := FindChild(payload, TagData)
		if data == nil {
			t.Fatal("Data not found")
		}
		if !bytes.Equal(data.BytesValue(), []byte("hello")) {
			t.Errorf("Data = %x, want %x", data.BytesValue(), []byte("hello"))
		}
	})
}

func TestBuildDecryptRequest(t *testing.T) {
	t.Run("valid TTLV with Decrypt operation", func(t *testing.T) {
		op, payload := decodeRequest(t, BuildDecryptRequest("dec-uid", []byte("ciphertext"), []byte("nonce12")))
		if op != OperationDecrypt {
			t.Errorf("operation = 0x%X, want 0x%X", op, OperationDecrypt)
		}
		uid := FindChild(payload, TagUniqueIdentifier)
		if uid == nil || uid.StringValue() != "dec-uid" {
			t.Errorf("uid = %v, want %q", uid, "dec-uid")
		}
	})

	t.Run("contains Data and IVCounterNonce", func(t *testing.T) {
		_, payload := decodeRequest(t, BuildDecryptRequest("dec-uid", []byte("ct"), []byte("iv123")))
		data := FindChild(payload, TagData)
		if data == nil {
			t.Fatal("Data not found")
		}
		if !bytes.Equal(data.BytesValue(), []byte("ct")) {
			t.Errorf("Data = %x, want %x", data.BytesValue(), []byte("ct"))
		}
		nonce := FindChild(payload, TagIVCounterNonce)
		if nonce == nil {
			t.Fatal("IVCounterNonce not found")
		}
		if !bytes.Equal(nonce.BytesValue(), []byte("iv123")) {
			t.Errorf("nonce = %x, want %x", nonce.BytesValue(), []byte("iv123"))
		}
	})

	t.Run("omits IVCounterNonce when nil", func(t *testing.T) {
		_, payload := decodeRequest(t, BuildDecryptRequest("dec-uid", []byte("ct"), nil))
		nonce := FindChild(payload, TagIVCounterNonce)
		if nonce != nil {
			t.Error("IVCounterNonce should be omitted when nil")
		}
	})
}

func TestBuildSignRequest(t *testing.T) {
	t.Run("valid TTLV with Sign operation", func(t *testing.T) {
		op, payload := decodeRequest(t, BuildSignRequest("sign-uid", []byte("message")))
		if op != OperationSign {
			t.Errorf("operation = 0x%X, want 0x%X", op, OperationSign)
		}
		uid := FindChild(payload, TagUniqueIdentifier)
		if uid == nil || uid.StringValue() != "sign-uid" {
			t.Errorf("uid = %v, want %q", uid, "sign-uid")
		}
		data := FindChild(payload, TagData)
		if data == nil {
			t.Fatal("Data not found")
		}
		if !bytes.Equal(data.BytesValue(), []byte("message")) {
			t.Errorf("Data = %x, want %x", data.BytesValue(), []byte("message"))
		}
	})
}

func TestBuildSignatureVerifyRequest(t *testing.T) {
	t.Run("valid TTLV with SignatureVerify operation", func(t *testing.T) {
		op, payload := decodeRequest(t, BuildSignatureVerifyRequest("sv-uid", []byte("msg"), []byte("sig")))
		if op != OperationSignatureVerify {
			t.Errorf("operation = 0x%X, want 0x%X", op, OperationSignatureVerify)
		}
		uid := FindChild(payload, TagUniqueIdentifier)
		if uid == nil || uid.StringValue() != "sv-uid" {
			t.Errorf("uid = %v, want %q", uid, "sv-uid")
		}
	})

	t.Run("contains Data and SignatureData", func(t *testing.T) {
		_, payload := decodeRequest(t, BuildSignatureVerifyRequest("sv-uid", []byte("msg"), []byte("sig")))
		data := FindChild(payload, TagData)
		if data == nil {
			t.Fatal("Data not found")
		}
		if !bytes.Equal(data.BytesValue(), []byte("msg")) {
			t.Errorf("Data = %x, want %x", data.BytesValue(), []byte("msg"))
		}
		sigData := FindChild(payload, TagSignatureData)
		if sigData == nil {
			t.Fatal("SignatureData not found")
		}
		if !bytes.Equal(sigData.BytesValue(), []byte("sig")) {
			t.Errorf("SignatureData = %x, want %x", sigData.BytesValue(), []byte("sig"))
		}
	})
}

func TestBuildMACRequest(t *testing.T) {
	t.Run("valid TTLV with MAC operation", func(t *testing.T) {
		op, payload := decodeRequest(t, BuildMACRequest("mac-uid", []byte("data")))
		if op != OperationMAC {
			t.Errorf("operation = 0x%X, want 0x%X", op, OperationMAC)
		}
		uid := FindChild(payload, TagUniqueIdentifier)
		if uid == nil || uid.StringValue() != "mac-uid" {
			t.Errorf("uid = %v, want %q", uid, "mac-uid")
		}
		data := FindChild(payload, TagData)
		if data == nil {
			t.Fatal("Data not found")
		}
		if !bytes.Equal(data.BytesValue(), []byte("data")) {
			t.Errorf("Data = %x, want %x", data.BytesValue(), []byte("data"))
		}
	})
}

// ---------------------------------------------------------------------------
// New response parser tests
// ---------------------------------------------------------------------------

func TestParseCheckPayload(t *testing.T) {
	t.Run("extracts UID from payload", func(t *testing.T) {
		payloadBytes := EncodeStructure(TagResponsePayload,
			EncodeTextString(TagUniqueIdentifier, "check-uid-1"),
		)
		payload, err := DecodeTTLV(payloadBytes, 0)
		if err != nil {
			t.Fatal(err)
		}
		result := ParseCheckPayload(payload)
		if result.UniqueIdentifier != "check-uid-1" {
			t.Errorf("uid = %q, want %q", result.UniqueIdentifier, "check-uid-1")
		}
	})

	t.Run("nil payload returns empty result", func(t *testing.T) {
		result := ParseCheckPayload(nil)
		if result.UniqueIdentifier != "" {
			t.Errorf("uid = %q, want empty", result.UniqueIdentifier)
		}
	})
}

func TestParseReKeyPayload(t *testing.T) {
	t.Run("extracts UID from payload", func(t *testing.T) {
		payloadBytes := EncodeStructure(TagResponsePayload,
			EncodeTextString(TagUniqueIdentifier, "rekey-new-uid"),
		)
		payload, err := DecodeTTLV(payloadBytes, 0)
		if err != nil {
			t.Fatal(err)
		}
		result := ParseReKeyPayload(payload)
		if result.UniqueIdentifier != "rekey-new-uid" {
			t.Errorf("uid = %q, want %q", result.UniqueIdentifier, "rekey-new-uid")
		}
	})

	t.Run("nil payload returns empty result", func(t *testing.T) {
		result := ParseReKeyPayload(nil)
		if result.UniqueIdentifier != "" {
			t.Errorf("uid = %q, want empty", result.UniqueIdentifier)
		}
	})
}

func TestParseEncryptPayload(t *testing.T) {
	t.Run("extracts Data and Nonce", func(t *testing.T) {
		payloadBytes := EncodeStructure(TagResponsePayload,
			EncodeByteString(TagData, []byte("ciphertext")),
			EncodeByteString(TagIVCounterNonce, []byte("nonce12bytes")),
		)
		payload, err := DecodeTTLV(payloadBytes, 0)
		if err != nil {
			t.Fatal(err)
		}
		result := ParseEncryptPayload(payload)
		if !bytes.Equal(result.Data, []byte("ciphertext")) {
			t.Errorf("Data = %x, want %x", result.Data, []byte("ciphertext"))
		}
		if !bytes.Equal(result.Nonce, []byte("nonce12bytes")) {
			t.Errorf("Nonce = %x, want %x", result.Nonce, []byte("nonce12bytes"))
		}
	})

	t.Run("extracts Data without Nonce", func(t *testing.T) {
		payloadBytes := EncodeStructure(TagResponsePayload,
			EncodeByteString(TagData, []byte("ct-only")),
		)
		payload, err := DecodeTTLV(payloadBytes, 0)
		if err != nil {
			t.Fatal(err)
		}
		result := ParseEncryptPayload(payload)
		if !bytes.Equal(result.Data, []byte("ct-only")) {
			t.Errorf("Data = %x, want %x", result.Data, []byte("ct-only"))
		}
		if result.Nonce != nil {
			t.Errorf("Nonce = %x, want nil", result.Nonce)
		}
	})

	t.Run("nil payload returns empty result", func(t *testing.T) {
		result := ParseEncryptPayload(nil)
		if result.Data != nil {
			t.Errorf("Data = %x, want nil", result.Data)
		}
		if result.Nonce != nil {
			t.Errorf("Nonce = %x, want nil", result.Nonce)
		}
	})
}

func TestParseDecryptPayload(t *testing.T) {
	t.Run("extracts Data", func(t *testing.T) {
		payloadBytes := EncodeStructure(TagResponsePayload,
			EncodeByteString(TagData, []byte("plaintext")),
		)
		payload, err := DecodeTTLV(payloadBytes, 0)
		if err != nil {
			t.Fatal(err)
		}
		result := ParseDecryptPayload(payload)
		if !bytes.Equal(result.Data, []byte("plaintext")) {
			t.Errorf("Data = %x, want %x", result.Data, []byte("plaintext"))
		}
	})

	t.Run("nil payload returns empty result", func(t *testing.T) {
		result := ParseDecryptPayload(nil)
		if result.Data != nil {
			t.Errorf("Data = %x, want nil", result.Data)
		}
	})
}

func TestParseSignPayload(t *testing.T) {
	t.Run("extracts SignatureData", func(t *testing.T) {
		payloadBytes := EncodeStructure(TagResponsePayload,
			EncodeByteString(TagSignatureData, []byte("signature-bytes")),
		)
		payload, err := DecodeTTLV(payloadBytes, 0)
		if err != nil {
			t.Fatal(err)
		}
		result := ParseSignPayload(payload)
		if !bytes.Equal(result.SignatureData, []byte("signature-bytes")) {
			t.Errorf("SignatureData = %x, want %x", result.SignatureData, []byte("signature-bytes"))
		}
	})

	t.Run("nil payload returns empty result", func(t *testing.T) {
		result := ParseSignPayload(nil)
		if result.SignatureData != nil {
			t.Errorf("SignatureData = %x, want nil", result.SignatureData)
		}
	})
}

func TestParseSignatureVerifyPayload(t *testing.T) {
	t.Run("valid when indicator is 0", func(t *testing.T) {
		payloadBytes := EncodeStructure(TagResponsePayload,
			EncodeEnum(TagValidityIndicator, 0),
		)
		payload, err := DecodeTTLV(payloadBytes, 0)
		if err != nil {
			t.Fatal(err)
		}
		result := ParseSignatureVerifyPayload(payload)
		if !result.Valid {
			t.Error("Valid = false, want true (indicator=0)")
		}
	})

	t.Run("invalid when indicator is 1", func(t *testing.T) {
		payloadBytes := EncodeStructure(TagResponsePayload,
			EncodeEnum(TagValidityIndicator, 1),
		)
		payload, err := DecodeTTLV(payloadBytes, 0)
		if err != nil {
			t.Fatal(err)
		}
		result := ParseSignatureVerifyPayload(payload)
		if result.Valid {
			t.Error("Valid = true, want false (indicator=1)")
		}
	})

	t.Run("nil payload returns empty result (Valid=false)", func(t *testing.T) {
		result := ParseSignatureVerifyPayload(nil)
		if result.Valid {
			t.Error("Valid = true, want false for nil payload")
		}
	})
}

func TestParseMACPayload(t *testing.T) {
	t.Run("extracts MACData", func(t *testing.T) {
		payloadBytes := EncodeStructure(TagResponsePayload,
			EncodeByteString(TagMACData, []byte("mac-output")),
		)
		payload, err := DecodeTTLV(payloadBytes, 0)
		if err != nil {
			t.Fatal(err)
		}
		result := ParseMACPayload(payload)
		if !bytes.Equal(result.MACData, []byte("mac-output")) {
			t.Errorf("MACData = %x, want %x", result.MACData, []byte("mac-output"))
		}
	})

	t.Run("nil payload returns empty result", func(t *testing.T) {
		result := ParseMACPayload(nil)
		if result.MACData != nil {
			t.Errorf("MACData = %x, want nil", result.MACData)
		}
	})
}

func TestParseQueryPayload(t *testing.T) {
	t.Run("extracts operations and object types", func(t *testing.T) {
		payloadBytes := EncodeStructure(TagResponsePayload,
			EncodeEnum(TagOperation, OperationCreate),
			EncodeEnum(TagOperation, OperationGet),
			EncodeEnum(TagOperation, OperationDestroy),
			EncodeEnum(TagObjectType, ObjectTypeSymmetricKey),
			EncodeEnum(TagObjectType, ObjectTypePublicKey),
		)
		payload, err := DecodeTTLV(payloadBytes, 0)
		if err != nil {
			t.Fatal(err)
		}
		result := ParseQueryPayload(payload)
		if len(result.Operations) != 3 {
			t.Fatalf("operations count = %d, want 3", len(result.Operations))
		}
		if result.Operations[0] != OperationCreate {
			t.Errorf("ops[0] = 0x%X, want 0x%X", result.Operations[0], OperationCreate)
		}
		if result.Operations[1] != OperationGet {
			t.Errorf("ops[1] = 0x%X, want 0x%X", result.Operations[1], OperationGet)
		}
		if result.Operations[2] != OperationDestroy {
			t.Errorf("ops[2] = 0x%X, want 0x%X", result.Operations[2], OperationDestroy)
		}
		if len(result.ObjectTypes) != 2 {
			t.Fatalf("object types count = %d, want 2", len(result.ObjectTypes))
		}
		if result.ObjectTypes[0] != ObjectTypeSymmetricKey {
			t.Errorf("types[0] = 0x%X, want 0x%X", result.ObjectTypes[0], ObjectTypeSymmetricKey)
		}
		if result.ObjectTypes[1] != ObjectTypePublicKey {
			t.Errorf("types[1] = 0x%X, want 0x%X", result.ObjectTypes[1], ObjectTypePublicKey)
		}
	})

	t.Run("nil payload returns empty slices", func(t *testing.T) {
		result := ParseQueryPayload(nil)
		if len(result.Operations) != 0 {
			t.Errorf("operations count = %d, want 0", len(result.Operations))
		}
		if len(result.ObjectTypes) != 0 {
			t.Errorf("object types count = %d, want 0", len(result.ObjectTypes))
		}
	})
}

func TestParseDiscoverVersionsPayload(t *testing.T) {
	t.Run("extracts versions", func(t *testing.T) {
		payloadBytes := EncodeStructure(TagResponsePayload,
			EncodeStructure(TagProtocolVersion,
				EncodeInteger(TagProtocolVersionMajor, 1),
				EncodeInteger(TagProtocolVersionMinor, 4),
			),
			EncodeStructure(TagProtocolVersion,
				EncodeInteger(TagProtocolVersionMajor, 1),
				EncodeInteger(TagProtocolVersionMinor, 3),
			),
		)
		payload, err := DecodeTTLV(payloadBytes, 0)
		if err != nil {
			t.Fatal(err)
		}
		result := ParseDiscoverVersionsPayload(payload)
		if len(result.Versions) != 2 {
			t.Fatalf("versions count = %d, want 2", len(result.Versions))
		}
		if result.Versions[0].Major != 1 || result.Versions[0].Minor != 4 {
			t.Errorf("versions[0] = %d.%d, want 1.4", result.Versions[0].Major, result.Versions[0].Minor)
		}
		if result.Versions[1].Major != 1 || result.Versions[1].Minor != 3 {
			t.Errorf("versions[1] = %d.%d, want 1.3", result.Versions[1].Major, result.Versions[1].Minor)
		}
	})

	t.Run("nil payload returns empty result", func(t *testing.T) {
		result := ParseDiscoverVersionsPayload(nil)
		if len(result.Versions) != 0 {
			t.Errorf("versions count = %d, want 0", len(result.Versions))
		}
	})
}

func TestParseDeriveKeyPayload(t *testing.T) {
	t.Run("extracts UID", func(t *testing.T) {
		payloadBytes := EncodeStructure(TagResponsePayload,
			EncodeTextString(TagUniqueIdentifier, "derived-uid-42"),
		)
		payload, err := DecodeTTLV(payloadBytes, 0)
		if err != nil {
			t.Fatal(err)
		}
		result := ParseDeriveKeyPayload(payload)
		if result.UniqueIdentifier != "derived-uid-42" {
			t.Errorf("uid = %q, want %q", result.UniqueIdentifier, "derived-uid-42")
		}
	})

	t.Run("nil payload returns empty result", func(t *testing.T) {
		result := ParseDeriveKeyPayload(nil)
		if result.UniqueIdentifier != "" {
			t.Errorf("uid = %q, want empty", result.UniqueIdentifier)
		}
	})
}

func TestParseCreateKeyPairPayload(t *testing.T) {
	t.Run("extracts private and public UIDs", func(t *testing.T) {
		payloadBytes := EncodeStructure(TagResponsePayload,
			EncodeTextString(TagPrivateKeyUniqueIdentifier, "priv-uid-1"),
			EncodeTextString(TagPublicKeyUniqueIdentifier, "pub-uid-1"),
		)
		payload, err := DecodeTTLV(payloadBytes, 0)
		if err != nil {
			t.Fatal(err)
		}
		result := ParseCreateKeyPairPayload(payload)
		if result.PrivateKeyUID != "priv-uid-1" {
			t.Errorf("PrivateKeyUID = %q, want %q", result.PrivateKeyUID, "priv-uid-1")
		}
		if result.PublicKeyUID != "pub-uid-1" {
			t.Errorf("PublicKeyUID = %q, want %q", result.PublicKeyUID, "pub-uid-1")
		}
	})

	t.Run("nil payload returns empty result", func(t *testing.T) {
		result := ParseCreateKeyPairPayload(nil)
		if result.PrivateKeyUID != "" {
			t.Errorf("PrivateKeyUID = %q, want empty", result.PrivateKeyUID)
		}
		if result.PublicKeyUID != "" {
			t.Errorf("PublicKeyUID = %q, want empty", result.PublicKeyUID)
		}
	})
}

// ---------------------------------------------------------------------------
// Round-trip tests for new operations
// ---------------------------------------------------------------------------

func TestRoundTrip_Encrypt(t *testing.T) {
	request := BuildEncryptRequest("uid-1", []byte("hello"))
	decoded, err := DecodeTTLV(request, 0)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Tag != TagRequestMessage {
		t.Errorf("tag = 0x%06X, want 0x%06X", decoded.Tag, TagRequestMessage)
	}
	batch := FindChild(decoded, TagBatchItem)
	op := FindChild(batch, TagOperation)
	if int(op.IntValue()) != OperationEncrypt {
		t.Errorf("operation = 0x%X, want 0x%X", op.IntValue(), OperationEncrypt)
	}
	payload := FindChild(batch, TagRequestPayload)
	uid := FindChild(payload, TagUniqueIdentifier)
	if uid.StringValue() != "uid-1" {
		t.Errorf("uid = %q, want %q", uid.StringValue(), "uid-1")
	}
	data := FindChild(payload, TagData)
	if !bytes.Equal(data.BytesValue(), []byte("hello")) {
		t.Errorf("data = %x, want %x", data.BytesValue(), []byte("hello"))
	}
}

func TestRoundTrip_Decrypt(t *testing.T) {
	request := BuildDecryptRequest("uid-2", []byte("ciphertext"), []byte("nonce"))
	decoded, err := DecodeTTLV(request, 0)
	if err != nil {
		t.Fatal(err)
	}
	batch := FindChild(decoded, TagBatchItem)
	op := FindChild(batch, TagOperation)
	if int(op.IntValue()) != OperationDecrypt {
		t.Errorf("operation = 0x%X, want 0x%X", op.IntValue(), OperationDecrypt)
	}
	payload := FindChild(batch, TagRequestPayload)
	nonce := FindChild(payload, TagIVCounterNonce)
	if !bytes.Equal(nonce.BytesValue(), []byte("nonce")) {
		t.Errorf("nonce = %x, want %x", nonce.BytesValue(), []byte("nonce"))
	}
}

func TestRoundTrip_Sign(t *testing.T) {
	request := BuildSignRequest("uid-3", []byte("tosign"))
	decoded, err := DecodeTTLV(request, 0)
	if err != nil {
		t.Fatal(err)
	}
	batch := FindChild(decoded, TagBatchItem)
	op := FindChild(batch, TagOperation)
	if int(op.IntValue()) != OperationSign {
		t.Errorf("operation = 0x%X, want 0x%X", op.IntValue(), OperationSign)
	}
}

func TestRoundTrip_MAC(t *testing.T) {
	request := BuildMACRequest("uid-4", []byte("macdata"))
	decoded, err := DecodeTTLV(request, 0)
	if err != nil {
		t.Fatal(err)
	}
	batch := FindChild(decoded, TagBatchItem)
	op := FindChild(batch, TagOperation)
	if int(op.IntValue()) != OperationMAC {
		t.Errorf("operation = 0x%X, want 0x%X", op.IntValue(), OperationMAC)
	}
}

func TestRoundTrip_CreateKeyPair(t *testing.T) {
	request := BuildCreateKeyPairRequest("kp-rt", AlgorithmRSA, 2048)
	decoded, err := DecodeTTLV(request, 0)
	if err != nil {
		t.Fatal(err)
	}
	batch := FindChild(decoded, TagBatchItem)
	op := FindChild(batch, TagOperation)
	if int(op.IntValue()) != OperationCreateKeyPair {
		t.Errorf("operation = 0x%X, want 0x%X", op.IntValue(), OperationCreateKeyPair)
	}
}

func TestRoundTrip_Register(t *testing.T) {
	material := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	request := BuildRegisterRequest(ObjectTypeSymmetricKey, material, "reg-rt", AlgorithmAES, 128)
	decoded, err := DecodeTTLV(request, 0)
	if err != nil {
		t.Fatal(err)
	}
	batch := FindChild(decoded, TagBatchItem)
	op := FindChild(batch, TagOperation)
	if int(op.IntValue()) != OperationRegister {
		t.Errorf("operation = 0x%X, want 0x%X", op.IntValue(), OperationRegister)
	}
}

func TestRoundTrip_DeriveKey(t *testing.T) {
	request := BuildDeriveKeyRequest("dk-rt", []byte("salt"), "derived", 256)
	decoded, err := DecodeTTLV(request, 0)
	if err != nil {
		t.Fatal(err)
	}
	batch := FindChild(decoded, TagBatchItem)
	op := FindChild(batch, TagOperation)
	if int(op.IntValue()) != OperationDeriveKey {
		t.Errorf("operation = 0x%X, want 0x%X", op.IntValue(), OperationDeriveKey)
	}
}

func TestRoundTrip_Revoke(t *testing.T) {
	request := BuildRevokeRequest("rev-rt", 3)
	decoded, err := DecodeTTLV(request, 0)
	if err != nil {
		t.Fatal(err)
	}
	batch := FindChild(decoded, TagBatchItem)
	op := FindChild(batch, TagOperation)
	if int(op.IntValue()) != OperationRevoke {
		t.Errorf("operation = 0x%X, want 0x%X", op.IntValue(), OperationRevoke)
	}
	payload := FindChild(batch, TagRequestPayload)
	revReason := FindChild(payload, TagRevocationReason)
	code := FindChild(revReason, TagRevocationReasonCode)
	if int(code.IntValue()) != 3 {
		t.Errorf("reason code = %d, want 3", code.IntValue())
	}
}

// ---------------------------------------------------------------------------
// ParseLocatePayload nil safety (existing tests covered non-nil; add nil)
// ---------------------------------------------------------------------------

func TestParseLocatePayload_Nil(t *testing.T) {
	result := ParseLocatePayload(nil)
	if len(result.UniqueIdentifiers) != 0 {
		t.Errorf("count = %d, want 0", len(result.UniqueIdentifiers))
	}
}

// ---------------------------------------------------------------------------
// Activate and Destroy request builders (verify operation)
// ---------------------------------------------------------------------------

func TestBuildActivateRequest(t *testing.T) {
	t.Run("valid TTLV with Activate operation and UID", func(t *testing.T) {
		op, payload := decodeRequest(t, BuildActivateRequest("act-uid"))
		if op != OperationActivate {
			t.Errorf("operation = 0x%X, want 0x%X", op, OperationActivate)
		}
		uid := FindChild(payload, TagUniqueIdentifier)
		if uid == nil || uid.StringValue() != "act-uid" {
			t.Errorf("uid = %v, want %q", uid, "act-uid")
		}
	})
}

func TestBuildDestroyRequest(t *testing.T) {
	t.Run("valid TTLV with Destroy operation and UID", func(t *testing.T) {
		op, payload := decodeRequest(t, BuildDestroyRequest("del-uid"))
		if op != OperationDestroy {
			t.Errorf("operation = 0x%X, want 0x%X", op, OperationDestroy)
		}
		uid := FindChild(payload, TagUniqueIdentifier)
		if uid == nil || uid.StringValue() != "del-uid" {
			t.Errorf("uid = %v, want %q", uid, "del-uid")
		}
	})
}

// ---------------------------------------------------------------------------
// ResolveAlgorithm tests
// ---------------------------------------------------------------------------

func TestResolveAlgorithm(t *testing.T) {
	cases := []struct {
		input string
		want  int
	}{
		{"AES", AlgorithmAES},
		{"aes", AlgorithmAES},
		{"Aes", AlgorithmAES},
		{"DES", AlgorithmDES},
		{"TRIPLEDES", AlgorithmTripleDES},
		{"3DES", AlgorithmTripleDES},
		{"RSA", AlgorithmRSA},
		{"DSA", AlgorithmDSA},
		{"ECDSA", AlgorithmECDSA},
		{"HMACSHA1", AlgorithmHMACSHA1},
		{"HMACSHA256", AlgorithmHMACSHA256},
		{"HMACSHA384", AlgorithmHMACSHA384},
		{"HMACSHA512", AlgorithmHMACSHA512},
		{"unknown", 0},
		{"", 0},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := ResolveAlgorithm(tc.input)
			if got != tc.want {
				t.Errorf("ResolveAlgorithm(%q) = 0x%X, want 0x%X", tc.input, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// KmipError tests
// ---------------------------------------------------------------------------

func TestKmipError(t *testing.T) {
	t.Run("Error() returns message", func(t *testing.T) {
		err := &KmipError{Message: "test error", ResultStatus: 1, ResultReason: 2}
		if err.Error() != "test error" {
			t.Errorf("Error() = %q, want %q", err.Error(), "test error")
		}
	})

	t.Run("ParseResponse returns KmipError with reason", func(t *testing.T) {
		batchChildren := [][]byte{
			EncodeEnum(TagOperation, OperationGet),
			EncodeEnum(TagResultStatus, ResultStatusOperationFailed),
			EncodeEnum(TagResultReason, 4),
			EncodeTextString(TagResultMessage, "not found"),
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
			t.Fatal("expected error")
		}
		var kmipErr *KmipError
		if !errors.As(err, &kmipErr) {
			t.Fatal("expected KmipError type")
		}
		if kmipErr.ResultReason != 4 {
			t.Errorf("ResultReason = %d, want 4", kmipErr.ResultReason)
		}
	})
}
