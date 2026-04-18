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

import "fmt"

// Protocol version: KMIP 1.4.
const (
	ProtocolMajor = 1
	ProtocolMinor = 4
)

// Response holds a parsed KMIP response.
type Response struct {
	Operation     int
	ResultStatus  int
	ResultReason  int
	ResultMessage string
	Payload       *Item
}

// LocateResult holds a parsed Locate response.
type LocateResult struct {
	UniqueIdentifiers []string
}

// GetResult holds a parsed Get response.
type GetResult struct {
	ObjectType       int
	UniqueIdentifier string
	KeyMaterial      []byte
}

// CreateResult holds a parsed Create response.
type CreateResult struct {
	ObjectType       int
	UniqueIdentifier string
}

// buildRequestHeader builds the request header included in every request.
func buildRequestHeader(batchCount int32) []byte {
	return EncodeStructure(TagRequestHeader,
		EncodeStructure(TagProtocolVersion,
			EncodeInteger(TagProtocolVersionMajor, int32(ProtocolMajor)),
			EncodeInteger(TagProtocolVersionMinor, int32(ProtocolMinor)),
		),
		EncodeInteger(TagBatchCount, batchCount),
	)
}

// BuildLocateRequest builds a Locate request to find keys by name.
func BuildLocateRequest(name string) []byte {
	payload := EncodeStructure(TagRequestPayload,
		EncodeStructure(TagAttribute,
			EncodeTextString(TagAttributeName, "Name"),
			EncodeStructure(TagAttributeValue,
				EncodeTextString(TagNameValue, name),
				EncodeEnum(TagNameType, NameTypeUninterpretedTextString),
			),
		),
	)

	batchItem := EncodeStructure(TagBatchItem,
		EncodeEnum(TagOperation, OperationLocate),
		payload,
	)

	return EncodeStructure(TagRequestMessage,
		buildRequestHeader(1),
		batchItem,
	)
}

// BuildGetRequest builds a Get request to fetch key material by unique ID.
func BuildGetRequest(uniqueID string) []byte {
	payload := EncodeStructure(TagRequestPayload,
		EncodeTextString(TagUniqueIdentifier, uniqueID),
	)

	batchItem := EncodeStructure(TagBatchItem,
		EncodeEnum(TagOperation, OperationGet),
		payload,
	)

	return EncodeStructure(TagRequestMessage,
		buildRequestHeader(1),
		batchItem,
	)
}

// BuildCreateRequest builds a Create request for a new symmetric key.
func BuildCreateRequest(name string, algorithm int, length int32) []byte {
	payload := EncodeStructure(TagRequestPayload,
		EncodeEnum(TagObjectType, ObjectTypeSymmetricKey),
		EncodeStructure(TagTemplateAttribute,
			EncodeStructure(TagAttribute,
				EncodeTextString(TagAttributeName, "Cryptographic Algorithm"),
				EncodeEnum(TagAttributeValue, algorithm),
			),
			EncodeStructure(TagAttribute,
				EncodeTextString(TagAttributeName, "Cryptographic Length"),
				EncodeInteger(TagAttributeValue, length),
			),
			EncodeStructure(TagAttribute,
				EncodeTextString(TagAttributeName, "Cryptographic Usage Mask"),
				EncodeInteger(TagAttributeValue, int32(UsageMaskEncrypt|UsageMaskDecrypt)),
			),
			EncodeStructure(TagAttribute,
				EncodeTextString(TagAttributeName, "Name"),
				EncodeStructure(TagAttributeValue,
					EncodeTextString(TagNameValue, name),
					EncodeEnum(TagNameType, NameTypeUninterpretedTextString),
				),
			),
		),
	)

	batchItem := EncodeStructure(TagBatchItem,
		EncodeEnum(TagOperation, OperationCreate),
		payload,
	)

	return EncodeStructure(TagRequestMessage,
		buildRequestHeader(1),
		batchItem,
	)
}

// ParseResponse parses a KMIP response message.
func ParseResponse(data []byte) (*Response, error) {
	msg, err := DecodeTTLV(data, 0)
	if err != nil {
		return nil, err
	}
	if msg.Tag != TagResponseMessage {
		return nil, fmt.Errorf("expected ResponseMessage (0x42007B), got 0x%06X", msg.Tag)
	}

	batchItem := FindChild(msg, TagBatchItem)
	if batchItem == nil {
		return nil, fmt.Errorf("no BatchItem in response")
	}

	operationItem := FindChild(batchItem, TagOperation)
	statusItem := FindChild(batchItem, TagResultStatus)
	reasonItem := FindChild(batchItem, TagResultReason)
	messageItem := FindChild(batchItem, TagResultMessage)
	payloadItem := FindChild(batchItem, TagResponsePayload)

	resp := &Response{
		Payload: payloadItem,
	}
	if operationItem != nil {
		resp.Operation = int(operationItem.IntValue())
	}
	if statusItem != nil {
		resp.ResultStatus = int(statusItem.IntValue())
	}
	if reasonItem != nil {
		resp.ResultReason = int(reasonItem.IntValue())
	}
	if messageItem != nil {
		resp.ResultMessage = messageItem.StringValue()
	}

	if resp.ResultStatus != ResultStatusSuccess {
		errMsg := resp.ResultMessage
		if errMsg == "" {
			errMsg = fmt.Sprintf("KMIP operation failed (status=%d)", resp.ResultStatus)
		}
		return nil, &KmipError{
			Message:      errMsg,
			ResultStatus: resp.ResultStatus,
			ResultReason: resp.ResultReason,
		}
	}

	return resp, nil
}

// ParseLocatePayload parses a Locate response payload.
func ParseLocatePayload(payload *Item) *LocateResult {
	ids := FindChildren(payload, TagUniqueIdentifier)
	result := &LocateResult{
		UniqueIdentifiers: make([]string, 0, len(ids)),
	}
	for _, id := range ids {
		result.UniqueIdentifiers = append(result.UniqueIdentifiers, id.StringValue())
	}
	return result
}

// ParseGetPayload parses a Get response payload.
func ParseGetPayload(payload *Item) *GetResult {
	uid := FindChild(payload, TagUniqueIdentifier)
	objType := FindChild(payload, TagObjectType)

	// Navigate: SymmetricKey -> KeyBlock -> KeyValue -> KeyMaterial
	var keyMaterial []byte
	symKey := FindChild(payload, TagSymmetricKey)
	if symKey != nil {
		keyBlock := FindChild(symKey, TagKeyBlock)
		if keyBlock != nil {
			keyValue := FindChild(keyBlock, TagKeyValue)
			if keyValue != nil {
				material := FindChild(keyValue, TagKeyMaterial)
				if material != nil {
					keyMaterial = material.BytesValue()
				}
			}
		}
	}

	result := &GetResult{
		KeyMaterial: keyMaterial,
	}
	if objType != nil {
		result.ObjectType = int(objType.IntValue())
	}
	if uid != nil {
		result.UniqueIdentifier = uid.StringValue()
	}
	return result
}

// ParseCreatePayload parses a Create response payload.
func ParseCreatePayload(payload *Item) *CreateResult {
	uid := FindChild(payload, TagUniqueIdentifier)
	objType := FindChild(payload, TagObjectType)
	result := &CreateResult{}
	if objType != nil {
		result.ObjectType = int(objType.IntValue())
	}
	if uid != nil {
		result.UniqueIdentifier = uid.StringValue()
	}
	return result
}

// KmipError represents a KMIP operation error.
type KmipError struct {
	Message      string
	ResultStatus int
	ResultReason int
}

func (e *KmipError) Error() string {
	return e.Message
}
