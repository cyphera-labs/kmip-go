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

// BuildActivateRequest builds an Activate request for a key by unique ID.
func BuildActivateRequest(uniqueID string) []byte {
	payload := EncodeStructure(TagRequestPayload,
		EncodeTextString(TagUniqueIdentifier, uniqueID),
	)

	batchItem := EncodeStructure(TagBatchItem,
		EncodeEnum(TagOperation, OperationActivate),
		payload,
	)

	return EncodeStructure(TagRequestMessage,
		buildRequestHeader(1),
		batchItem,
	)
}

// BuildDestroyRequest builds a Destroy request for a key by unique ID.
func BuildDestroyRequest(uniqueID string) []byte {
	payload := EncodeStructure(TagRequestPayload,
		EncodeTextString(TagUniqueIdentifier, uniqueID),
	)

	batchItem := EncodeStructure(TagBatchItem,
		EncodeEnum(TagOperation, OperationDestroy),
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
	result := &LocateResult{
		UniqueIdentifiers: make([]string, 0),
	}
	if payload == nil {
		return result
	}
	ids := FindChildren(payload, TagUniqueIdentifier)
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

// ---------------------------------------------------------------------------
// Additional result types
// ---------------------------------------------------------------------------

// CheckResult holds a parsed Check response.
type CheckResult struct {
	UniqueIdentifier string
}

// ReKeyResult holds a parsed ReKey response.
type ReKeyResult struct {
	UniqueIdentifier string
}

// EncryptResult holds a parsed Encrypt response.
type EncryptResult struct {
	Data  []byte
	Nonce []byte
}

// DecryptResult holds a parsed Decrypt response.
type DecryptResult struct {
	Data []byte
}

// SignResult holds a parsed Sign response.
type SignResult struct {
	SignatureData []byte
}

// SignatureVerifyResult holds a parsed SignatureVerify response.
type SignatureVerifyResult struct {
	Valid bool
}

// MACResult holds a parsed MAC response.
type MACResult struct {
	MACData []byte
}

// QueryResult holds a parsed Query response.
type QueryResult struct {
	Operations  []int
	ObjectTypes []int
}

// DiscoverVersionsResult holds a parsed DiscoverVersions response.
type DiscoverVersionsResult struct {
	Versions []struct{ Major, Minor int }
}

// DeriveKeyResult holds a parsed DeriveKey response.
type DeriveKeyResult struct {
	UniqueIdentifier string
}

// CreateKeyPairResult holds a parsed CreateKeyPair response.
type CreateKeyPairResult struct {
	PrivateKeyUID string
	PublicKeyUID  string
}

// ---------------------------------------------------------------------------
// Additional request builders
// ---------------------------------------------------------------------------

// buildUIDOnlyRequest builds a request with just a UID in the payload.
func buildUIDOnlyRequest(operation int, uniqueID string) []byte {
	payload := EncodeStructure(TagRequestPayload,
		EncodeTextString(TagUniqueIdentifier, uniqueID),
	)
	batchItem := EncodeStructure(TagBatchItem,
		EncodeEnum(TagOperation, operation),
		payload,
	)
	return EncodeStructure(TagRequestMessage,
		buildRequestHeader(1),
		batchItem,
	)
}

// buildEmptyPayloadRequest builds a request with an empty payload.
func buildEmptyPayloadRequest(operation int) []byte {
	payload := EncodeStructure(TagRequestPayload)
	batchItem := EncodeStructure(TagBatchItem,
		EncodeEnum(TagOperation, operation),
		payload,
	)
	return EncodeStructure(TagRequestMessage,
		buildRequestHeader(1),
		batchItem,
	)
}

// BuildCreateKeyPairRequest builds a CreateKeyPair request.
func BuildCreateKeyPairRequest(name string, algorithm int, length int32) []byte {
	payload := EncodeStructure(TagRequestPayload,
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
				EncodeInteger(TagAttributeValue, int32(UsageMaskSign|UsageMaskVerify)),
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
		EncodeEnum(TagOperation, OperationCreateKeyPair),
		payload,
	)
	return EncodeStructure(TagRequestMessage,
		buildRequestHeader(1),
		batchItem,
	)
}

// BuildRegisterRequest builds a Register request for a symmetric key.
func BuildRegisterRequest(objectType int, material []byte, name string, algorithm int, length int32) []byte {
	payloadChildren := [][]byte{
		EncodeEnum(TagObjectType, objectType),
		EncodeStructure(TagSymmetricKey,
			EncodeStructure(TagKeyBlock,
				EncodeEnum(TagKeyFormatType, KeyFormatRaw),
				EncodeStructure(TagKeyValue,
					EncodeByteString(TagKeyMaterial, material),
				),
				EncodeEnum(TagCryptographicAlgorithm, algorithm),
				EncodeInteger(TagCryptographicLength, length),
			),
		),
	}
	if name != "" {
		payloadChildren = append(payloadChildren,
			EncodeStructure(TagTemplateAttribute,
				EncodeStructure(TagAttribute,
					EncodeTextString(TagAttributeName, "Name"),
					EncodeStructure(TagAttributeValue,
						EncodeTextString(TagNameValue, name),
						EncodeEnum(TagNameType, NameTypeUninterpretedTextString),
					),
				),
			),
		)
	}
	payload := EncodeStructure(TagRequestPayload, payloadChildren...)
	batchItem := EncodeStructure(TagBatchItem,
		EncodeEnum(TagOperation, OperationRegister),
		payload,
	)
	return EncodeStructure(TagRequestMessage,
		buildRequestHeader(1),
		batchItem,
	)
}

// BuildReKeyRequest builds a ReKey request.
func BuildReKeyRequest(uniqueID string) []byte {
	return buildUIDOnlyRequest(OperationReKey, uniqueID)
}

// BuildDeriveKeyRequest builds a DeriveKey request.
func BuildDeriveKeyRequest(uniqueID string, derivationData []byte, name string, length int32) []byte {
	payload := EncodeStructure(TagRequestPayload,
		EncodeTextString(TagUniqueIdentifier, uniqueID),
		EncodeStructure(TagDerivationParameters,
			EncodeByteString(TagDerivationData, derivationData),
		),
		EncodeStructure(TagTemplateAttribute,
			EncodeStructure(TagAttribute,
				EncodeTextString(TagAttributeName, "Cryptographic Length"),
				EncodeInteger(TagAttributeValue, length),
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
		EncodeEnum(TagOperation, OperationDeriveKey),
		payload,
	)
	return EncodeStructure(TagRequestMessage,
		buildRequestHeader(1),
		batchItem,
	)
}

// BuildCheckRequest builds a Check request.
func BuildCheckRequest(uniqueID string) []byte {
	return buildUIDOnlyRequest(OperationCheck, uniqueID)
}

// BuildGetAttributesRequest builds a GetAttributes request.
func BuildGetAttributesRequest(uniqueID string) []byte {
	return buildUIDOnlyRequest(OperationGetAttributes, uniqueID)
}

// BuildGetAttributeListRequest builds a GetAttributeList request.
func BuildGetAttributeListRequest(uniqueID string) []byte {
	return buildUIDOnlyRequest(OperationGetAttributeList, uniqueID)
}

// BuildAddAttributeRequest builds an AddAttribute request.
func BuildAddAttributeRequest(uniqueID, attrName, attrValue string) []byte {
	payload := EncodeStructure(TagRequestPayload,
		EncodeTextString(TagUniqueIdentifier, uniqueID),
		EncodeStructure(TagAttribute,
			EncodeTextString(TagAttributeName, attrName),
			EncodeTextString(TagAttributeValue, attrValue),
		),
	)
	batchItem := EncodeStructure(TagBatchItem,
		EncodeEnum(TagOperation, OperationAddAttribute),
		payload,
	)
	return EncodeStructure(TagRequestMessage,
		buildRequestHeader(1),
		batchItem,
	)
}

// BuildModifyAttributeRequest builds a ModifyAttribute request.
func BuildModifyAttributeRequest(uniqueID, attrName, attrValue string) []byte {
	payload := EncodeStructure(TagRequestPayload,
		EncodeTextString(TagUniqueIdentifier, uniqueID),
		EncodeStructure(TagAttribute,
			EncodeTextString(TagAttributeName, attrName),
			EncodeTextString(TagAttributeValue, attrValue),
		),
	)
	batchItem := EncodeStructure(TagBatchItem,
		EncodeEnum(TagOperation, OperationModifyAttribute),
		payload,
	)
	return EncodeStructure(TagRequestMessage,
		buildRequestHeader(1),
		batchItem,
	)
}

// BuildDeleteAttributeRequest builds a DeleteAttribute request.
func BuildDeleteAttributeRequest(uniqueID, attrName string) []byte {
	payload := EncodeStructure(TagRequestPayload,
		EncodeTextString(TagUniqueIdentifier, uniqueID),
		EncodeStructure(TagAttribute,
			EncodeTextString(TagAttributeName, attrName),
		),
	)
	batchItem := EncodeStructure(TagBatchItem,
		EncodeEnum(TagOperation, OperationDeleteAttribute),
		payload,
	)
	return EncodeStructure(TagRequestMessage,
		buildRequestHeader(1),
		batchItem,
	)
}

// BuildObtainLeaseRequest builds an ObtainLease request.
func BuildObtainLeaseRequest(uniqueID string) []byte {
	return buildUIDOnlyRequest(OperationObtainLease, uniqueID)
}

// BuildRevokeRequest builds a Revoke request with a revocation reason.
func BuildRevokeRequest(uniqueID string, reason int) []byte {
	payload := EncodeStructure(TagRequestPayload,
		EncodeTextString(TagUniqueIdentifier, uniqueID),
		EncodeStructure(TagRevocationReason,
			EncodeEnum(TagRevocationReasonCode, reason),
		),
	)
	batchItem := EncodeStructure(TagBatchItem,
		EncodeEnum(TagOperation, OperationRevoke),
		payload,
	)
	return EncodeStructure(TagRequestMessage,
		buildRequestHeader(1),
		batchItem,
	)
}

// BuildArchiveRequest builds an Archive request.
func BuildArchiveRequest(uniqueID string) []byte {
	return buildUIDOnlyRequest(OperationArchive, uniqueID)
}

// BuildRecoverRequest builds a Recover request.
func BuildRecoverRequest(uniqueID string) []byte {
	return buildUIDOnlyRequest(OperationRecover, uniqueID)
}

// BuildQueryRequest builds a Query request.
func BuildQueryRequest() []byte {
	return buildEmptyPayloadRequest(OperationQuery)
}

// BuildPollRequest builds a Poll request.
func BuildPollRequest() []byte {
	return buildEmptyPayloadRequest(OperationPoll)
}

// BuildDiscoverVersionsRequest builds a DiscoverVersions request.
func BuildDiscoverVersionsRequest() []byte {
	return buildEmptyPayloadRequest(OperationDiscoverVersions)
}

// BuildEncryptRequest builds an Encrypt request.
func BuildEncryptRequest(uniqueID string, data []byte) []byte {
	payload := EncodeStructure(TagRequestPayload,
		EncodeTextString(TagUniqueIdentifier, uniqueID),
		EncodeByteString(TagData, data),
	)
	batchItem := EncodeStructure(TagBatchItem,
		EncodeEnum(TagOperation, OperationEncrypt),
		payload,
	)
	return EncodeStructure(TagRequestMessage,
		buildRequestHeader(1),
		batchItem,
	)
}

// BuildDecryptRequest builds a Decrypt request.
func BuildDecryptRequest(uniqueID string, data []byte, nonce []byte) []byte {
	payloadChildren := [][]byte{
		EncodeTextString(TagUniqueIdentifier, uniqueID),
		EncodeByteString(TagData, data),
	}
	if len(nonce) > 0 {
		payloadChildren = append(payloadChildren, EncodeByteString(TagIVCounterNonce, nonce))
	}
	payload := EncodeStructure(TagRequestPayload, payloadChildren...)
	batchItem := EncodeStructure(TagBatchItem,
		EncodeEnum(TagOperation, OperationDecrypt),
		payload,
	)
	return EncodeStructure(TagRequestMessage,
		buildRequestHeader(1),
		batchItem,
	)
}

// BuildSignRequest builds a Sign request.
func BuildSignRequest(uniqueID string, data []byte) []byte {
	payload := EncodeStructure(TagRequestPayload,
		EncodeTextString(TagUniqueIdentifier, uniqueID),
		EncodeByteString(TagData, data),
	)
	batchItem := EncodeStructure(TagBatchItem,
		EncodeEnum(TagOperation, OperationSign),
		payload,
	)
	return EncodeStructure(TagRequestMessage,
		buildRequestHeader(1),
		batchItem,
	)
}

// BuildSignatureVerifyRequest builds a SignatureVerify request.
func BuildSignatureVerifyRequest(uniqueID string, data []byte, signature []byte) []byte {
	payload := EncodeStructure(TagRequestPayload,
		EncodeTextString(TagUniqueIdentifier, uniqueID),
		EncodeByteString(TagData, data),
		EncodeByteString(TagSignatureData, signature),
	)
	batchItem := EncodeStructure(TagBatchItem,
		EncodeEnum(TagOperation, OperationSignatureVerify),
		payload,
	)
	return EncodeStructure(TagRequestMessage,
		buildRequestHeader(1),
		batchItem,
	)
}

// BuildMACRequest builds a MAC request.
func BuildMACRequest(uniqueID string, data []byte) []byte {
	payload := EncodeStructure(TagRequestPayload,
		EncodeTextString(TagUniqueIdentifier, uniqueID),
		EncodeByteString(TagData, data),
	)
	batchItem := EncodeStructure(TagBatchItem,
		EncodeEnum(TagOperation, OperationMAC),
		payload,
	)
	return EncodeStructure(TagRequestMessage,
		buildRequestHeader(1),
		batchItem,
	)
}

// ---------------------------------------------------------------------------
// Additional response parsers
// ---------------------------------------------------------------------------

// ParseCheckPayload parses a Check response payload.
func ParseCheckPayload(payload *Item) *CheckResult {
	result := &CheckResult{}
	if payload == nil {
		return result
	}
	uid := FindChild(payload, TagUniqueIdentifier)
	if uid != nil {
		result.UniqueIdentifier = uid.StringValue()
	}
	return result
}

// ParseReKeyPayload parses a ReKey response payload.
func ParseReKeyPayload(payload *Item) *ReKeyResult {
	result := &ReKeyResult{}
	if payload == nil {
		return result
	}
	uid := FindChild(payload, TagUniqueIdentifier)
	if uid != nil {
		result.UniqueIdentifier = uid.StringValue()
	}
	return result
}

// ParseEncryptPayload parses an Encrypt response payload.
func ParseEncryptPayload(payload *Item) *EncryptResult {
	result := &EncryptResult{}
	if payload == nil {
		return result
	}
	data := FindChild(payload, TagData)
	if data != nil {
		result.Data = data.BytesValue()
	}
	nonce := FindChild(payload, TagIVCounterNonce)
	if nonce != nil {
		result.Nonce = nonce.BytesValue()
	}
	return result
}

// ParseDecryptPayload parses a Decrypt response payload.
func ParseDecryptPayload(payload *Item) *DecryptResult {
	result := &DecryptResult{}
	if payload == nil {
		return result
	}
	data := FindChild(payload, TagData)
	if data != nil {
		result.Data = data.BytesValue()
	}
	return result
}

// ParseSignPayload parses a Sign response payload.
func ParseSignPayload(payload *Item) *SignResult {
	result := &SignResult{}
	if payload == nil {
		return result
	}
	sig := FindChild(payload, TagSignatureData)
	if sig != nil {
		result.SignatureData = sig.BytesValue()
	}
	return result
}

// ParseSignatureVerifyPayload parses a SignatureVerify response payload.
func ParseSignatureVerifyPayload(payload *Item) *SignatureVerifyResult {
	result := &SignatureVerifyResult{}
	if payload == nil {
		return result
	}
	indicator := FindChild(payload, TagValidityIndicator)
	if indicator != nil {
		// 0 = Valid, 1 = Invalid
		result.Valid = indicator.IntValue() == 0
	}
	return result
}

// ParseMACPayload parses a MAC response payload.
func ParseMACPayload(payload *Item) *MACResult {
	result := &MACResult{}
	if payload == nil {
		return result
	}
	macData := FindChild(payload, TagMACData)
	if macData != nil {
		result.MACData = macData.BytesValue()
	}
	return result
}

// ParseQueryPayload parses a Query response payload.
func ParseQueryPayload(payload *Item) *QueryResult {
	result := &QueryResult{
		Operations:  make([]int, 0),
		ObjectTypes: make([]int, 0),
	}
	if payload == nil {
		return result
	}
	ops := FindChildren(payload, TagOperation)
	for _, op := range ops {
		result.Operations = append(result.Operations, int(op.IntValue()))
	}
	objTypes := FindChildren(payload, TagObjectType)
	for _, ot := range objTypes {
		result.ObjectTypes = append(result.ObjectTypes, int(ot.IntValue()))
	}
	return result
}

// ParseDiscoverVersionsPayload parses a DiscoverVersions response payload.
func ParseDiscoverVersionsPayload(payload *Item) *DiscoverVersionsResult {
	result := &DiscoverVersionsResult{}
	if payload == nil {
		return result
	}
	versions := FindChildren(payload, TagProtocolVersion)
	for _, v := range versions {
		major := FindChild(v, TagProtocolVersionMajor)
		minor := FindChild(v, TagProtocolVersionMinor)
		entry := struct{ Major, Minor int }{}
		if major != nil {
			entry.Major = int(major.IntValue())
		}
		if minor != nil {
			entry.Minor = int(minor.IntValue())
		}
		result.Versions = append(result.Versions, entry)
	}
	return result
}

// ParseDeriveKeyPayload parses a DeriveKey response payload.
func ParseDeriveKeyPayload(payload *Item) *DeriveKeyResult {
	result := &DeriveKeyResult{}
	if payload == nil {
		return result
	}
	uid := FindChild(payload, TagUniqueIdentifier)
	if uid != nil {
		result.UniqueIdentifier = uid.StringValue()
	}
	return result
}

// ParseCreateKeyPairPayload parses a CreateKeyPair response payload.
func ParseCreateKeyPairPayload(payload *Item) *CreateKeyPairResult {
	result := &CreateKeyPairResult{}
	if payload == nil {
		return result
	}
	privUID := FindChild(payload, TagPrivateKeyUniqueIdentifier)
	if privUID != nil {
		result.PrivateKeyUID = privUID.StringValue()
	}
	pubUID := FindChild(payload, TagPublicKeyUniqueIdentifier)
	if pubUID != nil {
		result.PublicKeyUID = pubUID.StringValue()
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
