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

// KMIP 1.4 tag, type, and enum constants.
// Only the subset needed for Locate, Get, Create operations.
//
// Reference: OASIS KMIP Specification v1.4
// https://docs.oasis-open.org/kmip/spec/v1.4/kmip-spec-v1.4.html

// Tags — message structure.
const (
	TagRequestMessage       = 0x420078
	TagResponseMessage      = 0x42007B
	TagRequestHeader        = 0x420077
	TagResponseHeader       = 0x42007A
	TagProtocolVersion      = 0x420069
	TagProtocolVersionMajor = 0x42006A
	TagProtocolVersionMinor = 0x42006B
	TagBatchCount           = 0x42000D
	TagBatchItem            = 0x42000F
	TagOperation            = 0x42005C
	TagRequestPayload       = 0x420079
	TagResponsePayload      = 0x42007C
	TagResultStatus         = 0x42007F
	TagResultReason         = 0x420080
	TagResultMessage        = 0x420081
)

// Tags — object identification.
const (
	TagUniqueIdentifier = 0x420094
	TagObjectType       = 0x420057
)

// Tags — naming.
const (
	TagName      = 0x420053
	TagNameValue = 0x420055
	TagNameType  = 0x420054
)

// Tags — attributes (KMIP 1.x style).
const (
	TagAttribute      = 0x420008
	TagAttributeName  = 0x42000A
	TagAttributeValue = 0x42000B
)

// Tags — key structure.
const (
	TagSymmetricKey  = 0x42008F
	TagKeyBlock      = 0x420040
	TagKeyFormatType = 0x420042
	TagKeyValue      = 0x420045
	TagKeyMaterial   = 0x420043
)

// Tags — crypto attributes.
const (
	TagCryptographicAlgorithm = 0x420028
	TagCryptographicLength    = 0x42002A
	TagCryptographicUsageMask = 0x42002C
)

// Tags — template.
const (
	TagTemplateAttribute = 0x420091
)

// Operations.
const (
	OperationCreate   = 0x00000001
	OperationLocate   = 0x00000008
	OperationGet      = 0x0000000A
	OperationActivate = 0x00000012
	OperationDestroy  = 0x00000014
	OperationCheck    = 0x0000001C
)

// Object types.
const (
	ObjectTypeSymmetricKey = 0x00000001
	ObjectTypePublicKey    = 0x00000002
	ObjectTypePrivateKey   = 0x00000003
	ObjectTypeCertificate  = 0x00000006
	ObjectTypeSecretData   = 0x00000007
	ObjectTypeOpaqueData   = 0x00000008
)

// Result statuses.
const (
	ResultStatusSuccess          = 0x00000000
	ResultStatusOperationFailed  = 0x00000001
	ResultStatusOperationPending = 0x00000002
	ResultStatusOperationUndone  = 0x00000003
)

// Key format types.
const (
	KeyFormatRaw                 = 0x00000001
	KeyFormatOpaque              = 0x00000002
	KeyFormatPKCS1               = 0x00000003
	KeyFormatPKCS8               = 0x00000004
	KeyFormatX509                = 0x00000005
	KeyFormatECPrivateKey        = 0x00000006
	KeyFormatTransparentSymmetric = 0x00000007
)

// Algorithms.
const (
	AlgorithmDES        = 0x00000001
	AlgorithmTripleDES  = 0x00000002
	AlgorithmAES        = 0x00000003
	AlgorithmRSA        = 0x00000004
	AlgorithmDSA        = 0x00000005
	AlgorithmECDSA      = 0x00000006
	AlgorithmHMACSHA1   = 0x00000007
	AlgorithmHMACSHA256 = 0x00000008
	AlgorithmHMACSHA384 = 0x00000009
	AlgorithmHMACSHA512 = 0x0000000A
)

// Name types.
const (
	NameTypeUninterpretedTextString = 0x00000001
	NameTypeURI                    = 0x00000002
)

// Cryptographic usage mask (bitmask).
const (
	UsageMaskSign         = 0x00000001
	UsageMaskVerify       = 0x00000002
	UsageMaskEncrypt      = 0x00000004
	UsageMaskDecrypt      = 0x00000008
	UsageMaskWrapKey      = 0x00000010
	UsageMaskUnwrapKey    = 0x00000020
	UsageMaskExport       = 0x00000040
	UsageMaskDeriveKey    = 0x00000100
	UsageMaskKeyAgreement = 0x00000800
)
