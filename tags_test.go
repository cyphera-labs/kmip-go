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
	"testing"
)

// ---------------------------------------------------------------------------
// ObjectType values — KMIP 1.4 Section 9.1.3.2.3
// ---------------------------------------------------------------------------

func TestObjectTypeValues(t *testing.T) {
	t.Run("Certificate = 0x00000001", func(t *testing.T) {
		if ObjectTypeCertificate != 0x00000001 {
			t.Errorf("got 0x%08X, want 0x00000001", ObjectTypeCertificate)
		}
	})
	t.Run("SymmetricKey = 0x00000002", func(t *testing.T) {
		if ObjectTypeSymmetricKey != 0x00000002 {
			t.Errorf("got 0x%08X, want 0x00000002", ObjectTypeSymmetricKey)
		}
	})
	t.Run("PublicKey = 0x00000003", func(t *testing.T) {
		if ObjectTypePublicKey != 0x00000003 {
			t.Errorf("got 0x%08X, want 0x00000003", ObjectTypePublicKey)
		}
	})
	t.Run("PrivateKey = 0x00000004", func(t *testing.T) {
		if ObjectTypePrivateKey != 0x00000004 {
			t.Errorf("got 0x%08X, want 0x00000004", ObjectTypePrivateKey)
		}
	})
	t.Run("SplitKey = 0x00000005", func(t *testing.T) {
		if ObjectTypeSplitKey != 0x00000005 {
			t.Errorf("got 0x%08X, want 0x00000005", ObjectTypeSplitKey)
		}
	})
	t.Run("Template = 0x00000006", func(t *testing.T) {
		if ObjectTypeTemplate != 0x00000006 {
			t.Errorf("got 0x%08X, want 0x00000006", ObjectTypeTemplate)
		}
	})
	t.Run("SecretData = 0x00000007", func(t *testing.T) {
		if ObjectTypeSecretData != 0x00000007 {
			t.Errorf("got 0x%08X, want 0x00000007", ObjectTypeSecretData)
		}
	})
	t.Run("OpaqueData = 0x00000008", func(t *testing.T) {
		if ObjectTypeOpaqueData != 0x00000008 {
			t.Errorf("got 0x%08X, want 0x00000008", ObjectTypeOpaqueData)
		}
	})
	t.Run("no duplicate ObjectType values", func(t *testing.T) {
		values := []int{
			ObjectTypeCertificate, ObjectTypeSymmetricKey, ObjectTypePublicKey,
			ObjectTypePrivateKey, ObjectTypeSplitKey, ObjectTypeTemplate,
			ObjectTypeSecretData, ObjectTypeOpaqueData,
		}
		seen := make(map[int]bool)
		for _, v := range values {
			if seen[v] {
				t.Errorf("duplicate ObjectType value 0x%08X", v)
			}
			seen[v] = true
		}
	})
}

// ---------------------------------------------------------------------------
// Operation values — KMIP 1.4 Section 9.1.3.2.2
// ---------------------------------------------------------------------------

func TestOperationValues(t *testing.T) {
	t.Run("Create = 0x00000001", func(t *testing.T) {
		if OperationCreate != 0x00000001 {
			t.Errorf("got 0x%08X, want 0x00000001", OperationCreate)
		}
	})
	t.Run("Locate = 0x00000008", func(t *testing.T) {
		if OperationLocate != 0x00000008 {
			t.Errorf("got 0x%08X, want 0x00000008", OperationLocate)
		}
	})
	t.Run("Get = 0x0000000A", func(t *testing.T) {
		if OperationGet != 0x0000000A {
			t.Errorf("got 0x%08X, want 0x0000000A", OperationGet)
		}
	})
	t.Run("Activate = 0x00000012", func(t *testing.T) {
		if OperationActivate != 0x00000012 {
			t.Errorf("got 0x%08X, want 0x00000012", OperationActivate)
		}
	})
	t.Run("Destroy = 0x00000014", func(t *testing.T) {
		if OperationDestroy != 0x00000014 {
			t.Errorf("got 0x%08X, want 0x00000014", OperationDestroy)
		}
	})
	t.Run("Check = 0x0000001C", func(t *testing.T) {
		if OperationCheck != 0x0000001C {
			t.Errorf("got 0x%08X, want 0x0000001C", OperationCheck)
		}
	})
	t.Run("no duplicate Operation values", func(t *testing.T) {
		values := []int{
			OperationCreate, OperationLocate, OperationGet,
			OperationActivate, OperationDestroy, OperationCheck,
		}
		seen := make(map[int]bool)
		for _, v := range values {
			if seen[v] {
				t.Errorf("duplicate Operation value 0x%08X", v)
			}
			seen[v] = true
		}
	})
}

// ---------------------------------------------------------------------------
// ResultStatus
// ---------------------------------------------------------------------------

func TestResultStatusValues(t *testing.T) {
	t.Run("Success = 0x00000000", func(t *testing.T) {
		if ResultStatusSuccess != 0x00000000 {
			t.Errorf("got 0x%08X, want 0x00000000", ResultStatusSuccess)
		}
	})
	t.Run("OperationFailed = 0x00000001", func(t *testing.T) {
		if ResultStatusOperationFailed != 0x00000001 {
			t.Errorf("got 0x%08X, want 0x00000001", ResultStatusOperationFailed)
		}
	})
	t.Run("OperationPending = 0x00000002", func(t *testing.T) {
		if ResultStatusOperationPending != 0x00000002 {
			t.Errorf("got 0x%08X, want 0x00000002", ResultStatusOperationPending)
		}
	})
	t.Run("OperationUndone = 0x00000003", func(t *testing.T) {
		if ResultStatusOperationUndone != 0x00000003 {
			t.Errorf("got 0x%08X, want 0x00000003", ResultStatusOperationUndone)
		}
	})
	t.Run("no duplicate ResultStatus values", func(t *testing.T) {
		values := []int{
			ResultStatusSuccess, ResultStatusOperationFailed,
			ResultStatusOperationPending, ResultStatusOperationUndone,
		}
		seen := make(map[int]bool)
		for _, v := range values {
			if seen[v] {
				t.Errorf("duplicate ResultStatus value 0x%08X", v)
			}
			seen[v] = true
		}
	})
}

// ---------------------------------------------------------------------------
// Algorithm values — KMIP 1.4 Section 9.1.3.2.13
// ---------------------------------------------------------------------------

func TestAlgorithmValues(t *testing.T) {
	t.Run("DES = 0x00000001", func(t *testing.T) {
		if AlgorithmDES != 0x00000001 {
			t.Errorf("got 0x%08X, want 0x00000001", AlgorithmDES)
		}
	})
	t.Run("TripleDES = 0x00000002", func(t *testing.T) {
		if AlgorithmTripleDES != 0x00000002 {
			t.Errorf("got 0x%08X, want 0x00000002", AlgorithmTripleDES)
		}
	})
	t.Run("AES = 0x00000003", func(t *testing.T) {
		if AlgorithmAES != 0x00000003 {
			t.Errorf("got 0x%08X, want 0x00000003", AlgorithmAES)
		}
	})
	t.Run("RSA = 0x00000004", func(t *testing.T) {
		if AlgorithmRSA != 0x00000004 {
			t.Errorf("got 0x%08X, want 0x00000004", AlgorithmRSA)
		}
	})
	t.Run("DSA = 0x00000005", func(t *testing.T) {
		if AlgorithmDSA != 0x00000005 {
			t.Errorf("got 0x%08X, want 0x00000005", AlgorithmDSA)
		}
	})
	t.Run("ECDSA = 0x00000006", func(t *testing.T) {
		if AlgorithmECDSA != 0x00000006 {
			t.Errorf("got 0x%08X, want 0x00000006", AlgorithmECDSA)
		}
	})
	t.Run("HMACSHA1 = 0x00000007", func(t *testing.T) {
		if AlgorithmHMACSHA1 != 0x00000007 {
			t.Errorf("got 0x%08X, want 0x00000007", AlgorithmHMACSHA1)
		}
	})
	t.Run("HMACSHA256 = 0x00000008", func(t *testing.T) {
		if AlgorithmHMACSHA256 != 0x00000008 {
			t.Errorf("got 0x%08X, want 0x00000008", AlgorithmHMACSHA256)
		}
	})
	t.Run("HMACSHA384 = 0x00000009", func(t *testing.T) {
		if AlgorithmHMACSHA384 != 0x00000009 {
			t.Errorf("got 0x%08X, want 0x00000009", AlgorithmHMACSHA384)
		}
	})
	t.Run("HMACSHA512 = 0x0000000A", func(t *testing.T) {
		if AlgorithmHMACSHA512 != 0x0000000A {
			t.Errorf("got 0x%08X, want 0x0000000A", AlgorithmHMACSHA512)
		}
	})
	t.Run("no duplicate Algorithm values", func(t *testing.T) {
		values := []int{
			AlgorithmDES, AlgorithmTripleDES, AlgorithmAES, AlgorithmRSA,
			AlgorithmDSA, AlgorithmECDSA, AlgorithmHMACSHA1, AlgorithmHMACSHA256,
			AlgorithmHMACSHA384, AlgorithmHMACSHA512,
		}
		seen := make(map[int]bool)
		for _, v := range values {
			if seen[v] {
				t.Errorf("duplicate Algorithm value 0x%08X", v)
			}
			seen[v] = true
		}
	})
}

// ---------------------------------------------------------------------------
// KeyFormatType values
// ---------------------------------------------------------------------------

func TestKeyFormatTypeValues(t *testing.T) {
	t.Run("Raw = 0x00000001", func(t *testing.T) {
		if KeyFormatRaw != 0x00000001 {
			t.Errorf("got 0x%08X, want 0x00000001", KeyFormatRaw)
		}
	})
	t.Run("Opaque = 0x00000002", func(t *testing.T) {
		if KeyFormatOpaque != 0x00000002 {
			t.Errorf("got 0x%08X, want 0x00000002", KeyFormatOpaque)
		}
	})
	t.Run("PKCS1 = 0x00000003", func(t *testing.T) {
		if KeyFormatPKCS1 != 0x00000003 {
			t.Errorf("got 0x%08X, want 0x00000003", KeyFormatPKCS1)
		}
	})
	t.Run("PKCS8 = 0x00000004", func(t *testing.T) {
		if KeyFormatPKCS8 != 0x00000004 {
			t.Errorf("got 0x%08X, want 0x00000004", KeyFormatPKCS8)
		}
	})
	t.Run("X509 = 0x00000005", func(t *testing.T) {
		if KeyFormatX509 != 0x00000005 {
			t.Errorf("got 0x%08X, want 0x00000005", KeyFormatX509)
		}
	})
	t.Run("ECPrivateKey = 0x00000006", func(t *testing.T) {
		if KeyFormatECPrivateKey != 0x00000006 {
			t.Errorf("got 0x%08X, want 0x00000006", KeyFormatECPrivateKey)
		}
	})
	t.Run("TransparentSymmetric = 0x00000007", func(t *testing.T) {
		if KeyFormatTransparentSymmetric != 0x00000007 {
			t.Errorf("got 0x%08X, want 0x00000007", KeyFormatTransparentSymmetric)
		}
	})
	t.Run("no duplicate KeyFormatType values", func(t *testing.T) {
		values := []int{
			KeyFormatRaw, KeyFormatOpaque, KeyFormatPKCS1, KeyFormatPKCS8,
			KeyFormatX509, KeyFormatECPrivateKey, KeyFormatTransparentSymmetric,
		}
		seen := make(map[int]bool)
		for _, v := range values {
			if seen[v] {
				t.Errorf("duplicate KeyFormatType value 0x%08X", v)
			}
			seen[v] = true
		}
	})
}

// ---------------------------------------------------------------------------
// NameType values
// ---------------------------------------------------------------------------

func TestNameTypeValues(t *testing.T) {
	t.Run("UninterpretedTextString = 0x00000001", func(t *testing.T) {
		if NameTypeUninterpretedTextString != 0x00000001 {
			t.Errorf("got 0x%08X, want 0x00000001", NameTypeUninterpretedTextString)
		}
	})
	t.Run("URI = 0x00000002", func(t *testing.T) {
		if NameTypeURI != 0x00000002 {
			t.Errorf("got 0x%08X, want 0x00000002", NameTypeURI)
		}
	})
}

// ---------------------------------------------------------------------------
// UsageMask — bitmask values
// ---------------------------------------------------------------------------

func TestUsageMaskValues(t *testing.T) {
	t.Run("Sign = 0x00000001", func(t *testing.T) {
		if UsageMaskSign != 0x00000001 {
			t.Errorf("got 0x%08X, want 0x00000001", UsageMaskSign)
		}
	})
	t.Run("Verify = 0x00000002", func(t *testing.T) {
		if UsageMaskVerify != 0x00000002 {
			t.Errorf("got 0x%08X, want 0x00000002", UsageMaskVerify)
		}
	})
	t.Run("Encrypt = 0x00000004", func(t *testing.T) {
		if UsageMaskEncrypt != 0x00000004 {
			t.Errorf("got 0x%08X, want 0x00000004", UsageMaskEncrypt)
		}
	})
	t.Run("Decrypt = 0x00000008", func(t *testing.T) {
		if UsageMaskDecrypt != 0x00000008 {
			t.Errorf("got 0x%08X, want 0x00000008", UsageMaskDecrypt)
		}
	})
	t.Run("WrapKey = 0x00000010", func(t *testing.T) {
		if UsageMaskWrapKey != 0x00000010 {
			t.Errorf("got 0x%08X, want 0x00000010", UsageMaskWrapKey)
		}
	})
	t.Run("UnwrapKey = 0x00000020", func(t *testing.T) {
		if UsageMaskUnwrapKey != 0x00000020 {
			t.Errorf("got 0x%08X, want 0x00000020", UsageMaskUnwrapKey)
		}
	})
	t.Run("Export = 0x00000040", func(t *testing.T) {
		if UsageMaskExport != 0x00000040 {
			t.Errorf("got 0x%08X, want 0x00000040", UsageMaskExport)
		}
	})
	t.Run("DeriveKey = 0x00000100", func(t *testing.T) {
		if UsageMaskDeriveKey != 0x00000100 {
			t.Errorf("got 0x%08X, want 0x00000100", UsageMaskDeriveKey)
		}
	})
	t.Run("KeyAgreement = 0x00000800", func(t *testing.T) {
		if UsageMaskKeyAgreement != 0x00000800 {
			t.Errorf("got 0x%08X, want 0x00000800", UsageMaskKeyAgreement)
		}
	})
	t.Run("Encrypt | Decrypt combines correctly", func(t *testing.T) {
		combined := UsageMaskEncrypt | UsageMaskDecrypt
		if combined != 0x0000000C {
			t.Errorf("got 0x%08X, want 0x0000000C", combined)
		}
	})
	t.Run("all values are distinct (no overlapping bits)", func(t *testing.T) {
		values := []int{
			UsageMaskSign, UsageMaskVerify, UsageMaskEncrypt, UsageMaskDecrypt,
			UsageMaskWrapKey, UsageMaskUnwrapKey, UsageMaskExport,
			UsageMaskDeriveKey, UsageMaskKeyAgreement,
		}
		combined := 0
		for _, v := range values {
			if combined&v != 0 {
				t.Errorf("value 0x%X overlaps with previous values", v)
			}
			combined |= v
		}
	})
}

// ---------------------------------------------------------------------------
// Tag values — all should be in the 0x42XXXX range
// ---------------------------------------------------------------------------

func TestTagValuesInKMIPRange(t *testing.T) {
	tags := map[string]int{
		"TagRequestMessage":          TagRequestMessage,
		"TagResponseMessage":         TagResponseMessage,
		"TagRequestHeader":           TagRequestHeader,
		"TagResponseHeader":          TagResponseHeader,
		"TagProtocolVersion":         TagProtocolVersion,
		"TagProtocolVersionMajor":    TagProtocolVersionMajor,
		"TagProtocolVersionMinor":    TagProtocolVersionMinor,
		"TagBatchCount":              TagBatchCount,
		"TagBatchItem":               TagBatchItem,
		"TagOperation":               TagOperation,
		"TagRequestPayload":          TagRequestPayload,
		"TagResponsePayload":         TagResponsePayload,
		"TagResultStatus":            TagResultStatus,
		"TagResultReason":            TagResultReason,
		"TagResultMessage":           TagResultMessage,
		"TagUniqueIdentifier":        TagUniqueIdentifier,
		"TagObjectType":              TagObjectType,
		"TagName":                    TagName,
		"TagNameValue":               TagNameValue,
		"TagNameType":                TagNameType,
		"TagAttribute":               TagAttribute,
		"TagAttributeName":           TagAttributeName,
		"TagAttributeValue":          TagAttributeValue,
		"TagSymmetricKey":            TagSymmetricKey,
		"TagKeyBlock":                TagKeyBlock,
		"TagKeyFormatType":           TagKeyFormatType,
		"TagKeyValue":                TagKeyValue,
		"TagKeyMaterial":             TagKeyMaterial,
		"TagCryptographicAlgorithm":  TagCryptographicAlgorithm,
		"TagCryptographicLength":     TagCryptographicLength,
		"TagCryptographicUsageMask":  TagCryptographicUsageMask,
		"TagTemplateAttribute":       TagTemplateAttribute,
	}

	t.Run("all Tag values are in 0x42XXXX range", func(t *testing.T) {
		for name, value := range tags {
			if value < 0x420000 || value > 0x42FFFF {
				t.Errorf("%s = 0x%06X is outside 0x42XXXX range", name, value)
			}
		}
	})

	t.Run("no duplicate tag values", func(t *testing.T) {
		seen := make(map[int]string)
		for name, value := range tags {
			if prev, ok := seen[value]; ok {
				t.Errorf("duplicate tag value 0x%06X: %s and %s", value, prev, name)
			}
			seen[value] = name
		}
	})

	// Individual tag value spot checks for specific hex values.
	t.Run("TagRequestMessage = 0x420078", func(t *testing.T) {
		if TagRequestMessage != 0x420078 {
			t.Errorf("got 0x%06X, want 0x420078", TagRequestMessage)
		}
	})
	t.Run("TagResponseMessage = 0x42007B", func(t *testing.T) {
		if TagResponseMessage != 0x42007B {
			t.Errorf("got 0x%06X, want 0x42007B", TagResponseMessage)
		}
	})
	t.Run("TagOperation = 0x42005C", func(t *testing.T) {
		if TagOperation != 0x42005C {
			t.Errorf("got 0x%06X, want 0x42005C", TagOperation)
		}
	})
	t.Run("TagUniqueIdentifier = 0x420094", func(t *testing.T) {
		if TagUniqueIdentifier != 0x420094 {
			t.Errorf("got 0x%06X, want 0x420094", TagUniqueIdentifier)
		}
	})
	t.Run("TagSymmetricKey = 0x42008F", func(t *testing.T) {
		if TagSymmetricKey != 0x42008F {
			t.Errorf("got 0x%06X, want 0x42008F", TagSymmetricKey)
		}
	})
}

