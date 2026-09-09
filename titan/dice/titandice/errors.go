// Copyright 2026 Google LLC
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

package titandice

import (
	"errors"
)

var (
	// ErrMissingCertChain indicates that the certificate chain is missing.
	ErrMissingCertChain = errors.New("missing certificate chain")

	// ErrMissingAKC indicates that the AliasKeyCertificate is missing.
	ErrMissingAKC = errors.New("missing AliasKeyCertificate")

	// ErrMissingAKHC indicates that the AliasKeyHprivCertificate is missing.
	ErrMissingAKHC = errors.New("missing AliasKeyHprivCertificate")

	// ErrMissingDIDC indicates that the DeviceIdCertificate is missing.
	ErrMissingDIDC = errors.New("missing DeviceIdCertificate")

	// ErrMissingDIDSC indicates that the DeviceIdScribeCertificate is missing.
	ErrMissingDIDSC = errors.New("missing DeviceIdScribeCertificate")

	// ErrMissingEKC indicates that the EndorsementKeyCertificate is missing.
	ErrMissingEKC = errors.New("missing EndorsementKeyCertificate")

	// ErrMissingFH indicates that the FwHash is missing.
	ErrMissingFH = errors.New("missing FwHash")

	// ErrMissingHKC indicates that the TitanKeyCertificate is missing.
	ErrMissingHKC = errors.New("missing TitanKeyCertificate")

	// ErrMissingValidateOpts indicates that the ValidateScribeCertificateChainOptions is missing.
	ErrMissingValidateOpts = errors.New("missing ValidateScribeCertificateChainOptions")

	// ErrAKCSignatureVersion indicates that the AliasKeyCertificate contains an invalid SignatureVersion.
	ErrAKCSignatureVersion = errors.New("bad AliasKeyCertificate.SignatureVersion")

	// ErrAKCSignaturePurpose indicates that the AliasKeyCertificate contains an invalid SignaturePurpose.
	ErrAKCSignaturePurpose = errors.New("bad AliasKeyCertificate.SignaturePurpose")

	// ErrAKCKeyType indicates that the AliasKeyCertificate contains an invalid KeyType.
	ErrAKCKeyType = errors.New("bad AliasKeyCertificate.KeyType")

	// ErrAKCKeyOp indicates that the AliasKeyCertificate contains an invalid KeyOp.
	ErrAKCKeyOp = errors.New("bad AliasKeyCertificate.KeyOp")

	// ErrAKCKeyAlg indicates that the AliasKeyCertificate contains an invalid KeyAlg.
	ErrAKCKeyAlg = errors.New("bad AliasKeyCertificate.KeyAlg")

	// ErrAKCReserved0 indicates that the AliasKeyCertificate contains an invalid Reserved0.
	ErrAKCReserved0 = errors.New("bad AliasKeyCertificate.Reserved0")

	// ErrAKCPubKeySize indicates that the AliasKeyCertificate contains an invalid PubKeySize.
	ErrAKCPubKeySize = errors.New("bad AliasKeyCertificate.PubKeySize")

	// ErrAKCReserved1 indicates that the AliasKeyCertificate contains an invalid Reserved1.
	ErrAKCReserved1 = errors.New("bad AliasKeyCertificate.Reserved1")

	// ErrAKCExtensionHeaderType indicates that the AliasKeyCertificate contains an invalid ExtensionHeaderType.
	ErrAKCExtensionHeaderType = errors.New("bad AliasKeyCertificate.ExtensionHeaderType")

	// ErrAKCCertValidity indicates that the AliasKeyCertificate contains an invalid CertValidity.
	ErrAKCCertValidity = errors.New("bad AliasKeyCertificate.CertValidity")

	// ErrAKCHWCat indicates that the AliasKeyCertificate HwCat does not match the DeviceIdCertificate HwCat.
	ErrAKCHWCat = errors.New("AliasKeyCertificate.HwCat does not match DeviceIdCertificate")

	// ErrAKCHWID indicates that the AliasKeyCertificate HwId does not match the DeviceIdCertificate HwId.
	ErrAKCHWID = errors.New("AliasKeyCertificate.HwId does not match DeviceIdCertificate")

	// ErrAKCBootloaderTag indicates that the AliasKeyCertificate BootloaderTag does not match the DeviceIdCertificate BootloaderTag.
	ErrAKCBootloaderTag = errors.New("AliasKeyCertificate.BootloaderTag does not match DeviceIdCertificate")

	// ErrAKCKeyInfo indicates that the AliasKeyCertificate KeyInfo does not match the DeviceIdCertificate public key.
	ErrAKCKeyInfo = errors.New("AliasKeyCertificate.KeyInfo does not match DeviceIdCertificate public key")

	// ErrAKCSignature indicates that the AliasKeyCertificate Signature does not validate using the DeviceIdCertificate public key.
	ErrAKCSignature = errors.New("AliasKeyCertificate.Signature does not validate with DeviceIdCertificate public key")

	// ErrAKHCCertHash indicates that the AliasKeyHprivCertificate contains an invalid CertHash.
	ErrAKHCCertHash = errors.New("bad AliasKeyHprivCertificate.CertHash")

	// ErrAKHCHpubKey indicates that the AliasKeyHprivCertificate contains an invalid HpubKey.
	ErrAKHCHpubKey = errors.New("bad AliasKeyHprivCertificate.HpubKey")

	// ErrAKHCSignature indicates that the AliasKeyHprivCertificate Signature does not validate using the TitanKeyCertificate public key.
	ErrAKHCSignature = errors.New("AliasKeyHprivCertificate.Signature does not validate with TitanKeyCertificate public key")

	// ErrDIDCHWID0 indicates that the DeviceIdCertificate HwId is 0, indicating possible flash corruption.
	ErrDIDCHWID0 = errors.New("Device ID Certificate hardware ID is 0, possible flash corruption")

	// ErrDIDCSignatureVersion indicates that the DeviceIdCertificate contains an invalid SignatureVersion.
	ErrDIDCSignatureVersion = errors.New("bad DeviceIdCertificate.SignatureVersion")

	// ErrDIDCSignaturePurpose indicates that the DeviceIdCertificate contains an invalid SignaturePurpose.
	ErrDIDCSignaturePurpose = errors.New("bad DeviceIdCertificate.SignaturePurpose")

	// ErrDIDCKeyType indicates that the DeviceIdCertificate contains an invalid KeyType.
	ErrDIDCKeyType = errors.New("bad DeviceIdCertificate.KeyType")

	// ErrDIDCKeyOp indicates that the DeviceIdCertificate contains an invalid KeyOp.
	ErrDIDCKeyOp = errors.New("bad DeviceIdCertificate.KeyOp")

	// ErrDIDCKeyAlg indicates that the DeviceIdCertificate contains an invalid KeyAlg.
	ErrDIDCKeyAlg = errors.New("bad DeviceIdCertificate.KeyAlg")

	// ErrDIDCExtensionHeaderType indicates that the DeviceIdCertificate contains an invalid ExtensionHeaderType.
	ErrDIDCExtensionHeaderType = errors.New("bad DeviceIdCertificate.ExtensionHeaderType")

	// ErrDIDCSignedDataSize indicates that the DeviceIdCertificate contains an invalid SignedDataSize.
	ErrDIDCSignedDataSize = errors.New("bad DeviceIdCertificate.SignedDataSize")

	// ErrDIDCScribeKeyID indicates that the DeviceIdCertificate contains a non-trusted ScribeKeyID.
	ErrDIDCScribeKeyID = errors.New("bad DeviceIdCertificate.ScribeKeyID")

	// ErrDIDCScribeKeyInfo indicates that the DeviceIdCertificate KeyInfo does not match the ScribeCertificate public key.
	ErrDIDCScribeKeyInfo = errors.New("DeviceIdCertificate.KeyInfo does not match ScribeCertificate public key")

	// ErrDIDCScribeType indicates that the ScribeCertificate used to sign the DeviceIdCertificate is not a payload signing key.
	ErrDIDCScribeType = errors.New("bad ScribeCertificate.Magic")

	// ErrDIDCSignature indicates that the DeviceIdCertificate Signature does not validate using the ScribeCertificate public key.
	ErrDIDCSignature = errors.New("DeviceIdCertificate.Signature does not validate with ScribeCertificate public key")

	// ErrDIDSCCertHash indicates that the DeviceIdScribeCertificate contains an invalid CertHash.
	ErrDIDSCCertHash = errors.New("bad DeviceIdScribeCertificate.CertHash")

	// ErrDIDSCScribeKey indicates that the DeviceIdScribeCertificate contains a non-trusted ScribeRwKey.
	ErrDIDSCScribeKey = errors.New("bad DeviceIdScribeCertificate.ScribeRwKey")

	// ErrDIDSCScribeType indicates that the ScribeCertificate used to sign the DeviceIdScribeCertificate is not a Titan scribe key.
	ErrDIDSCScribeType = errors.New("bad ScribeCertificate.Magic")

	// ErrDIDSCSignature indicates that the DeviceIdScribeCertificate Signature does not validate using the ScribeCertificate public key.
	ErrDIDSCSignature = errors.New("DeviceIdScribeCertificate.Signature does not validate with ScribeCertificate public key")

	// ErrEKSignatureVersion indicates that the EkCertificate contains an invalid SignatureVersion.
	ErrEKSignatureVersion = errors.New("bad EkCertificate.SignatureVersion")

	// ErrEKSignaturePurpose indicates that the EkCertificate contains an invalid SignaturePurpose.
	ErrEKSignaturePurpose = errors.New("bad EkCertificate.SignaturePurpose")

	// ErrEKExtensionHeaderType indicates that the EkCertificate contains an invalid ExtensionHeaderType.
	ErrEKExtensionHeaderType = errors.New("bad EkCertificate.ExtensionHeaderType")

	// ErrEKKeyType indicates that the EkCertificate contains an invalid KeyType.
	ErrEKKeyType = errors.New("bad EkCertificate.KeyType")

	// ErrEKKeyOp indicates that the EkCertificate contains an invalid KeyOp.
	ErrEKKeyOp = errors.New("bad EkCertificate.KeyOp")

	// ErrEKKeyAlg indicates that the EkCertificate contains an invalid KeyAlg.
	ErrEKKeyAlg = errors.New("bad EkCertificate.KeyAlg")

	// ErrEKReserved0 indicates that the EkCertificate contains an invalid Reserved0.
	ErrEKReserved0 = errors.New("bad EkCertificate.Reserved0")

	// ErrEKPubKeySize indicates that the EkCertificate contains an invalid PubKeySize.
	ErrEKPubKeySize = errors.New("bad EkCertificate.PubKeySize")

	// ErrEKReserved1 indicates that the EkCertificate contains an invalid Reserved1.
	ErrEKReserved1 = errors.New("bad EkCertificate.Reserved1")

	// ErrEKHWCat indicates that the EkCertificate HwCat does not match the AliasKeyCertificate HwCat.
	ErrEKHWCat = errors.New("EkCertificate.HwCat does not match AliasKeyCertificate")

	// ErrEKHWID indicates that the EkCertificate HwId does not match the AliasKeyCertificate HwId.
	ErrEKHWID = errors.New("EkCertificate.HwId does not match AliasKeyCertificate")

	// ErrEKBootloaderTag indicates that the EkCertificate BootloaderTag does not match the AliasKeyCertificate BootloaderTag.
	ErrEKBootloaderTag = errors.New("EkCertificate.BootloaderTag does not match AliasKeyCertificate")

	// ErrEKFirmwareEpoch indicates that the EkCertificate FirmwareEpoch does not match the AliasKeyCertificate FirmwareEpoch.
	ErrEKFirmwareEpoch = errors.New("EkCertificate.FirmwareEpoch does not match AliasKeyCertificate")

	// ErrEKFirmwareMajorVersionMismatch indicates that the EkCertificate FirmwareMajorVersion does not match the AliasKeyCertificate FirmwareMajorVersion.
	ErrEKFirmwareMajorVersionMismatch = errors.New("EkCertificate.FirmwareMajorVersion does not match AliasKeyCertificate")

	// ErrEKFirmwareMajorVersionNonZero indicates that the EkCertificate FirmwareMajorVersion is non-zero.
	ErrEKFirmwareMajorVersionNonZero = errors.New("EkCertificate.FirmwareMajorVersion is non-zero")

	// ErrEKPubToECCPoint indicates an error converting an EkCertificate's key to an ECC point.
	ErrEKPubToECCPoint = errors.New("error converting EkCertificate's public key to an ECC point")

	// ErrEKSignature indicates that the EkCertificate Signature does not validate using the AliasKeyCertificate.
	ErrEKSignature = errors.New("EkCertificate.Signature does not validate with AliasKeyCertificate")

	// ErrEKTemplate indicates that the EK template was incorrect.
	ErrEKTemplate = errors.New("EKCertificate object name does not match the expected template")

	// ErrEKTemplateAssembly indicates that the EK certificate could not be assembled.
	ErrEKTemplateAssembly = errors.New("could not assemble EK certificate with expected template")
)
