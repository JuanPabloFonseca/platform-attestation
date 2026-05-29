package descriptor

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// createTestDescriptor generates a valid descriptor using official structures and logic.
func createTestDescriptor(t *testing.T, scheme VerificationScheme, hashType HashType, offset uint32) []byte {
	t.Helper()
	dp := DescriptorParts{
		Descriptor: ImageDescriptor{
			DescriptorMagic:    DescriptorMagicLE,
			DescriptorMajor:    1,
			DescriptorMinor:    0,
			DescriptorOffset:   offset,
			HashType:           hashType,
			VerificationScheme: scheme,
			RegionCount:        1,
		},
		Regions: []ImageRegion{
			{
				RegionOffset: 0,
				RegionSize:   1024,
			},
		},
	}
	copy(dp.Regions[0].RegionName[:], "test_region")

	// Initialize the internal optional structures.
	var err error
	dp.Hash, err = NewDescriptorHash(hashType)
	if err != nil {
		t.Fatalf("createTestDescriptor: NewDescriptorHash failed: %v", err)
	}
	if scheme == VerificationSchemeSHA256 {
		dp.Signature, err = NewSignatureDigest(scheme)
		if err != nil {
			t.Fatalf("createTestDescriptor: NewSignatureDigest failed: %v", err)
		}
	} else {
		// Use dummy RSA parameters.
		dp.Signature, err = NewSignatureRSA(scheme, 0, 0, 0, nil)
		if err != nil {
			t.Fatalf("createTestDescriptor: NewSignatureRSA failed: %v", err)
		}
	}

	// Calculate and set the correct area size.
	size, err := dp.Descriptor.CalculateSize()
	if err != nil {
		t.Fatalf("createTestDescriptor: CalculateSize failed: %v", err)
	}
	dp.Descriptor.DescriptorAreaSize = uint32(size)

	var b bytes.Buffer
	if _, err := dp.WriteDescriptorParts(&b); err != nil {
		t.Fatalf("Failed to build test descriptor: %v", err)
	}

	return b.Bytes()
}

// TestGetHashFromFile_Schemes verifies that the library can parse descriptors
// using various Verification Schemes and correctly identifies the hash algorithm.
func TestHashFromFile_Schemes(t *testing.T) {
	tests := []struct {
		name   string
		scheme VerificationScheme
		hash   HashType
	}{
		{"SHA256_Only", VerificationSchemeSHA256, HashTypeSHA2_256},
		{"RSA2048", VerificationSchemeRSA2048PKCS15SHA256, HashTypeSHA2_256},
		{"RSA4096_SHA512", VerificationSchemeRSA4096PKCS15SHA512, HashTypeSHA2_512},
	}

	tmpDir := t.TempDir()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			descData := createTestDescriptor(t, tt.scheme, tt.hash, 0)
			path := filepath.Join(tmpDir, fmt.Sprintf("%s.bin", tt.name))
			os.WriteFile(path, descData, 0644)

			got, err := HashFromFile(path)
			if err != nil {
				t.Fatalf("HashFromFile failed: %v", err)
			}

			if got.hashType != tt.hash {
				t.Errorf("HashFromFile returned wrong hash type: got %v, want %v", got.hashType, tt.hash)
			}

			// Verify digest size matches the algorithm output
			expectedDigestSize := 32
			if tt.hash == HashTypeSHA2_512 {
				expectedDigestSize = 64
			}
			if len(got.digest) != expectedDigestSize {
				t.Errorf("HashFromFile returned wrong digest size: got %d, want %d", len(got.digest), expectedDigestSize)
			}
		})
	}
}

// TestGetHashFromFile_Scanner verifies the backward-scanning logic.
// It ensures that "fake" magic numbers are ignored if their internal DescriptorOffset field
// doesn't point correctly to the physical start of the descriptor.
func TestHashFromFile_Scanner(t *testing.T) {
	tmpDir := t.TempDir()
	const validOffset = uint32(0x20000) // 128KB boundary

	image := make([]byte, 256*1024)
	for i := range image {
		image[i] = 0xAA // Background noise
	}

	// 1. Setup a "Fake" Magic at 64KB.
	// This has the right magic but a wrong internal offset.
	fakeHeader := ImageDescriptor{
		DescriptorMagic:  DescriptorMagicLE,
		DescriptorOffset: 0x9999, // Wrong offset (False Positive)
	}
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, fakeHeader)
	copy(image[0x10000:], buf.Bytes())

	// 2. Setup a "Real" Magic at 128KB.
	// This correctly points to its own starting position.
	realDesc := createTestDescriptor(t, VerificationSchemeSHA256, HashTypeSHA2_256, validOffset)
	copy(image[validOffset:], realDesc)

	path := filepath.Join(tmpDir, "scanner_test.bin")
	os.WriteFile(path, image, 0644)

	got, err := HashFromFile(path)
	if err != nil {
		t.Fatalf("HashFromFile failed to find valid descriptor: %v", err)
	}

	if len(got.digest) != 32 {
		t.Error("HashFromFile failed to extract valid descriptor from multi-magic image")
	}
}

// TestAllCombinations ensures that the library correctly handles every supported
// combination of Verification Scheme and Hash Type without crashing.
func TestAllCombinations(t *testing.T) {
	schemes := []VerificationScheme{
		VerificationSchemeRSA2048PKCS15SHA256,
		VerificationSchemeRSA3072PKCS15SHA256,
		VerificationSchemeRSA4096PKCS15SHA256,
		VerificationSchemeRSA4096PKCS15SHA512,
		VerificationSchemeSHA256,
	}
	hashTypes := []HashType{
		HashTypeSHA2_256,
		HashTypeSHA2_512,
	}

	tmpDir := t.TempDir()

	for _, s := range schemes {
		for _, h := range hashTypes {
			t.Run(fmt.Sprintf("Scheme%d_Hash%d", s, h), func(t *testing.T) {
				data := createTestDescriptor(t, s, h, 0)
				path := filepath.Join(tmpDir, "combo.bin")
				os.WriteFile(path, data, 0644)
				// We don't check the hash value here, just that it doesn't crash
				// and handles errors gracefully for the invalid scheme.
				if _, err := HashFromFile(path); err != nil {
					t.Logf("HashFromFile failed for combination (Scheme: %d, Hash: %d) as expected: %v", s, h, err)
				}
			})
		}
	}
}

// TestSignatureBoundary verifies that the hashing logic stops exactly at the
// beginning of the signature area, ensuring mathematical precision.
func TestSignatureBoundary(t *testing.T) {
	scheme := VerificationSchemeSHA256 // Has 32-byte signature
	hashType := HashType(HashTypeSHA2_256)

	// 1. Create a valid descriptor using the helper.
	data := createTestDescriptor(t, scheme, hashType, 0)
	sigSize := SignatureValueSize(scheme)
	payloadLen := len(data) - sigSize

	// Create poisoned data where we manually overwrite the signature area with 0xBB.
	poisonedData := make([]byte, len(data))
	copy(poisonedData, data)
	for i := payloadLen; i < len(poisonedData); i++ {
		poisonedData[i] = 0xBB
	}

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "boundary.bin")
	os.WriteFile(path, poisonedData, 0644)

	// 2. Perform reference hash of only the payload (the original unpoisoned data)
	expected := sha256.Sum256(data[0:payloadLen])

	// 3. Run library logic on the full binary file (including poison)
	got, err := HashFromFile(path)
	if err != nil {
		t.Fatalf("HashFromFile failed: %v", err)
	}

	if !bytes.Equal(got.digest, expected[:]) {
		t.Errorf("GetHashFromFile precision failure! Library did not stop at the signature boundary.\nGot: %x\nWant: %x", got.digest, expected)
	}
}
