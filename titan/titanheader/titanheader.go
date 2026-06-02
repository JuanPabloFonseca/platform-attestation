// Package titanheader provides shared parsed structures, offsets, and descriptor scanning for Titan libraries.
package titanheader

import (
	"encoding/binary"
	"fmt"
	"io"
)

// TitanHeaderMagic is the magic number identifying a Titan Region Descriptor ("_HAVEND_").
const TitanHeaderMagic = 0x5f444e455641485f

// SignedHeaderSize is the exact size of the SignedHeader struct in bytes.
const SignedHeaderSize = 1024

// SignedHeader Byte Offsets:
const (
	MagicFieldOffset     = 0
	ImageSizeFieldOffset = 808
	MajorFieldOffset     = 864
	TagFieldOffset       = 392
)

// TitanRegionDescriptor maps the layout of the update bundle components.
type TitanRegionDescriptor struct {
	DescriptorMagic    uint64
	DescriptorVersion  uint8
	DeliveryMechanism  uint8
	Flags              uint16
	BootloaderAOffset  uint32
	BootloaderASize    uint32
	BootloaderBOffset  uint32
	BootloaderBSize    uint32
	AppFirmwareAOffset uint32
	AppFirmwareASize   uint32
	AppFirmwareBOffset uint32
	AppFirmwareBSize   uint32
	DataRegionOffset   uint32
	DataRegionSize     uint32
}

// ScanHeader scans the file stream to locate where the TitanRegionDescriptor begins.
// It checks offset 0 first, then offset 12 (to handle nested SPI file structures).
func ScanHeader(r io.ReadSeeker) (int64, error) {
	var magic uint64

	// 1. Check offset 0.
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return 0, fmt.Errorf("ScanHeader failed to seek to 0: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &magic); err == nil {
		if magic == TitanHeaderMagic {
			return 0, nil
		}
	}

	// 2. Check offset 12.
	if _, err := r.Seek(12, io.SeekStart); err != nil {
		return 0, fmt.Errorf("ScanHeader failed to seek to 12: %w", err)
	}
	if err := binary.Read(r, binary.LittleEndian, &magic); err == nil {
		if magic == TitanHeaderMagic {
			return 12, nil
		}
	}

	return 0, fmt.Errorf("no valid TitanRegionDescriptor found")
}
