package fairplay

import (
	"bytes"
	"debug/macho"
	"encoding/hex"
	"fmt"

	"golang.org/x/arch/arm64/arm64asm"
)

const FairPlayBinaryProfileSchema = "ipatool-fairplay-binary-profile-v1"

type FairPlayBinaryAnchor struct {
	Name              string   `json:"name"`
	ReferenceAddress  uint64   `json:"reference_address"`
	InstructionCount  int      `json:"instruction_count"`
	ExactMatches      []uint64 `json:"exact_matches,omitempty"`
	NormalizedMatches []uint64 `json:"normalized_matches,omitempty"`
}

type FairPlayBinaryProfile struct {
	Schema            string                 `json:"schema"`
	SHA256            string                 `json:"sha256"`
	Bytes             int64                  `json:"bytes"`
	TextAddress       uint64                 `json:"text_address"`
	TextBytes         uint64                 `json:"text_bytes"`
	StructuralFamily  string                 `json:"structural_family,omitempty"`
	UniqueAnchorCount int                    `json:"unique_anchor_count"`
	ExactAnchorCount  int                    `json:"exact_anchor_count"`
	PortableCandidate bool                   `json:"portable_candidate"`
	Anchors           []FairPlayBinaryAnchor `json:"anchors"`
}

type fairPlayAnchorPattern struct {
	name       string
	address    uint64
	bytes      []byte
	operations []arm64asm.Op
}

var fairPlayAnchorDefinitions = []struct {
	name, encoded string
	address       uint64
}{
	{"account-entry", "4857bb720805000a0900130b2801084b21000014c7ed15350c7d1f53eb03282a6b7d1f538d150c4b0e0380526b350e1b6b010a0b4a010c0beada6af80c269252", 0x100cd1c18},
	{"state-bootstrap", "cb010a0a91020d0b82d871b8420018ca42805c8ba3d871b8630018ca7c08ac9b620117cac227c29a420006cad1da71b8310218ca310ab39b31423c8be204118a", 0x10057ae74},
	{"record-selection", "f407409194c20e9148c68c526821ae727a02080b48698f526821ae726802080be9fb46f929d968f888a496d2883ea0f2e873d4f2c8a7e6f2f95b46f9fb5f46f9", 0x1006b10a0},
	{"sinf-entry", "899a9152494bbb72aa9982520b01090beb0703b968010a4aa80314b8883d001249f69a524992b2726901094a2a7d081b481d0012493d0853815345b9ae424bb9", 0x10008a644},
	{"sinf-consumer", "886b683889258552a935a5724b01090b49038052eb0704b96901094aaa1880520a010acaf5cf41f9aa6a6a382901084a0b09805208010b4a8b791e12c7239252", 0x100234cdc},
}

func fairPlayAnchorPatterns() ([]fairPlayAnchorPattern, error) {
	result := make([]fairPlayAnchorPattern, 0, len(fairPlayAnchorDefinitions))
	for _, definition := range fairPlayAnchorDefinitions {
		data, err := hex.DecodeString(definition.encoded)
		if err != nil || len(data)%4 != 0 {
			return nil, fmt.Errorf("invalid FairPlay anchor %q", definition.name)
		}
		operations := make([]arm64asm.Op, len(data)/4)
		for index := range operations {
			instruction, decodeErr := arm64asm.Decode(data[index*4 : index*4+4])
			if decodeErr != nil {
				return nil, fmt.Errorf("decode FairPlay anchor %q: %w", definition.name, decodeErr)
			}
			operations[index] = instruction.Op
		}
		result = append(result, fairPlayAnchorPattern{
			name: definition.name, address: definition.address, bytes: data, operations: operations,
		})
	}
	return result, nil
}

func allByteMatches(blob, pattern []byte, base uint64, limit int) []uint64 {
	var result []uint64
	for cursor := 0; cursor <= len(blob)-len(pattern); {
		index := bytes.Index(blob[cursor:], pattern)
		if index < 0 {
			break
		}
		offset := cursor + index
		if offset%4 != 0 {
			cursor = offset + 1
			continue
		}
		result = append(result, base+uint64(offset))
		if len(result) == limit {
			break
		}
		cursor = offset + 4
	}
	return result
}

func normalizedARM64Operations(text []byte) ([]arm64asm.Op, []bool) {
	operations := make([]arm64asm.Op, len(text)/4)
	valid := make([]bool, len(operations))
	for index := range operations {
		instruction, err := arm64asm.Decode(text[index*4 : index*4+4])
		if err == nil {
			operations[index], valid[index] = instruction.Op, true
		}
	}
	return operations, valid
}

func normalizedOperationMatches(operations []arm64asm.Op, valid []bool, pattern []arm64asm.Op, base uint64, limit int) []uint64 {
	var result []uint64
	for start := 0; start+len(pattern) <= len(operations); start++ {
		if !valid[start] || operations[start] != pattern[0] {
			continue
		}
		matched := true
		for index := 1; index < len(pattern); index++ {
			if !valid[start+index] || operations[start+index] != pattern[index] {
				matched = false
				break
			}
		}
		if matched {
			result = append(result, base+uint64(start*4))
			if len(result) == limit {
				break
			}
		}
	}
	return result
}

func InspectFairPlayBinaryProfile(path string) (FairPlayBinaryProfile, error) {
	var result FairPlayBinaryProfile
	var file *macho.File
	fat, fatErr := macho.OpenFat(path)
	if fatErr == nil {
		defer fat.Close()
		for index := range fat.Arches {
			candidate := fat.Arches[index].File
			if candidate.Cpu == macho.CpuArm64 && uint32(candidate.SubCpu)&0x00ffffff == 2 {
				file = candidate
				if uint32(candidate.SubCpu)&0xff000000 == 0 {
					break
				}
			}
		}
	} else {
		thin, err := macho.Open(path)
		if err != nil {
			return result, fmt.Errorf("open FairPlay Mach-O: %w", err)
		}
		defer thin.Close()
		file = thin
	}
	if file == nil || file.Cpu != macho.CpuArm64 || uint32(file.SubCpu)&0x00ffffff != 2 {
		return result, fmt.Errorf("FairPlay binary is not arm64e")
	}
	section := file.Section("__text")
	if section == nil || section.Seg != "__TEXT" {
		return result, fmt.Errorf("FairPlay binary has no __TEXT,__text section")
	}
	text, err := section.Data()
	if err != nil {
		return result, err
	}
	hash, size, err := arm64eMachOHash(path)
	if err != nil {
		return result, err
	}
	patterns, err := fairPlayAnchorPatterns()
	if err != nil {
		return result, err
	}
	operations, valid := normalizedARM64Operations(text)
	result = FairPlayBinaryProfile{
		Schema: FairPlayBinaryProfileSchema, SHA256: hash, Bytes: size,
		TextAddress: section.Addr, TextBytes: section.Size,
	}
	accountEntryMatched := false
	for _, pattern := range patterns {
		anchor := FairPlayBinaryAnchor{
			Name: pattern.name, ReferenceAddress: pattern.address,
			InstructionCount:  len(pattern.operations),
			ExactMatches:      allByteMatches(text, pattern.bytes, section.Addr, 64),
			NormalizedMatches: normalizedOperationMatches(operations, valid, pattern.operations, section.Addr, 64),
		}
		if len(anchor.ExactMatches) == 1 {
			result.ExactAnchorCount++
		}
		if len(anchor.NormalizedMatches) == 1 {
			result.UniqueAnchorCount++
			accountEntryMatched = accountEntryMatched || pattern.name == "account-entry"
		}
		result.Anchors = append(result.Anchors, anchor)
	}
	if result.UniqueAnchorCount >= 3 {
		result.StructuralFamily = "macos-current-flattened-v1"
		result.PortableCandidate = true
	} else if accountEntryMatched {
		result.StructuralFamily = "macos-current-account-entry-v1"
	}
	return result, nil
}
