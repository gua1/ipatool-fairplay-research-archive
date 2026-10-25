package fairplay

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

type SINFDiagnostic struct {
	Path          string       `json:"path,omitempty"`
	SHA256        string       `json:"sha256"`
	Bytes         int          `json:"bytes"`
	Selector      SINFSelector `json:"selector"`
	SelectorID    string       `json:"selector_id"`
	PrivateBytes  int          `json:"private_bytes"`
	Atoms         []string     `json:"atoms"`
	CurrentLayout bool         `json:"current_layout"`
	LegacyMarkers bool         `json:"legacy_markers"`
}

type EnrollmentModelDiagnostic struct {
	Path          string        `json:"path"`
	SHA256        string        `json:"sha256"`
	Bytes         int           `json:"bytes"`
	Version       uint32        `json:"version"`
	FairPlaydHash string        `json:"fairplayd_sha256"`
	Selector      *SINFSelector `json:"selector,omitempty"`
	SelectorID    string        `json:"selector_id,omitempty"`
}

type FairPlayDoctorReport struct {
	Schema          string                       `json:"schema"`
	CreatedAt       string                       `json:"created_at"`
	Ready           bool                         `json:"ready"`
	DecryptReady    bool                         `json:"decrypt_ready"`
	Host            *FairPlayHostDiagnostic      `json:"host,omitempty"`
	Capture         *EnrollmentCaptureDiagnostic `json:"capture,omitempty"`
	CaptureVerified bool                         `json:"capture_verified"`
	SINF            []SINFDiagnostic             `json:"sinf,omitempty"`
	Models          []EnrollmentModelDiagnostic  `json:"models,omitempty"`
	CompatibleModel string                       `json:"compatible_model,omitempty"`
	Checks          map[string]bool              `json:"checks"`
	Errors          []string                     `json:"errors,omitempty"`
	Warnings        []string                     `json:"warnings,omitempty"`
	NextActions     []string                     `json:"next_actions,omitempty"`
}

type EnrollmentCaptureDiagnostic struct {
	ProductVersion  string               `json:"product_version"`
	BuildVersion    string               `json:"build_version"`
	FairPlaydSHA256 string               `json:"fairplayd_sha256"`
	FairPlaySupport FairPlayBuildSupport `json:"fairplay_support"`
	SelectorID      string               `json:"selector_id"`
	Files           int                  `json:"files"`
	HasIPA          bool                 `json:"has_ipa"`
}

type FairPlayHostDiagnostic struct {
	ProductVersion     string               `json:"product_version"`
	BuildVersion       string               `json:"build_version"`
	FairPlaydSHA256    string               `json:"fairplayd_sha256"`
	FairPlaySupport    FairPlayBuildSupport `json:"fairplay_support"`
	StateAccessible    bool                 `json:"state_accessible"`
	StateFiles         int                  `json:"state_files"`
	HardwareMACPresent bool                 `json:"hardware_iomac_present"`
}

func InspectLocalFairPlayHost() (FairPlayHostDiagnostic, error) {
	var result FairPlayHostDiagnostic
	if runtime.GOOS != "darwin" {
		return result, fmt.Errorf("local FairPlay host inspection requires macOS")
	}
	var err error
	result.ProductVersion, err = querySystemVersion("-productVersion")
	if err != nil {
		return result, err
	}
	result.BuildVersion, err = querySystemVersion("-buildVersion")
	if err != nil {
		return result, err
	}
	result.FairPlaydSHA256, _, err = arm64eMachOHash("/System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/fairplayd")
	if err != nil {
		return result, err
	}
	if support, ok := LookupFairPlayBuild(result.FairPlaydSHA256); ok {
		result.FairPlaySupport = support
	} else {
		result.FairPlaySupport = FairPlayBuildSupport{Build: result.BuildVersion, Status: "unsupported"}
	}
	entries, stateErr := os.ReadDir("/private/var/db/fpsd/SC Info")
	if stateErr == nil {
		result.StateAccessible = true
		for _, entry := range entries {
			if !entry.IsDir() && entry.Type()&os.ModeSymlink == 0 {
				result.StateFiles++
			}
		}
	}
	mac, macErr := ioregHardwareMAC("en0")
	if macErr == nil && len(mac) == 6 {
		result.HardwareMACPresent = true
		clear(mac)
	}
	return result, nil
}

func InspectSINF(data []byte) (SINFDiagnostic, error) {
	var result SINFDiagnostic
	digest := sha256.Sum256(data)
	result.SHA256 = hex.EncodeToString(digest[:])
	result.Bytes = len(data)
	fields, err := parseSINFFields(data)
	if err != nil {
		return result, err
	}
	selector, err := sinfSelector(data, fields)
	if err != nil {
		return result, err
	}
	result.Selector = selector
	result.SelectorID = selector.Identifier()
	for _, field := range fields {
		result.Atoms = append(result.Atoms, field.typ)
		if field.typ == "priv" {
			result.PrivateBytes = field.end - field.start
		}
		if field.typ == "crdt" || field.typ == "asdt" {
			result.LegacyMarkers = true
		}
	}
	// Current Store enrollments can retain crdt/asdt compatibility atoms. The
	// protected private-payload geometry, not those optional markers, is the
	// useful non-secret preflight signal.
	result.CurrentLayout = result.PrivateBytes == 440 || result.PrivateBytes == 448
	return result, nil
}

func InspectEnrollmentModel(path string) (EnrollmentModelDiagnostic, error) {
	var result EnrollmentModelDiagnostic
	pack, err := readEnrollmentModel(path)
	if err != nil {
		return result, err
	}
	defer clear(pack)
	model, err := parseCurrentSINFModel(pack)
	if err != nil {
		return result, err
	}
	digest := sha256.Sum256(pack)
	result = EnrollmentModelDiagnostic{
		Path: path, SHA256: hex.EncodeToString(digest[:]), Bytes: len(pack), Version: model.version,
		FairPlaydHash: hex.EncodeToString(model.fairplaydHash[:]),
	}
	if model.hasSelector {
		selector := model.selector
		result.Selector = &selector
		result.SelectorID = selector.Identifier()
	}
	return result, nil
}

func inspectModelPath(path string) ([]EnrollmentModelDiagnostic, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		model, err := InspectEnrollmentModel(path)
		return []EnrollmentModelDiagnostic{model}, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("model directory must be mode 0700 or stricter")
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	var result []EnrollmentModelDiagnostic
	for _, entry := range entries {
		if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".bin") {
			continue
		}
		model, err := InspectEnrollmentModel(filepath.Join(path, entry.Name()))
		if err != nil {
			return nil, err
		}
		result = append(result, model)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("model directory contains no .bin models")
	}
	return result, nil
}

func inspectIPASINFs(path string) ([]SINFDiagnostic, error) {
	archive, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer archive.Close()
	var result []SINFDiagnostic
	for _, file := range archive.File {
		if !strings.Contains(file.Name, "/SC_Info/") || !strings.HasSuffix(strings.ToLower(file.Name), ".sinf") {
			continue
		}
		reader, err := file.Open()
		if err != nil {
			return nil, err
		}
		data, readErr := io.ReadAll(reader)
		closeErr := reader.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		value, err := InspectSINF(data)
		if err != nil {
			return nil, fmt.Errorf("inspect %s: %w", file.Name, err)
		}
		value.Path = file.Name
		result = append(result, value)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("IPA contains no SINF files")
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Path < result[right].Path })
	return result, nil
}

func readIPASINF(path, member string) ([]byte, error) {
	archive, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer archive.Close()
	var selected *zip.File
	for _, file := range archive.File {
		if file.Name != member {
			continue
		}
		if selected != nil {
			return nil, fmt.Errorf("IPA has duplicate SINF member %q", member)
		}
		selected = file
	}
	if selected == nil {
		return nil, fmt.Errorf("IPA SINF member %q is missing", member)
	}
	return zipBytes(selected)
}

func validatedModelForSINF(ipaPath, member, modelPath string,
	models []EnrollmentModelDiagnostic, capture *EnrollmentCaptureManifest) (string, error) {
	sinf, err := readIPASINF(ipaPath, member)
	if err != nil {
		return "", err
	}
	defer clear(sinf)
	info, err := os.Stat(modelPath)
	if err != nil {
		return "", err
	}
	var material KeyMaterial
	if info.IsDir() {
		packs, readErr := readEnrollmentModelRegistry(modelPath)
		if readErr != nil {
			return "", readErr
		}
		defer clearModelPacks(packs)
		eligible := make([][]byte, 0, len(packs))
		for _, pack := range packs {
			model, parseErr := parseCurrentSINFModel(pack)
			if parseErr != nil {
				return "", parseErr
			}
			if modelMatchesCaptureBuild(hex.EncodeToString(model.fairplaydHash[:]), capture) {
				eligible = append(eligible, pack)
			}
		}
		if len(eligible) == 0 {
			return "", fmt.Errorf("no enrollment model matches the capture's FairPlay build")
		}
		material, err = ResolveLogicalKeyWithModels(sinf, eligible)
	} else {
		pack, readErr := readEnrollmentModel(modelPath)
		if readErr != nil {
			return "", readErr
		}
		defer clear(pack)
		model, parseErr := parseCurrentSINFModel(pack)
		if parseErr != nil {
			return "", parseErr
		}
		if !modelMatchesCaptureBuild(hex.EncodeToString(model.fairplaydHash[:]), capture) {
			return "", fmt.Errorf("enrollment model does not match the capture's FairPlay build")
		}
		material, err = ResolveLogicalKeyWithModel(sinf, pack)
	}
	if err != nil {
		return "", err
	}
	defer clear(material.LogicalKey[:])
	selectedHash, _ := material.Evidence["model_sha256"].(string)
	for _, model := range models {
		if model.SHA256 == selectedHash {
			return model.Path, nil
		}
	}
	return "", fmt.Errorf("validated enrollment model is missing from diagnostics")
}

func modelMatchesCaptureBuild(modelHash string, capture *EnrollmentCaptureManifest) bool {
	return capture == nil || modelHash == capture.FairPlayd.SHA256 ||
		capture.FairPlay.CompatibilitySHA256 != "" && modelHash == capture.FairPlay.CompatibilitySHA256
}

func DoctorFairPlay(capturePath, ipaPath, modelPath string) FairPlayDoctorReport {
	report := FairPlayDoctorReport{
		Schema: "ipatool-fairplay-doctor-v1", CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Checks: make(map[string]bool),
	}
	var captureManifest *EnrollmentCaptureManifest
	if capturePath == "" {
		if host, err := InspectLocalFairPlayHost(); err == nil {
			report.Host = &host
			report.Checks["supported_fairplayd"] = host.FairPlaySupport.Recovery
			report.Checks["native_state_accessible"] = host.StateAccessible && host.StateFiles != 0
			report.Checks["hardware_iomac"] = host.HardwareMACPresent
		} else if ipaPath == "" && modelPath == "" {
			report.Errors = append(report.Errors, "host: "+err.Error())
		}
	}
	if capturePath != "" {
		capture, err := LoadEnrollmentCapture(capturePath, true)
		if err != nil {
			report.Errors = append(report.Errors, "capture: "+err.Error())
		} else {
			captureManifest = &capture
			report.Capture = &EnrollmentCaptureDiagnostic{
				ProductVersion:  capture.ProductVersion,
				BuildVersion:    capture.BuildVersion,
				FairPlaydSHA256: capture.FairPlayd.SHA256,
				FairPlaySupport: capture.FairPlay,
				SelectorID:      capture.App.SelectorID,
				Files:           len(capture.Files),
				HasIPA:          capture.IPA != nil,
			}
			report.CaptureVerified = true
			report.Checks["capture_integrity"] = true
			report.Checks["supported_fairplayd"] = capture.FairPlay.Recovery
			if capture.FairPlay.CompatibilitySHA256 != "" && modelPath == "" {
				report.Warnings = append(report.Warnings, "this capture requires the checked compatibility evaluator; pass --compat-fairplayd with arm64e SHA-256 "+capture.FairPlay.CompatibilitySHA256+" to fairplay-enroll recover")
			}
			if ipaPath == "" && capture.IPA != nil {
				resolved, resolveErr := captureFilePath(capturePath, capture.IPA.Path)
				if resolveErr != nil {
					report.Errors = append(report.Errors, "capture IPA: "+resolveErr.Error())
				} else {
					ipaPath = resolved
				}
			}
		}
	}
	if ipaPath != "" {
		sinfs, err := inspectIPASINFs(ipaPath)
		if err != nil {
			report.Errors = append(report.Errors, "ipa: "+err.Error())
		} else {
			report.SINF = sinfs
			report.Checks["ipa_sinf"] = true
			current := true
			for _, value := range sinfs {
				current = current && value.CurrentLayout
			}
			report.Checks["current_sinf_layout"] = current
			if !current {
				report.Warnings = append(report.Warnings, "one or more SINF files use an unsupported or legacy layout")
			}
		}
	}
	if captureManifest != nil || len(report.SINF) != 0 {
		report.Warnings = append(report.Warnings, "SINF geometry cannot prove account age; current support assumes a newly created, natively enrolled Apple Account")
	}
	if modelPath != "" {
		models, err := inspectModelPath(modelPath)
		if err != nil {
			report.Errors = append(report.Errors, "model: "+err.Error())
		} else {
			report.Models = models
			report.Checks["model_valid"] = true
		}
	}
	if len(report.SINF) != 0 && len(report.Models) != 0 {
		if len(report.SINF) != 1 {
			report.Errors = append(report.Errors, "decryption requires exactly one SINF")
		} else {
			for _, model := range report.Models {
				if modelMatchesCaptureBuild(model.FairPlaydHash, captureManifest) &&
					(model.SelectorID == report.SINF[0].SelectorID || model.SelectorID == "" && len(report.Models) == 1) {
					report.Checks["selector_match"] = true
				}
			}
		}
		if !report.Checks["selector_match"] {
			report.Errors = append(report.Errors, "no enrollment model matches the IPA SINF selector")
		} else {
			selected, err := validatedModelForSINF(ipaPath, report.SINF[0].Path,
				modelPath, report.Models, captureManifest)
			if err != nil {
				report.Errors = append(report.Errors, "model validation: "+err.Error())
			} else {
				report.CompatibleModel = selected
				report.Checks["sinf_model_validation"] = true
			}
		}
	}
	if captureManifest != nil && len(report.SINF) != 0 {
		matched := false
		for _, value := range report.SINF {
			matched = matched || value.Selector == captureManifest.App.Selector
		}
		report.Checks["capture_selector_match"] = matched
		if !matched {
			report.Errors = append(report.Errors, "capture selector does not match the IPA")
		}
	}
	if captureManifest == nil {
		if report.Host != nil && !report.Host.StateAccessible {
			report.NextActions = append(report.NextActions, "rerun collection with permission to read /private/var/db/fpsd")
		}
		report.NextActions = append(report.NextActions, "collect native enrollment with fairplay-enroll collect")
	} else if !captureManifest.FairPlay.Recovery {
		report.NextActions = append(report.NextActions, "add and validate an exact evaluator for this fairplayd hash")
	} else if modelPath == "" {
		if captureManifest.FairPlay.CompatibilitySHA256 != "" {
			report.NextActions = append(report.NextActions, "recover fairplay-enrollment.bin with fairplay-enroll recover --compat-fairplayd /private/path/fairplayd.arm64e")
		} else {
			report.NextActions = append(report.NextActions, "recover fairplay-enrollment.bin with fairplay-enroll recover")
		}
	}
	if modelPath != "" && report.CompatibleModel != "" {
		report.NextActions = append(report.NextActions, "run fairplay-decrypt with the compatible model")
	}
	if len(report.SINF) != 0 || captureManifest != nil || modelPath != "" {
		report.Ready = len(report.Errors) == 0 && report.Checks["current_sinf_layout"] &&
			(captureManifest == nil || report.Checks["capture_integrity"] && report.Checks["supported_fairplayd"] && report.Checks["capture_selector_match"]) &&
			(modelPath == "" || report.Checks["sinf_model_validation"])
	} else if report.Host != nil {
		report.Ready = report.Checks["supported_fairplayd"] && report.Checks["native_state_accessible"] && report.Checks["hardware_iomac"]
	}
	report.DecryptReady = modelPath != "" && report.Ready && report.CompatibleModel != ""
	return report
}

func WriteDoctorReport(path string, report FairPlayDoctorReport) error {
	if path == "" {
		return nil
	}
	return writePrivateJSON(path, report)
}

func MarshalDoctorReport(report FairPlayDoctorReport) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}
