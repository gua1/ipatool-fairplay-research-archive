package fairplay

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

type KeyMaterial struct {
	LogicalKey [16]byte
	Evidence   map[string]any
}

func digest(blob []byte) string {
	value := sha256.Sum256(blob)
	return hex.EncodeToString(value[:])
}

func ResolveLogicalKey(sinf []byte) (KeyMaterial, error) {
	selector, err := ParseSINFSelector(sinf)
	if err != nil {
		return KeyMaterial{}, err
	}
	fields, err := parseSINFFields(sinf)
	if err != nil {
		return KeyMaterial{}, err
	}
	private, err := sinfPrivatePayload(sinf, fields)
	if err != nil {
		return KeyMaterial{}, err
	}
	return KeyMaterial{}, fmt.Errorf(
		"FairPlay profile %s (sinf_sha256=%s priv_bytes=%d priv_sha256=%s) requires a private enrollment model; pass --model FILE or --model DIRECTORY",
		selector.Identifier(), digest(sinf), len(private), digest(private),
	)
}

// ResolveLogicalKeyWithModel resolves a SINF with an experimental external
// model. Model packs are intentionally data, not Go code, so research models
// can be tested without changing the portable decryption path.
func ResolveLogicalKeyWithModel(sinf, pack []byte) (KeyMaterial, error) {
	model, err := parseCurrentSINFModel(pack)
	if err != nil {
		return KeyMaterial{}, err
	}
	modelSHA256 := digest(pack)
	modelName := "external-current-sinf-" + modelSHA256[:16]
	supportedSelector := ""
	if model.hasSelector {
		supportedSelector = model.selector.Identifier()
	}
	return resolveLogicalKey(sinf, model, modelName, modelSHA256, "external-enrollment-model", "recovered enrollment model", supportedSelector)
}

// ResolveLogicalKeyWithModels selects one selector-bound model from a
// registry. Version-1 packs remain supported as an explicit --model file, but
// are intentionally rejected in registries because they carry no selector.
func ResolveLogicalKeyWithModels(sinf []byte, packs [][]byte) (KeyMaterial, error) {
	selector, err := ParseSINFSelector(sinf)
	if err != nil {
		return KeyMaterial{}, err
	}
	var selected []byte
	for index, pack := range packs {
		model, parseErr := parseCurrentSINFModel(pack)
		if parseErr != nil {
			return KeyMaterial{}, fmt.Errorf("parse FairPlay model %d: %w", index, parseErr)
		}
		if !model.hasSelector {
			return KeyMaterial{}, fmt.Errorf("FairPlay model %d is version 1 and cannot be used in a registry", index)
		}
		if model.selector != selector {
			continue
		}
		if selected != nil {
			return KeyMaterial{}, fmt.Errorf("FairPlay model registry has multiple models for selector %s", selector.Identifier())
		}
		selected = pack
	}
	if selected == nil {
		return KeyMaterial{}, fmt.Errorf("FairPlay model registry has no model for selector %s", selector.Identifier())
	}
	return ResolveLogicalKeyWithModel(sinf, selected)
}

func resolveLogicalKey(sinf []byte, model currentSINFModel, modelName, modelSHA256, stateOrigin, supportedProfile, supportedSelector string) (KeyMaterial, error) {
	var result KeyMaterial
	fields, err := parseSINFFields(sinf)
	if err != nil {
		return result, err
	}
	selector, err := sinfSelector(sinf, fields)
	if err != nil {
		return result, err
	}
	private, err := sinfPrivatePayload(sinf, fields)
	if err != nil {
		return result, err
	}
	profile := fmt.Sprintf(
		"%s (sinf_sha256=%s priv_bytes=%d priv_sha256=%s)",
		selector.Identifier(), digest(sinf), len(private), digest(private),
	)
	if supportedSelector != "" && selector.Identifier() != supportedSelector {
		return result, fmt.Errorf(
			"unsupported FairPlay profile %s; the selected model supports selector %s from %s",
			profile, supportedSelector, supportedProfile,
		)
	}
	innerKey, err := currentSINFPrivateKey(model, sinf, fields)
	if err != nil {
		if supportedProfile != "" {
			return result, fmt.Errorf("unsupported FairPlay profile %s; the selected model is validated only for %s: %w", profile, supportedProfile, err)
		}
		return result, fmt.Errorf("FairPlay profile %s does not match the selected experimental model: %w", profile, err)
	}
	defer clear(innerKey[:])
	logical := logicalFromInnerKey(innerKey)
	result.LogicalKey = logical
	providerKind := "current-sinf-whitebox-direct-v1"
	if model.version == 3 {
		providerKind = "current-sinf-whitebox-direct-v3"
	}
	result.Evidence = map[string]any{
		"provider_kind":          providerKind,
		"provider_status":        0,
		"selector_status":        0,
		"status_patched":         false,
		"device_state_imported":  false,
		"state_origin":           stateOrigin,
		"hardware_backend":       "none",
		"runtime_hardware_calls": 0,
		"request_selector":       selector.Identifier(),
		"model_name":             modelName,
		"model_sha256":           modelSHA256,
		"model_version":          model.version,
		"fairplayd_sha256":       hex.EncodeToString(model.fairplaydHash[:]),
		"logical_key_sha256":     digest(logical[:]),
	}
	return result, nil
}
