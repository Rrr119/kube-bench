package check

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v2"
)

// RemediationBaseline is an optional overlay applied after a controls file is
// loaded. It lets operators provide organization-specific remediation guidance
// without forking the complete CIS benchmark.
type RemediationBaseline struct {
	APIVersion string           `yaml:"apiVersion"`
	Kind       string           `yaml:"kind"`
	Metadata   BaselineMetadata `yaml:"metadata"`
	Spec       BaselineSpec     `yaml:"spec"`
}

// BaselineMetadata identifies a remediation baseline.
type BaselineMetadata struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description,omitempty"`
}

// BaselineSpec contains check metadata and Kubernetes-version-specific
// overrides. Version overlays are applied in file order after the defaults.
type BaselineSpec struct {
	Checks   map[string]RemediationOverride `yaml:"checks"`
	Versions []VersionOverlay               `yaml:"versions"`
}

// VersionOverlay applies check overrides when the detected Kubernetes version
// matches Constraint.
type VersionOverlay struct {
	Name       string                         `yaml:"name,omitempty"`
	Constraint string                         `yaml:"constraint"`
	Checks     map[string]RemediationOverride `yaml:"checks"`
}

// RemediationOverride describes the operator-facing fields that can be
// customized for a check. Empty fields do not overwrite the loaded controls.
type RemediationOverride struct {
	Remediation      string   `yaml:"remediation,omitempty"`
	RemediationSteps []string `yaml:"remediation_steps,omitempty"`
	Impact           string   `yaml:"impact,omitempty"`
	Rollback         string   `yaml:"rollback,omitempty"`
	ImpactScope      string   `yaml:"impact_scope,omitempty"`
	RollbackCommand  string   `yaml:"rollback_command,omitempty"`
}

// LoadRemediationBaseline reads and validates a remediation baseline overlay.
func LoadRemediationBaseline(path string) (*RemediationBaseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read remediation baseline %s: %w", path, err)
	}

	var baseline RemediationBaseline
	if err := yaml.Unmarshal(data, &baseline); err != nil {
		return nil, fmt.Errorf("failed to parse remediation baseline %s: %w", path, err)
	}
	if baseline.Metadata.Name == "" {
		baseline.Metadata.Name = path
	}

	for i := range baseline.Spec.Versions {
		overlay := &baseline.Spec.Versions[i]
		if _, err := parseVersionConstraint(overlay.Constraint); err != nil {
			return nil, fmt.Errorf("invalid version constraint %q in baseline %s: %w", overlay.Constraint, path, err)
		}
	}

	return &baseline, nil
}

// Apply merges the baseline into controls. Only non-empty fields overwrite
// existing values, and version overlays are applied in their declared order.
func (b *RemediationBaseline) Apply(controls *Controls, kubernetesVersion string) {
	if b == nil || controls == nil {
		return
	}

	controls.Baseline = b.Metadata.Name
	applyOverrides(controls, b.Spec.Checks)

	version, hasVersion := parseKubeVersion(kubernetesVersion)
	if !hasVersion {
		return
	}
	controls.KubernetesVersion = version.String()

	for i := range b.Spec.Versions {
		overlay := &b.Spec.Versions[i]
		matches, err := matchVersionConstraint(version, overlay.Constraint)
		if err == nil && matches {
			applyOverrides(controls, overlay.Checks)
		}
	}
}

func applyOverrides(controls *Controls, overrides map[string]RemediationOverride) {
	if len(overrides) == 0 {
		return
	}

	for _, group := range controls.Groups {
		for _, item := range group.Checks {
			override, ok := overrides[item.ID]
			if !ok {
				continue
			}
			if override.Remediation != "" {
				item.Remediation = override.Remediation
			}
			if len(override.RemediationSteps) > 0 {
				item.RemediationSteps = append([]string(nil), override.RemediationSteps...)
			}
			impact := override.Impact
			if impact == "" {
				impact = override.ImpactScope
			}
			if impact != "" {
				item.Impact = impact
			}
			rollback := override.Rollback
			if rollback == "" {
				rollback = override.RollbackCommand
			}
			if rollback != "" {
				item.Rollback = rollback
			}
		}
	}
}

type kubeVersion struct {
	Major    int
	Minor    int
	Patch    int
	HasPatch bool
}

func (v kubeVersion) String() string {
	if v.HasPatch {
		return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	}
	return fmt.Sprintf("%d.%d", v.Major, v.Minor)
}

func parseKubeVersion(value string) (kubeVersion, bool) {
	value = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(value), "v"))
	if value == "" || value == "none" {
		return kubeVersion{}, false
	}
	if idx := strings.IndexAny(value, "+-"); idx >= 0 {
		value = value[:idx]
	}
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return kubeVersion{}, false
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return kubeVersion{}, false
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return kubeVersion{}, false
	}

	version := kubeVersion{Major: major, Minor: minor}
	if len(parts) >= 3 && parts[2] != "" {
		patch, err := strconv.Atoi(parts[2])
		if err != nil {
			return kubeVersion{}, false
		}
		version.Patch = patch
		version.HasPatch = true
	}
	return version, true
}

type versionConstraint struct {
	Op        string
	Version   kubeVersion
	MinorOnly bool
}

func parseVersionConstraint(value string) ([][]versionConstraint, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}

	var alternatives [][]versionConstraint
	for _, alternative := range strings.Split(value, "||") {
		alternative = strings.TrimSpace(alternative)
		if alternative == "" {
			return nil, fmt.Errorf("empty alternative")
		}

		tokens := strings.Fields(strings.ReplaceAll(alternative, ",", " "))
		if len(tokens) == 0 {
			return nil, fmt.Errorf("empty constraint")
		}

		constraints := make([]versionConstraint, 0, len(tokens))
		for _, token := range tokens {
			op := "="
			for _, candidate := range []string{">=", "<=", "==", ">", "<", "="} {
				if strings.HasPrefix(token, candidate) {
					op = candidate
					token = strings.TrimSpace(strings.TrimPrefix(token, candidate))
					break
				}
			}
			if token == "" {
				return nil, fmt.Errorf("missing version")
			}

			minorOnly := false
			lower := strings.ToLower(token)
			if strings.HasSuffix(lower, ".x") {
				minorOnly = true
				token = token[:len(token)-2]
			}

			version, ok := parseKubeVersion(token)
			if !ok {
				return nil, fmt.Errorf("invalid version %q", token)
			}
			if op == "==" {
				op = "="
			}
			constraints = append(constraints, versionConstraint{
				Op:        op,
				Version:   version,
				MinorOnly: minorOnly || !version.HasPatch,
			})
		}
		alternatives = append(alternatives, constraints)
	}
	return alternatives, nil
}

func matchVersionConstraint(version kubeVersion, value string) (bool, error) {
	alternatives, err := parseVersionConstraint(value)
	if err != nil {
		return false, err
	}
	if len(alternatives) == 0 {
		return true, nil
	}

	for _, constraints := range alternatives {
		matches := true
		for _, constraint := range constraints {
			if !constraint.match(version) {
				matches = false
				break
			}
		}
		if matches {
			return true, nil
		}
	}
	return false, nil
}

func (c versionConstraint) match(version kubeVersion) bool {
	comparison := compareVersions(version, c.Version, c.MinorOnly)
	switch c.Op {
	case "=":
		return comparison == 0
	case ">":
		return comparison > 0
	case ">=":
		return comparison >= 0
	case "<":
		return comparison < 0
	case "<=":
		return comparison <= 0
	default:
		return false
	}
}

func compareVersions(left, right kubeVersion, minorOnly bool) int {
	if left.Major != right.Major {
		if left.Major < right.Major {
			return -1
		}
		return 1
	}
	if left.Minor != right.Minor {
		if left.Minor < right.Minor {
			return -1
		}
		return 1
	}
	if minorOnly || !right.HasPatch {
		return 0
	}
	if left.Patch < right.Patch {
		return -1
	}
	if left.Patch > right.Patch {
		return 1
	}
	return 0
}
