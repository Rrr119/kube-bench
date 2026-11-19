package check

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

const sampleBaselinePath = "../cfg/baselines/production-remediation.yaml"

func TestLoadAndApplyRemediationBaseline(t *testing.T) {
	baseline, err := LoadRemediationBaseline(sampleBaselinePath)
	require.NoError(t, err)
	assert.Equal(t, "production-remediation", baseline.Metadata.Name)
	assert.Len(t, baseline.Spec.Checks, 10)

	controls := controlsForBaselineTest(t)
	baseline.Apply(controls, "v1.32.4")

	assert.Equal(t, "production-remediation", controls.Baseline)
	assert.Equal(t, "1.32.4", controls.KubernetesVersion)

	apiServerFile := controls.Groups[0].Checks[0]
	assert.Contains(t, apiServerFile.Remediation, "mode 600")
	assert.Contains(t, apiServerFile.Impact, "No API outage")
	assert.Contains(t, apiServerFile.Rollback, "OLD_MODE")
	assert.Len(t, apiServerFile.RemediationSteps, 4)

	anonymousAuth := controls.Groups[0].Checks[1]
	assert.Contains(t, anonymousAuth.Remediation, "Structured AuthenticationConfiguration")
	assert.Contains(t, anonymousAuth.Rollback, "kube-apiserver.yaml.bak")
}

func TestRemediationBaselineVersionOverlayDoesNotMatchOlderKubernetes(t *testing.T) {
	baseline, err := LoadRemediationBaseline(sampleBaselinePath)
	require.NoError(t, err)

	controls := controlsForBaselineTest(t)
	baseline.Apply(controls, "1.29.9")

	anonymousAuth := controls.Groups[0].Checks[1]
	assert.NotContains(t, anonymousAuth.Remediation, "Structured AuthenticationConfiguration")
	assert.Contains(t, anonymousAuth.Remediation, "Disable anonymous authentication")
}

func TestRemediationBaselineRejectsInvalidConstraint(t *testing.T) {
	data := []byte(`
apiVersion: kube-bench/v1
kind: RemediationBaseline
metadata:
  name: invalid
spec:
  versions:
    - constraint: ">=not-a-version"
      checks: {}
`)
	path := filepath.Join(t.TempDir(), "baseline.yaml")
	require.NoError(t, os.WriteFile(path, data, 0600))

	_, err := LoadRemediationBaseline(path)
	assert.Error(t, err)
}

func TestVersionConstraintMatching(t *testing.T) {
	testCases := []struct {
		name       string
		version    string
		constraint string
		want       bool
	}{
		{name: "greater or equal", version: "1.32.4", constraint: ">=1.30", want: true},
		{name: "older", version: "1.29.9", constraint: ">=1.30", want: false},
		{name: "minor exact", version: "1.32.4", constraint: "1.32", want: true},
		{name: "patch exact", version: "1.32.4", constraint: "1.32.0", want: false},
		{name: "patch exact match", version: "1.32.0", constraint: "1.32.0", want: true},
		{name: "range", version: "1.30.0", constraint: ">=1.30 <1.32", want: true},
		{name: "range excluded", version: "1.32.0", constraint: ">=1.30 <1.32", want: false},
		{name: "wildcard or exact", version: "1.35.1", constraint: "1.34.x || 1.35", want: true},
		{name: "v prefix", version: "v1.33.2", constraint: ">=1.30", want: true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			version, ok := parseKubeVersion(tc.version)
			require.True(t, ok)
			got, err := matchVersionConstraint(version, tc.constraint)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestCheckYAMLSupportsLongFieldAliases(t *testing.T) {
	in := []byte(`
id: "1.2.3"
impact_scope: "brief restart"
rollback_command: "restore backup"
`)
	var check Check
	require.NoError(t, yaml.Unmarshal(in, &check))
	assert.Equal(t, "brief restart", check.Impact)
	assert.Equal(t, "restore backup", check.Rollback)
}

func controlsForBaselineTest(t *testing.T) *Controls {
	t.Helper()
	in := []byte(`
type: "master"
groups:
- id: "1.1"
  text: "Configuration files"
  checks:
  - id: "1.1.1"
    text: "API server file permissions"
    remediation: "legacy remediation"
  - id: "1.2.1"
    text: "Anonymous authentication"
    remediation: "Disable anonymous authentication."
`)
	controls, err := NewControls(MASTER, in, "")
	require.NoError(t, err)
	return controls
}
