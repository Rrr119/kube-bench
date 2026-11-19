package check

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestControls_HTMLIncludesOperatorGuidance(t *testing.T) {
	controls := &Controls{
		ID:       "1",
		Version:  "cis-test",
		Text:     "Control Plane",
		Type:     MASTER,
		Baseline: "production",
		Summary:  Summary{Pass: 1, Fail: 1},
		Groups: []*Group{
			{
				ID:   "1.1",
				Text: "API Server",
				Checks: []*Check{
					{
						ID:               "1.1.1",
						Text:             "Restrict <script>alert(1)</script>",
						State:            FAIL,
						Remediation:      "chmod 600 /etc/kubernetes/manifests/kube-apiserver.yaml",
						RemediationSteps: []string{"Back up the manifest", "Apply mode 600"},
						Impact:           "API server restarts briefly",
						Rollback:         "cp -a /var/backups/kube-apiserver.yaml.bak /etc/kubernetes/manifests/kube-apiserver.yaml",
						ActualValue:      "permissions=644",
					},
				},
			},
		},
	}

	out, err := controls.HTML()
	require.NoError(t, err)

	html := string(out)
	assert.Contains(t, html, "<!doctype html>")
	assert.Contains(t, html, "production")
	assert.Contains(t, html, "Remediation steps")
	assert.Contains(t, html, "API server restarts briefly")
	assert.Contains(t, html, "cp -a /var/backups")
	assert.Contains(t, html, "permissions=644")
	assert.NotContains(t, html, "<script>alert(1)</script>")
	assert.Contains(t, html, "&lt;script&gt;alert(1)&lt;/script&gt;")
}

func TestCheckJSONIncludesRiskAndRollback(t *testing.T) {
	item := Check{
		ID:               "1.1.1",
		Remediation:      "chmod 600 manifest",
		RemediationSteps: []string{"backup", "chmod"},
		Impact:           "brief restart",
		Rollback:         "restore backup",
	}

	data, err := json.Marshal(item)
	require.NoError(t, err)

	var fields map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &fields))
	assert.Equal(t, "brief restart", fields["impact"])
	assert.Equal(t, "restore backup", fields["rollback"])
	assert.Len(t, fields["remediation_steps"], 2)

	data, err = json.Marshal(Check{ID: "1.1.2"})
	require.NoError(t, err)
	fields = nil
	require.NoError(t, json.Unmarshal(data, &fields))
	assert.NotContains(t, fields, "impact")
	assert.NotContains(t, fields, "rollback")
}
