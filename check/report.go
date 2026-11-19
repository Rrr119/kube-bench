package check

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"
)

type htmlReportData struct {
	Controls []*Controls
	Totals   Summary
}

// HTML encodes one controls result set as a standalone HTML report.
func (controls *Controls) HTML() ([]byte, error) {
	return HTML([]*Controls{controls})
}

// HTML encodes controls result sets as a standalone HTML report.
func HTML(controlsCollection []*Controls) ([]byte, error) {
	data := htmlReportData{
		Controls: controlsCollection,
		Totals:   summaryTotals(controlsCollection),
	}

	var out bytes.Buffer
	if err := htmlReportTemplate.Execute(&out, data); err != nil {
		return nil, fmt.Errorf("failed to render HTML report: %w", err)
	}
	return out.Bytes(), nil
}

func summaryTotals(controlsCollection []*Controls) Summary {
	var totals Summary
	for _, controls := range controlsCollection {
		if controls == nil {
			continue
		}
		totals.Pass += controls.Pass
		totals.Fail += controls.Fail
		totals.Warn += controls.Warn
		totals.Info += controls.Info
	}
	return totals
}

func statusClass(state State) string {
	return strings.ToLower(string(state))
}

var htmlReportTemplate = template.Must(template.New("kube-bench-report").Funcs(template.FuncMap{
	"statusClass": statusClass,
}).Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>kube-bench security baseline report</title>
<style>
:root {
  color-scheme: light;
  --bg: #f4f6f8;
  --panel: #ffffff;
  --text: #18212b;
  --muted: #5f6b76;
  --line: #d8dee5;
  --pass: #1f7a4d;
  --pass-bg: #e9f7ef;
  --fail: #b42318;
  --fail-bg: #fdecea;
  --warn: #9a6700;
  --warn-bg: #fff6dd;
  --info: #1d4f91;
  --info-bg: #eaf2ff;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font: 14px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
main { max-width: 1180px; margin: 0 auto; padding: 32px 20px 56px; }
h1 { margin: 0 0 6px; font-size: 27px; }
h2 { margin: 34px 0 12px; font-size: 20px; }
h3 { margin: 0; font-size: 16px; }
.subtitle { color: var(--muted); margin: 0 0 24px; }
.summary {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 12px;
  margin: 20px 0 28px;
}
.metric {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 9px;
  padding: 14px 16px;
}
.metric span { display: block; color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
.metric strong { display: block; font-size: 28px; line-height: 1.25; }
.controls-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 8px 18px;
  margin: 8px 0 14px;
  color: var(--muted);
  font-size: 13px;
}
.group { margin: 20px 0; }
.group-head { display: flex; align-items: baseline; gap: 10px; margin-bottom: 8px; }
.group-head p { margin: 0; color: var(--muted); }
.check {
  background: var(--panel);
  border: 1px solid var(--line);
  border-left-width: 5px;
  border-radius: 8px;
  margin: 10px 0;
  padding: 15px 17px;
}
.check.PASS { border-left-color: var(--pass); }
.check.FAIL { border-left-color: var(--fail); }
.check.WARN { border-left-color: var(--warn); }
.check.INFO { border-left-color: var(--info); }
.check-head { display: flex; align-items: flex-start; gap: 12px; }
.check-head h3 { flex: 1; }
.status {
  border-radius: 999px;
  padding: 2px 9px;
  font-size: 12px;
  font-weight: 700;
  letter-spacing: .03em;
}
.status.PASS { color: var(--pass); background: var(--pass-bg); }
.status.FAIL { color: var(--fail); background: var(--fail-bg); }
.status.WARN { color: var(--warn); background: var(--warn-bg); }
.status.INFO { color: var(--info); background: var(--info-bg); }
.fields { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 12px; margin-top: 14px; }
.field { border-top: 1px solid var(--line); padding-top: 10px; min-width: 0; }
.field h4 { margin: 0 0 5px; font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; }
.field pre, .field ol { margin: 0; white-space: pre-wrap; overflow-wrap: anywhere; font: inherit; }
.field ol { padding-left: 20px; }
.field code { font: 12px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.empty { color: var(--muted); font-style: italic; }
.evidence { margin-top: 12px; }
.evidence summary { cursor: pointer; color: var(--muted); }
.evidence pre { background: #f7f8fa; border-radius: 6px; padding: 10px; overflow-wrap: anywhere; white-space: pre-wrap; }
.footer { color: var(--muted); font-size: 12px; margin-top: 34px; }
@media print {
  body { background: #fff; }
  main { max-width: none; padding: 0; }
  .check { break-inside: avoid; }
}
</style>
</head>
<body>
<main>
  <h1>kube-bench security baseline report</h1>
  <p class="subtitle">Actionable findings with remediation, impact, and rollback guidance.</p>

  <section class="summary" aria-label="Summary">
    <div class="metric"><span>Pass</span><strong>{{.Totals.Pass}}</strong></div>
    <div class="metric"><span>Fail</span><strong>{{.Totals.Fail}}</strong></div>
    <div class="metric"><span>Warn</span><strong>{{.Totals.Warn}}</strong></div>
    <div class="metric"><span>Info</span><strong>{{.Totals.Info}}</strong></div>
  </section>

  {{range .Controls}}
  <section>
    <h2>{{.ID}} {{.Text}}</h2>
    <div class="controls-meta">
      <span>Benchmark: {{.Version}}</span>
      <span>Target: {{.Type}}</span>
      {{if .Baseline}}<span>Baseline: {{.Baseline}}</span>{{end}}
      {{if .KubernetesVersion}}<span>Kubernetes: {{.KubernetesVersion}}</span>{{else if .DetectedVersion}}<span>Kubernetes: {{.DetectedVersion}}</span>{{end}}
    </div>

    {{range .Groups}}
    <div class="group">
      <div class="group-head">
        <h3>{{.ID}} {{.Text}}</h3>
        <p>{{.Pass}} pass / {{.Fail}} fail / {{.Warn}} warn / {{.Info}} info</p>
      </div>

      {{range .Checks}}
      <article class="check {{statusClass .State}}">
        <div class="check-head">
          <h3>{{.ID}} {{.Text}}</h3>
          <span class="status {{statusClass .State}}">{{.State}}</span>
        </div>

        <div class="fields">
          <div class="field">
            <h4>Remediation</h4>
            {{if .Remediation}}<pre>{{.Remediation}}</pre>{{else}}<span class="empty">Not specified</span>{{end}}
          </div>

          {{if .RemediationSteps}}
          <div class="field">
            <h4>Remediation steps</h4>
            <ol>{{range .RemediationSteps}}<li>{{.}}</li>{{end}}</ol>
          </div>
          {{end}}

          <div class="field">
            <h4>Impact</h4>
            {{if .Impact}}<pre>{{.Impact}}</pre>{{else}}<span class="empty">Not specified</span>{{end}}
          </div>

          <div class="field">
            <h4>Rollback</h4>
            {{if .Rollback}}<pre><code>{{.Rollback}}</code></pre>{{else}}<span class="empty">Not specified</span>{{end}}
          </div>
        </div>

        {{if or .ActualValue .ExpectedResult .Reason}}
        <details class="evidence">
          <summary>Audit evidence</summary>
          {{if .Reason}}<p><strong>Reason:</strong> {{.Reason}}</p>{{end}}
          {{if .ExpectedResult}}<p><strong>Expected:</strong> {{.ExpectedResult}}</p>{{end}}
          {{if .ActualValue}}<p><strong>Actual:</strong></p><pre>{{.ActualValue}}</pre>{{end}}
        </details>
        {{end}}
      </article>
      {{end}}
    </div>
    {{end}}
  </section>
  {{end}}

  <p class="footer">Generated by kube-bench. Validate rollback commands in a non-production environment before use.</p>
</main>
</body>
</html>
`))
