# Remediation reports and custom baselines

kube-bench can attach operator-facing guidance to every check:

- `remediation` and optional `remediation_steps`: what to change
- `impact`: the blast radius and expected service interruption
- `rollback`: a command or procedure to restore the previous state

The guidance is available in JSON and in a standalone HTML report. It is
descriptive only; kube-bench never applies remediation or rollback commands.

## Output formats

Generate JSON:

```sh
kube-bench run --targets master --version 1.32 \
  --json --outputfile kube-bench-report.json
```

Generate HTML:

```sh
kube-bench run --targets master --version 1.32 \
  --html --outputfile kube-bench-report.html
```

The HTML file is self-contained and can be attached to a ticket or served by an
internal report portal. Failed and warning checks include the remediation
steps, impact, rollback command, and captured audit evidence.

Each check in the JSON output includes the new fields when they are present:

```json
{
  "test_number": "1.2.1",
  "test_desc": "Ensure that the --anonymous-auth argument is set to false",
  "status": "FAIL",
  "remediation": "Disable anonymous authentication on the API server.",
  "remediation_steps": [
    "Back up the API server manifest",
    "Set --anonymous-auth=false",
    "Wait for the static pod to restart"
  ],
  "impact": "The API server restarts and callers may see a short outage.",
  "rollback": "cp -a /var/backups/kube-bench/kube-apiserver.yaml.bak /etc/kubernetes/manifests/kube-apiserver.yaml"
}
```

Fields are omitted from JSON when they are not defined, preserving the existing
JSON shape for benchmarks that have not adopted the new metadata.

## Adding guidance to a controls file

Add the fields directly to a check:

```yaml
- id: 1.2.1
  text: "Ensure that the --anonymous-auth argument is set to false (Manual)"
  remediation: |
    Disable anonymous authentication on the API server.
  remediation_steps:
    - "Back up the API server manifest"
    - "Set --anonymous-auth=false in the manifest"
    - "Wait for the API server static pod to restart"
  impact: |
    The API server restarts. Expect a short control-plane API interruption.
  rollback: |
    cp -a /var/backups/kube-bench/kube-apiserver.yaml.bak \
      /etc/kubernetes/manifests/kube-apiserver.yaml
```

The aliases `impact_scope` and `rollback_command` are also accepted and are
normalized to `impact` and `rollback` in reports.

## Custom remediation baseline

An overlay lets a platform team keep organization-specific guidance in one
file without forking the complete CIS controls. Pass it with `--baseline`:

```sh
kube-bench run --targets master,node --version 1.32 \
  --baseline cfg/baselines/production-remediation.yaml \
  --html --outputfile report.html
```

The overlay format is:

```yaml
apiVersion: kube-bench/v1
kind: RemediationBaseline
metadata:
  name: production-remediation
  description: Production guidance for CIS checks
spec:
  checks:
    "1.2.1":
      remediation: |
        Disable anonymous authentication.
      impact: |
        A brief API server restart is expected.
      rollback: |
        cp -a /var/backups/kube-apiserver.yaml.bak \
          /etc/kubernetes/manifests/kube-apiserver.yaml
  versions:
    - name: kubernetes-1.30-plus
      constraint: ">=1.30"
      checks:
        "1.2.1":
          remediation: |
            Kubernetes 1.30+ guidance, including Structured Authentication.
```

`spec.checks` is applied first. Matching blocks in `spec.versions` are then
applied in file order. Only non-empty fields overwrite the existing check
metadata, so an overlay can change just `impact` or just `rollback`.

### Version constraints

The detected Kubernetes version comes from the same detection path used to
select the benchmark. Constraints support:

- exact minor versions: `1.30`, `v1.30`
- exact patch versions: `1.30.4`
- wildcards: `1.30.x`
- comparisons: `>=1.30`, `>1.30.1`, `<1.32`, `<=1.32.3`
- multiple constraints with AND: `>=1.30 <1.32`
- alternatives with OR: `1.29 || >=1.32`

When `--benchmark` is used and no Kubernetes version is detected, version
overlays are skipped and only `spec.checks` is applied.

The repository includes ten complete examples in
`cfg/baselines/production-remediation.yaml`, plus a `>=1.30` override to show
version-specific guidance.

## Complete custom benchmarks

Use `--baseline` for remediation metadata. To replace the check set itself,
provide a complete benchmark directory and point kube-bench at it:

```sh
kube-bench run \
  --config-dir ./my-cfg \
  --config ./my-cfg/config.yaml \
  --benchmark my-cis-1.0 \
  --targets master,node
```

The directory must contain `my-cis-1.0/master.yaml`, `node.yaml`, and any other
targets, plus the `version_mapping` and `target_mapping` entries in
`my-cfg/config.yaml`. This is the existing kube-bench mechanism for custom
benchmarks; the overlay mechanism above complements it.
