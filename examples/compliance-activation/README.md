# Tenant compliance assessment

`main.tf` configures an existing tenant's executable declarations in observe mode.
Supply the tenant ID and credentials through your normal provider configuration.
This repository change does not activate a tenant or deploy a service.

The first plan displays:

| Declared regime | Executable controls | Evidence gaps | Not action time |
| --- | ---: | ---: | ---: |
| FedRAMP | 4 | 1 | 4 |
| CMMC L1 | 3 | 2 | 1 |
| ISO 27001 | 0 | 0 | 0 |

ISO 27001 also appears in `regimes_without_controls`. It contributes a structural
coverage gap, never a per-action restriction. These counts describe author-classified
rules and do not establish regulatory conformance.

Observe evaluates and records findings while preserving the independent authorization
outcome. Review those findings before changing `compliance_enforcement_mode` to
`enforce`. In enforce mode, actionable DENY, STEP_UP and evidence-based UNRESOLVED
add non-grantable restrictions for every current and future tenant agent within 1000 ms.
Structural zero-control gaps remain visible and do not block traffic.

`observe-plan.txt` and `enforce-plan.txt` are actual Terraform output from the local
fixture. Only the temporary directory name was normalized. Regenerate them without
contacting a real tenant:

```shell
python3 examples/compliance-activation/verify_local_plan.py
```

Run from the provider directory. The script builds the local provider, uses temporary
Terraform state and a loopback HTTP fixture, verifies first-plan counts, applies observe,
checks stable refresh, captures and applies the enforce diff, and verifies revision-guarded
destroy. The mode-only diff retains unchanged tenant, routing, and coverage values;
only mode, revision, and the update timestamp change. The fixture also checks routing
updates through typed fields and `extra_settings_json`.

Computed routing values remain unknown during updates when routing inputs change or
when `extra_settings_json` manages that section: replaying even unchanged JSON can
reassert values after remote drift. The broker provider follows the same rule.
Nothing is deployed. Requires local Go and Terraform executables.

Removal of the managed declaration (or `[]` plus removal of mode) clears it using its
prior revision. Destroy clears only managed compliance fields. Existing legacy pack
settings remain separate and their defaults never activate executable bindings.
