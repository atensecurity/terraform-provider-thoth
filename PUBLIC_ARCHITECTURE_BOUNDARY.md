# Public Architecture Boundary

`terraform-provider-thoth` is a control-plane integration layer.

This public repository intentionally contains:

- Terraform provider schemas, validation, and CRUD/resource mapping.
- API client behavior for authenticated GovAPI control-plane calls.
- Documentation, examples, and release automation for provider distribution.

This public repository intentionally does **not** contain:

- policy decisioning logic (ALLOW/STEP_UP/BLOCK internals);
- enforcement/risk model internals;
- proprietary pack intelligence, tuning data, or private operational runbooks.

Sensitive implementation and operational controls are maintained in Aten
Security private systems and internal repositories.
