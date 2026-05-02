# Security Policy (Provider Scope)

## Scope

This file covers security reporting for `platform/public/terraform-provider-thoth`.

The Terraform provider is a control-plane API client. Most security-critical
enforcement behavior runs in Aten Security backend services.

## Report a Vulnerability

Do not open public GitHub issues for undisclosed vulnerabilities.

Report security issues privately to Aten Security security contacts through the
organization's coordinated disclosure channel.

Include:

- affected provider version;
- Terraform config snippet to reproduce;
- expected vs actual behavior;
- impact assessment and exploit prerequisites.

## Response Priorities

1. Credential/token exposure or misuse.
2. Privilege escalation via provider actions.
3. Incorrect resource behavior causing unsafe policy state.
4. Documentation/examples that lead to insecure deployment defaults.
