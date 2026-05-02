# Contributing

Thanks for contributing to `terraform-provider-thoth`.

## Ground Rules

- Keep provider code as an API integration layer.
- Do not add proprietary policy decision logic to this repository.
- Do not commit secrets, customer data, or private infrastructure details.
- Keep examples production-safe and tenant-generic.

## Pull Request Requirements

- Include tests for behavior changes.
- Update docs/examples for schema or workflow changes.
- Keep backward compatibility unless a breaking change is explicitly approved.
- Use clear commit messages with Terraform/provider scope.

## Sensitive Content Restrictions

Do not submit:

- internal runbooks or non-public incident details;
- private model prompts, scoring logic, or tuning data;
- copied code that you are not authorized to contribute.
