# S3 Access Policy Test Results

This archived page records the expected test shape without exposing account-specific
identifiers.

## Test Matrix

For each role, validate representative read/write behavior:

| Actor | Bucket Scope | Read | Write |
| --- | --- | --- | --- |
| Current member | own `User` bucket | allowed | allowed |
| Current member | other `User` bucket | allowed | denied |
| Current member | `SharedOps` bucket | allowed | denied |
| Alumni | historical own `User` bucket | allowed | denied |
| Alumni | other `User` bucket | allowed | denied |
| Admin | own `User` bucket | allowed | allowed |
| Admin | `SharedOps` bucket | allowed | allowed |
| Admin | other `User` bucket | allowed | denied by guardrail |
| Any routine user | `ServiceManaged` bucket | limited/read-only if approved | denied |

## Notes

`aws iam simulate-principal-policy` is useful but should not be the only validation for
S3 because resource-based bucket policy denies can be subtle. Use live temporary-user
tests for final confirmation in a non-production-safe test window.
