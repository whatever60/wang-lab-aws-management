# Refactor + Docs TODO

This file records the repo cleanup plan so the work can resume safely if active
context is lost.

## User Decisions

- Refactor scope is the whole repo, not only HPC.
- No backward compatibility is required for old root-level Python script commands.
- Expose one unified command: `aws-audit`.
- Python package name: `aws_audit`.
- Generated operational outputs should not be committed by default.
- Sensitive values should be scrubbed from docs and committed config.
- Docs audience includes lab users, admins, and developers.
- Docs should include conceptual explanation plus commands.
- Superseded docs should be retained in an archive/reference section.
- Use Material for MkDocs if it supports a dark theme.
- Ignore built docs output.
- AWS-touching validation should remain manual/opt-in; default tests stay offline.

## Target Layout

```text
src/aws_audit/
  __init__.py
  cli.py
  audit/
  cost/
  hpc/
  inventory/
  s3_access/
  tools/
config/
docs/
examples/
scripts/
tests/
```

## Code Plan

1. Move large root scripts into package modules.
2. Add `aws-audit` console script in `pyproject.toml`.
3. Implement a top-level CLI that dispatches to subcommands:
   - `aws-audit hpc ...`
   - `aws-audit inventory ...`
   - `aws-audit monthly-costs ...`
   - `aws-audit audit-setup ...`
   - `aws-audit s3-access ...`
4. Keep module internals mostly intact in this pass, but move code out of root.
5. Update tests to import package modules.
6. Add tests for unified CLI parsing/dispatch where useful.

## Config + Generated Files Plan

1. Keep source manifests/templates committed.
2. Remove generated operational outputs from git:
   - generated ParallelCluster YAML
   - generated active instance allowlist
   - current live catalog snapshots
3. Add generated config/catalog paths to `.gitignore`.
4. Scrub committed config values that are account/site-specific or sensitive:
   - account IDs
   - ARNs
   - subnet IDs
   - SSH key names
   - IP allowlists
   - bucket names
5. Prefer placeholders in committed config, with local override support if needed.

## Docs Plan

1. Add `mkdocs.yml` with Material theme and dark mode.
2. Organize docs into sections:
   - Overview
   - User guides
   - Admin runbooks
   - Developer notes
   - Reference/archive
3. Keep old PCS doc in archive/reference.
4. Make README shorter and point to the docs site.
5. Ensure docs do not expose sensitive account/site details.
6. Ignore `site/`.

## Validation Plan

1. Run offline unit tests.
2. Run `aws-audit --help` and selected subcommand help checks.
3. Run MkDocs build locally.
4. Do not run AWS dry-run/create/delete unless explicitly requested during this refactor.

## Commit Plan

Use staged commits:

1. Package layout and unified CLI.
2. Config/generated-output cleanup and secret scrubbing.
3. MkDocs documentation assembly.
4. Tests and final polish if needed.
