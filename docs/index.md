# Documentation Index

This repository treats in-repo docs as the system of record.
`AGENTS.md` is intentionally short and acts as a table of contents into this directory.

## Start Here

1. `README.md`: setup, operations, launchd workflow, cleanup entry points.
2. `docs/index.md` (this file): navigation map for repository knowledge.
3. Domain docs listed below based on task scope.

## Knowledge Map

```text
docs/
├── index.md
├── architecture.md
├── control-plane.md
├── troubleshooting.md
├── cleanup.md
├── security.md
└── exec-plans/
    ├── README.md
    ├── active/
    ├── completed/
    └── tech-debt-tracker.md
```

## Domain References

- Runtime architecture: `docs/architecture.md`
- Control-plane behavior and command surface: `docs/control-plane.md`
- Failure recovery and diagnosis: `docs/troubleshooting.md`
- Host cleanup and uninstall flow: `docs/cleanup.md`
- Security model and boundaries: `docs/security.md`
- Active/completed execution plans and debt register: `docs/exec-plans/`

## Operating Rules

- Keep docs close to code and update them in the same PR as behavior changes.
- Favor small, linked docs over monolithic instruction files.
- Preserve progressive disclosure: top-level map first, deep details on demand.
- Track work plans and debt in `docs/exec-plans/` so agents can reason from repository state.
