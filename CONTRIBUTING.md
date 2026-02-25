# Contributing

Thanks for contributing to `agent-chat`.

## Project Scope

This repository is macOS-only and focuses on local Codex/Claude runtime behavior across iMessage and Telegram integrations.
Please keep changes scoped to this runtime and its documentation.

## Development Setup

```bash
git clone <your-fork-url>
cd agent-chat
python3 -m compileall .
python3 -m unittest discover -s tests -p 'test_*.py'
```

## Pull Request Guidelines

- Keep PRs focused and small.
- Update docs when behavior or interfaces change.
- Add or update tests for behavior changes when practical.
- Avoid adding external runtime dependencies unless there is a strong justification.
- Preserve best-effort behavior for notify/bridge paths (do not make non-critical paths crash callers).

## Commit and Review Expectations

- Use clear commit messages describing intent and impact.
- Include reproduction steps for bug fixes.
- Include validation notes (commands run and results) in PR descriptions.

## Reporting Bugs and Features

Use GitHub Issues with:
- macOS version
- Python version
- command and env configuration (redact sensitive values)
- minimal reproduction steps
- expected vs actual behavior

## Security Reports

Do not post sensitive vulnerabilities publicly. Follow `SECURITY.md`.
