# Contributing to C2Monitor

Thanks for your interest in making C2Monitor better.

## How to Contribute

1. **Fork the repo** and create a branch from `master`.
2. **Make your changes.** Keep PRs focused — one feature or fix per PR.
3. **Test on Windows 10 or 11** with PowerShell 5.1. Do not use PowerShell 7+ features (`-AsHashtable`, ternary operators, null-coalescing, etc.).
4. **Submit a PR** with a clear description of what you changed and why.

## What We're Looking For

- New detection modules (follow the PHASE pattern in `C2Detect.ps1`)
- Additional blockchain RPC domains or build tool patterns
- Threat intelligence source integrations
- False positive reduction
- Documentation improvements
- Bug fixes

## Code Style

- Follow the existing patterns in `src/`. Variable naming, comment style, error handling — match what's there.
- Use `$ErrorActionPreference = "SilentlyContinue"` and `try {} catch {}` for resilience. This is a background monitor, not an interactive tool — it should never crash.
- Alert messages must include: process name, file path, remote address, and SHA256 hash when possible.
- Use the existing `Write-Alert` (deep scan) or `Write-QuickAlert` (quick scan) functions. Use the cooldown system to prevent alert spam.

## PowerShell 5.1 Compatibility

This is non-negotiable. C2Monitor must run on stock Windows 10/11 with zero prerequisites. Common pitfalls:

- No `-AsHashtable` on `ConvertFrom-Json` — use `PSObject.Properties` iteration
- No ternary operator (`$x ? $a : $b`) — use `if ($x) { $a } else { $b }`
- No null-coalescing (`$x ?? $default`) — use `if ($x) { $x } else { $default }`
- No `??=` assignment
- No pipeline chain operators (`&&`, `||`)

## Reporting Security Issues

If you find a security vulnerability in C2Monitor itself, please open an issue. This is a security tool — we take vulnerabilities in our own code seriously.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
