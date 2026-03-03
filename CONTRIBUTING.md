# Contributing to UGOW

Thanks for your interest in contributing! Here's how to get started.

## Getting Started

1. Fork the repository and clone your fork.
2. Install development dependencies:
   ```bash
   pip install -r requirements-dev.txt
   ```
3. Run the tests:
   ```bash
   pytest
   ```

## Submitting Changes

1. Create a branch for your work (`git checkout -b my-change`).
2. Make your changes and add tests where appropriate.
3. Run `pytest` and make sure everything passes.
4. Open a pull request with a clear description of what you changed and why.

## Reporting Bugs

Open an issue with:

- What you expected to happen.
- What actually happened.
- Steps to reproduce.
- Your environment (WSL2 distro, kernel version, backend in use).

## Code Style

- Python code follows PEP 8.
- Shell scripts use `set -euo pipefail`.
- Keep commits focused -- one logical change per commit.

## Scope

The FUSE and BPF backends are the primary focus. The kmod backend is experimental and not yet integrated into the installer, so contributions there are welcome but may take longer to review.
