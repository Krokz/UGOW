# Contributing to UGOW

Thanks for your interest in contributing! Here's how to get started.

## Getting Started

1. Fork the repository and clone your fork.
2. Install the runtime and development dependencies. The FUSE shim tests import
   `fuse`, so both files are needed:
   ```bash
   pip install -r requirements.txt -r requirements-dev.txt
   ```
3. Run the tests:
   ```bash
   pytest
   ```

## Testing on WSL2

`pytest` covers the Python code with the kernel mocked out. To check a real
install, run this on a WSL2 machine after `setup.sh` (or after booting a kernel
built with the kmod):

```bash
sudo ./ugow-verify.sh
```

It tests every gated operation against whichever backend is active, as an
unprivileged uid that holds a grant on one directory and not another.
`sudo ./ugow-verify.sh persist-setup`, a `wsl --shutdown`, then
`sudo ./ugow-verify.sh persist-check` confirm that grants survive a restart.

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

The FUSE and BPF backends are the primary focus. The kmod backend is experimental: CI compiles it against WSL's 6.6 and 6.18 kernels, but it has never been booted and is not integrated into the installer, so contributions there are welcome but may take longer to review.
