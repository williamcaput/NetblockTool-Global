# Contributing

1. Fork the repository and create a focused branch.
2. Install development dependencies with `python -m pip install -e '.[dev]'`.
3. Add or update tests for behavior changes.
4. Run `ruff check .` and `pytest` before opening a pull request.
5. Keep registry queries bounded and use only documented public interfaces.

Bug reports should include the command, Python version, operating system, verbose output, and a redacted sample response when parsing is involved.
