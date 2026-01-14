## Tooling
### Python
* Python version must be >= 3.13
* [uv](https://docs.astral.sh/uv/) is used to replace most python tools.
* `uv run python` must be used instead of `python`
* `uv pip` must be used instead of `pip`
* Python dependencies must be installed in a virtual environment via `uv venv`
* Additional `uv` functionality can be found with `uv --help`
* Code must be formatted with `ruff` via `uv run ruff format`. Additional functionality can be found with `uv run ruff format -h`
* Code must be linted with `ruff` via `uv run ruff linter`.  Additional functionality can be found with `uv run ruff linter -h`
* Code must be type checked with `ty` via `uv run ty`.  Additional functionality can be found with `uv run ty -h`

## Design Pattern
* Project must follow test driven design.  First create tests, then iterate and create code until tests pass.
