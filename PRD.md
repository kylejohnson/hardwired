I need your help in creating a PRD for a new Let's Encrypt ACME client.
The goal is to have this client act as a python library, similar to sewer(https://github.com/komuw/sewer/).  The difference is that sewer is unmaintained, and is also a cli client - which I do not need.
## Requirements: 
* Written in >= python 3.13
* Pluggable dns providers (e.g. powerdns, route53).  Start with a 
* Test suite which uses pebble (https://github.com/letsencrypt/pebble) and pebble-challtestsrv (https://github.com/letsencrypt/pebble/blob/main/cmd/pebble-challtestsrv/README.md) to verify compatibility with rfc8555
* Good test coverage (>80%)
* test driven development.  Tests are written first, code follows, and then you iterate until tests pass.
* full support of rfc8555 (https://datatracker.ietf.org/doc/html/rfc8555)
* full support of rfc9773 (https://datatracker.ietf.org/doc/html/rfc9773)
* [uv](https://docs.astral.sh/uv/) is used to replace most python tools.
* Project will be hosted on github, and eventually published to pypi (pypi will come at later date), so repository and python code must follow necessary requirements.
* Code must be formatted with `ruff` via `uv run ruff format`.
* Code must be linted with `ruff` via `uv run ruff linter`.
* Python type hits are required
* Code must be type checked with `ty` via `uv run ty`.
## Questions
* If rfc8555 and rfc9773 are not very tightly bundled, build out rfc8555 support in phase 1, and rfc9773 support in phase 2.
* Help me determine whetoer to implement celery (https://docs.celeryq.dev/en/stable/) as a task queue.  This project will primarially be utilized by another python project which manages ssl certificates for upwards of 300k domains.  That project is built using celery, and imports the sewer library.