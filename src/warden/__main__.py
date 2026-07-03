"""Enable ``python -m warden`` as an alias for the CLI."""

from warden.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
