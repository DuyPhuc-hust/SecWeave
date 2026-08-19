"""`python -m cli ...` entrypoint. Only loads dotenv here (not in
cli/__init__.py's main()) — a real .env file sitting on the dev machine
would otherwise silently break a test that's trying to simulate "missing
env var" via cli.main(), since that path never goes through this file."""

from dotenv import load_dotenv

from cli import main

if __name__ == "__main__":
    load_dotenv()
    raise SystemExit(main())
