"""Command-line entry point. Subcommands arrive with M1 (review, retry, refile, doctor)."""

import argparse

from scan_sorter import __version__


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scan-sorter")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.parse_args(argv)
    parser.print_help()
    return 0
