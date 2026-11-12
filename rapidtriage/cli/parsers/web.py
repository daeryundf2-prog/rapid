"""Parser registration for the web command."""

from __future__ import annotations

import argparse
import textwrap

from ..helpers import (
    add_web_arguments,
)


def register(sub: argparse._SubParsersAction) -> None:
    """Register web."""
    web = sub.add_parser(
        "web",
        help="Start the local rapidtriage web UI and API server",
        description="Start the local rapidtriage web UI and API server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            Examples:
              rapidtriage web
              rapidtriage web --host 127.0.0.1 --port 8765
              rapidtriage web --remote --host 0.0.0.0 --token <token>
            """
        ),
    )
    add_web_arguments(web)
