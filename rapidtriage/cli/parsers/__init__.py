"""Argparse subcommand registration, one module per command group (T-159).

Each module exposes ``register*`` functions that add subparsers to the
``rapidtriage`` subparser action. ``rapidtriage.cli.parser.build_parser`` calls
them in the original registration order, which is also the ``--help`` order.
"""
