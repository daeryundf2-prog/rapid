#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations
"""Packaged rename CLI (dashcam-rename)."""
import sys
from ._rename_impl import main  # type: ignore

def cli():
    code = main(sys.argv[1:])
    if isinstance(code, int):
        sys.exit(code)

if __name__ == "__main__":
    cli()
