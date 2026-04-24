# RapidTriage Release Checklist

## Required Checks

- Run `python -m unittest discover -s tests`.
- Run `python -m compileall -q rapidtriage`.
- Run `node --check rapidtriage/web/static/app.js`.
- Run `python -m build --wheel --sdist --no-isolation`.
- Run `rapidtriage sample --run --overwrite`.
- Run `rapidtriage benchmark --output-dir ./release-benchmark --file-count 1000 --overwrite`.

## Artifact Build

```bash
python scripts/build-release.py --output-dir release
```

Expected artifacts:

- Wheel and source distribution when build is not skipped.
- `rapidtriage-portable.zip`.
- Windows launchers.
- User guide and Windows quick-start docs.

## Release Notes Must Include

- Supported evidence inputs and limitations.
- E01/Ex01 external tool requirements.
- Test and benchmark result summary.
- Known parser coverage gaps.
- Security note for non-localhost web binding.
