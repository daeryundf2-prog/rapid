# T1 Manifest Templates

Status: schema template only

These files are schema-valid examples for future external T1 E01/Ex01 corpus generation. They are not generated from real E01/Ex01 evidence and must not be used as release evidence.

## Files

| File | Purpose |
| --- | --- |
| `t1-minimal-e01.manifest.example.json` | Minimal E01 truth manifest shape. |
| `t1-minimal-ex01.manifest.example.json` | Minimal Ex01 truth manifest shape. |

## Replacement Rules

Before any external run can become release evidence:

1. Replace every dummy hash.
2. Replace every placeholder path with controlled external storage records.
3. Replace template tool versions and commands with real run records.
4. Add real chain-of-custody records.
5. Run `scripts/known-answer-qc.py`.
6. Attach trusted/reference normalized outputs and `trusted-diff` results.

Do not commit actual E01/Ex01 binaries, recovered outputs, customer data, secrets, or license-restricted vendor output to Git.
