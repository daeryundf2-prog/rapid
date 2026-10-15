"""Rebuild the console's bundled web fonts (visual-polish plan U-V2).

    python -I frontend/src/assets/fonts/build_fonts.py      # needs fonttools + brotli

Inputs come from the npm packages `pretendard` and `@fontsource-variable/jetbrains-mono`
(frontend/node_modules, both SIL OFL 1.1). Outputs, next to this script:

* rf-ui-variable.woff2 — Pretendard Variable subset, weight axis limited to 400–700
  (the console uses 400/500/600/700): Latin + Latin-1 + punctuation/arrows/shapes the
  UI uses, Hangul compatibility jamo, the ~1,440 most frequent Hangul syllables
  (Pretendard's own frequency-ordered dynamic-subset slices 72–91) and every Hangul
  syllable found in the console's source strings. Rarer syllables fall back to a
  locally installed Pretendard, then the OS Korean font (see --font-ui in tokens.css).
  Pretendard has the Reserved Font Name "Pretendard", so the modified (subset) font is
  renamed "RapidForensic UI" as OFL 1.1 §3 requires.
* jetbrains-mono-{latin,latin-ext}-wght-normal.woff2 — unmodified copies from Fontsource.

Budget: ≤ 300 KB woff2 in total; the script prints the sizes and fails above it.
"""

import pathlib
import re
import shutil
import sys

from fontTools import subset
from fontTools.ttLib import TTFont
from fontTools.varLib import instancer

HERE = pathlib.Path(__file__).resolve().parent
FRONTEND = HERE.parents[2]
MODULES = FRONTEND / "node_modules"
PRETENDARD = MODULES / "pretendard/dist"
MONO = MODULES / "@fontsource-variable/jetbrains-mono"
FAMILY = "RapidForensic UI"
BUDGET = 300 * 1024
FREQUENT_SLICES = range(72, 92)  # dynamic-subset slices: higher index = more frequent

# fontTools 4.6x trips over this font's sparse gvar (KeyError on glyphs without deltas).
subset._dict_subset = lambda d, glyphs: {g: d[g] for g in glyphs if g in d}


def ranges(*spans):
    out = []
    for a, b in spans:
        out.extend(range(a, b + 1))
    return out


LATIN = ranges(
    (0x0020, 0x007E),  # ASCII
    (0x00A0, 0x00FF),  # Latin-1
    (0x2010, 0x205F),  # general punctuation
    (0x2190, 0x21FF),  # arrows
    (0x2200, 0x22FF),  # math operators (≤ ≥ − ⋯)
    (0x2300, 0x23FF),  # misc technical (⌘)
    (0x25A0, 0x25FF),  # geometric shapes (▲ ▼ ▸ ●)
    (0x2700, 0x271F),  # dingbats (✓ ✕)
    (0x3000, 0x303F),  # CJK punctuation
    (0x3131, 0x318E),  # Hangul compatibility jamo
    (0xFF01, 0xFF5E),  # full-width forms
) + [0x20A9, 0x2122]


def frequent_hangul():
    css = (PRETENDARD / "web/variable/pretendardvariable-dynamic-subset.css").read_text(encoding="utf-8")
    cps = set()
    for idx, uranges in re.findall(r"/\* \[(\d+)\] \*/.*?unicode-range: ([^;]+);", css, re.S):
        if int(idx) not in FREQUENT_SLICES:
            continue
        for part in uranges.split(","):
            a, _, b = part.strip().removeprefix("U+").partition("-")
            cps.update(range(int(a, 16), int(b or a, 16) + 1))
    return {c for c in cps if 0xAC00 <= c <= 0xD7A3}


def ui_hangul():
    cps = set()
    for path in (FRONTEND / "src").rglob("*"):
        if path.suffix in (".ts", ".tsx") and ".test." not in path.name:
            cps.update(ord(ch) for ch in path.read_text(encoding="utf-8") if 0xAC00 <= ord(ch) <= 0xD7A3)
    return cps


def rename(font, family):
    name = font["name"]
    for rec in list(name.names):
        if rec.nameID in (1, 3, 4, 6, 16, 25):
            text = {1: family, 3: f"{family};subset", 4: family, 6: family.replace(" ", ""), 16: family}.get(
                rec.nameID, family.replace(" ", "")
            )
            name.setName(text, rec.nameID, rec.platformID, rec.platEncID, rec.langID)
        elif rec.nameID >= 256:  # named-instance names, e.g. PretendardVariable-Bold
            text = rec.toUnicode().replace("PretendardVariable", family.replace(" ", ""))
            name.setName(text.replace("Pretendard", family), rec.nameID, rec.platformID, rec.platEncID, rec.langID)


def build_ui_font():
    font = TTFont(str(PRETENDARD / "public/variable/PretendardVariable.ttf"), lazy=False)
    font = instancer.instantiateVariableFont(font, {"wght": (400, 700)})
    opts = subset.Options()
    opts.flavor = "woff2"
    opts.hinting = False
    opts.name_IDs = ["*"]
    opts.notdef_outline = True
    unicodes = sorted(set(LATIN) | frequent_hangul() | ui_hangul())
    sub = subset.Subsetter(opts)
    sub.populate(unicodes=unicodes)
    sub.subset(font)
    rename(font, FAMILY)
    font.flavor = "woff2"
    out = HERE / "rf-ui-variable.woff2"
    font.save(str(out))
    missing = ui_hangul() - frequent_hangul()
    print(f"{out.name}: {len(unicodes)} code points ({len(missing)} UI-only syllables added)")
    return out


def main():
    outputs = [build_ui_font()]
    for name in ("jetbrains-mono-latin-wght-normal.woff2", "jetbrains-mono-latin-ext-wght-normal.woff2"):
        shutil.copyfile(MONO / "files" / name, HERE / name)
        outputs.append(HERE / name)
    shutil.copyfile(PRETENDARD / "LICENSE.txt", HERE / "LICENSE-Pretendard.txt")
    shutil.copyfile(MONO / "LICENSE", HERE / "LICENSE-JetBrainsMono.txt")
    total = 0
    for path in outputs:
        size = path.stat().st_size
        total += size
        print(f"  {path.name:48} {size / 1024:7.1f} KB")
    print(f"  {'total':48} {total / 1024:7.1f} KB (budget {BUDGET // 1024} KB)")
    return 0 if total <= BUDGET else 1


if __name__ == "__main__":
    sys.exit(main())
