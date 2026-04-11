#!/usr/bin/env python3
import cv2
import numpy as np
from PIL import Image, ImageDraw, ImageFont
from pathlib import Path

W, H = 1280, 720
DURATION = 8
FPS = 25
BASE_DATE = '2024-01-02'

CANDIDATES = [
    '/System/Library/Fonts/Supplemental/Arial.ttf',
    '/System/Library/Fonts/AppleSDGothicNeo.ttc',
    '/Library/Fonts/Arial.ttf',
]
font_path = None
for p in CANDIDATES:
    if Path(p).exists():
        font_path = p
        break

font = ImageFont.truetype(font_path, 48) if font_path else ImageFont.load_default()

out_path = Path('testdata/synth_overlay.mp4')
out_path.parent.mkdir(parents=True, exist_ok=True)
fourcc = cv2.VideoWriter_fourcc(*'mp4v')
writer = cv2.VideoWriter(str(out_path), fourcc, FPS, (W, H))

for i in range(DURATION * FPS):
    t = i / FPS
    frame = np.zeros((H, W, 3), dtype=np.uint8)
    frame[:] = (0, 0, 0)
    # rectangle for legibility
    cv2.rectangle(frame, (W - 520, H - 100), (W - 20, H - 20), (40, 40, 40), -1)
    im = Image.fromarray(frame)
    dr = ImageDraw.Draw(im)
    hh = int(t // 3600)
    mm = int((t % 3600) // 60)
    ss = int(t % 60)
    time_text = '{} {:02d}:{:02d}:{:02d}'.format(BASE_DATE, hh, mm, ss)
    dr.text((W - 500, H - 90), time_text, font=font, fill=(255, 255, 255))
    frame = np.array(im)
    writer.write(frame)

writer.release()
print('Wrote {} (font={})'.format(out_path, font_path))

