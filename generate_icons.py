"""Generate all PWA icons and favicon for the helpdesk app."""
import os
import struct
import zlib
from PIL import Image, ImageDraw, ImageFont

STATIC = os.path.join(os.path.dirname(__file__), 'static')
os.makedirs(STATIC, exist_ok=True)

# Brand colors
TEAL_DARK  = (44,  95,  95)
TEAL_MED   = (74,  155, 155)
TEAL_LIGHT = (107, 196, 196)
WHITE      = (255, 255, 255)

def make_icon(size):
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    # Background circle with gradient simulation
    pad = int(size * 0.04)
    # Outer gradient ring
    for i in range(pad, 0, -1):
        ratio = i / pad
        r = int(TEAL_DARK[0] + (TEAL_MED[0] - TEAL_DARK[0]) * (1 - ratio))
        g = int(TEAL_DARK[1] + (TEAL_MED[1] - TEAL_DARK[1]) * (1 - ratio))
        b = int(TEAL_DARK[2] + (TEAL_MED[2] - TEAL_DARK[2]) * (1 - ratio))
        d.ellipse([i, i, size - i, size - i], fill=(r, g, b, 255))

    # Main circle
    d.ellipse([pad, pad, size - pad, size - pad],
              fill=TEAL_DARK)

    # Headset icon drawn with simple shapes
    cx, cy = size // 2, size // 2
    r_head  = int(size * 0.22)
    r_ear   = int(size * 0.09)
    stroke  = max(2, int(size * 0.055))
    ear_h   = int(size * 0.13)
    ear_w   = int(size * 0.09)

    # Arc (headband) — draw as thick arc using concentric ellipses
    arc_box = [cx - r_head, cy - r_head, cx + r_head, cy + r_head]
    for t in range(-stroke // 2, stroke // 2 + 1):
        off = t
        b2  = [arc_box[0] - off, arc_box[1] - off,
               arc_box[2] + off, arc_box[3] + off]
        d.arc(b2, start=200, end=340, fill=WHITE, width=max(1, stroke - abs(t)))

    # Left ear cup
    lx = cx - r_head
    d.rounded_rectangle(
        [lx - ear_w, cy - ear_h, lx + ear_w // 2, cy + ear_h],
        radius=ear_w // 2, fill=WHITE
    )

    # Right ear cup
    rx = cx + r_head
    d.rounded_rectangle(
        [rx - ear_w // 2, cy - ear_h, rx + ear_w, cy + ear_h],
        radius=ear_w // 2, fill=WHITE
    )

    # Mic arm (small line down from right cup)
    mic_x1 = rx + ear_w // 2
    mic_y1 = cy + ear_h // 2
    mic_x2 = rx + ear_w // 2 + int(size * 0.08)
    mic_y2 = cy + ear_h + int(size * 0.08)
    d.line([mic_x1, mic_y1, mic_x2, mic_y2], fill=WHITE, width=stroke)
    mic_r = max(2, int(size * 0.035))
    d.ellipse([mic_x2 - mic_r, mic_y2 - mic_r, mic_x2 + mic_r, mic_y2 + mic_r],
              fill=WHITE)

    return img

# Generate all sizes
sizes = {
    'icon-16x16.png':   16,
    'icon-32x32.png':   32,
    'icon-48x48.png':   48,
    'icon-72x72.png':   72,
    'icon-96x96.png':   96,
    'icon-128x128.png': 128,
    'icon-144x144.png': 144,
    'icon-152x152.png': 152,
    'icon-192x192.png': 192,
    'icon-384x384.png': 384,
    'icon-512x512.png': 512,
    'apple-touch-icon.png': 180,
}

for fname, sz in sizes.items():
    img = make_icon(sz)
    img.save(os.path.join(STATIC, fname))
    print(f'  {fname} ({sz}x{sz})')

# favicon.ico — multi-size ICO file (16, 32, 48)
ico_sizes = [16, 32, 48]
ico_imgs  = [make_icon(s).convert('RGBA') for s in ico_sizes]
ico_imgs[0].save(
    os.path.join(STATIC, 'favicon.ico'),
    format='ICO',
    sizes=[(s, s) for s in ico_sizes]
)
print('  favicon.ico (16,32,48)')

# Maskable icon (512 with safe-zone padding ~10%)
mask_img = Image.new('RGBA', (512, 512), TEAL_DARK)
inner = make_icon(400)
mask_img.paste(inner, (56, 56), inner)
mask_img.save(os.path.join(STATIC, 'icon-maskable-512x512.png'))
print('  icon-maskable-512x512.png')

print('\nAll icons generated successfully.')
