"""Draw dryfire's 512 x 512 plugin icon with the standard library only.

A target on a dark rounded tile: rings in outline (a practice run, nothing
live), with a solid centre. Run from the repository root:

    python3 tools/make_icon.py plugins/dryfire/.claude-plugin/icon.png

The output is deterministic, so CI can check the committed file matches.
"""

import math
import struct
import sys
import zlib

SIZE = 512
SAMPLES = 4  # Supersampling per axis, for smooth edges.
TILE = (24, 28, 36)
RING = (245, 166, 35)
CENTRE = (255, 214, 102)


def _coverage(x, y):
    """(colour, alpha) of the shape at one sample point."""
    c = SIZE / 2.0
    # Rounded tile.
    r_corner, half = 96.0, SIZE / 2.0 - 8
    dx, dy = max(abs(x - c) - (half - r_corner), 0.0), max(abs(y - c) - (half - r_corner), 0.0)
    if math.hypot(dx, dy) > r_corner:
        return None
    d = math.hypot(x - c, y - c)
    if d <= 40:
        return CENTRE
    for radius in (92, 148, 204):
        if abs(d - radius) <= 11:
            # Gaps at the four compass points: the rings read as a sight, not a solid target.
            angle = math.degrees(math.atan2(y - c, x - c)) % 90
            if 9 < angle < 81:
                return RING
    return TILE


def render():
    rows = []
    n = SAMPLES * SAMPLES
    for py in range(SIZE):
        row = bytearray([0])  # Filter type 0 for each scanline.
        for px in range(SIZE):
            acc = [0, 0, 0, 0]
            for sy in range(SAMPLES):
                for sx in range(SAMPLES):
                    col = _coverage(px + (sx + 0.5) / SAMPLES, py + (sy + 0.5) / SAMPLES)
                    if col is not None:
                        acc[0] += col[0]
                        acc[1] += col[1]
                        acc[2] += col[2]
                        acc[3] += 1
            if acc[3]:
                row += bytes([acc[0] // acc[3], acc[1] // acc[3], acc[2] // acc[3], 255 * acc[3] // n])
            else:
                row += b"\0\0\0\0"
        rows.append(bytes(row))
    return b"".join(rows)


def png(raw):
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    header = struct.pack(">IIBBBBB", SIZE, SIZE, 8, 6, 0, 0, 0)  # 8-bit RGBA.
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(raw, 9)) +
            chunk(b"IEND", b""))


def main(argv):
    if len(argv) != 2:
        sys.stderr.write("usage: make_icon.py OUTPUT.png\n")
        return 2
    with open(argv[1], "wb") as fh:
        fh.write(png(render()))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
