"""
Pictures for the manual: annotated screenshots and terminal transcripts.

Two jobs.  One draws arrows and labels onto a screenshot so a reader is told
where to click rather than left to hunt for it.  The other renders a block of
terminal text as an image, because a wall of monospace pasted into Word looks
like something went wrong, and a picture of a terminal reads as a terminal.

Both are deterministic.  The same input gives the same picture every time, so
rebuilding the manual after a feature changes does not churn every image in it.
"""
import pathlib

from PIL import Image, ImageDraw, ImageFont

FONT_DIR = pathlib.Path("/usr/share/fonts/truetype")
SANS = FONT_DIR / "dejavu/DejaVuSans.ttf"
SANS_BOLD = FONT_DIR / "dejavu/DejaVuSans-Bold.ttf"
MONO = FONT_DIR / "dejavu/DejaVuSansMono.ttf"
MONO_BOLD = FONT_DIR / "dejavu/DejaVuSansMono-Bold.ttf"

# One accent colour, used for every arrow and every label.  A reader learns
# within two pages that this colour means "we added this, it is not on your
# screen", and after that the pictures need no explaining.
ACCENT = (214, 45, 32)
ACCENT_TEXT = (255, 255, 255)

# A terminal that prints like a terminal people actually use.
TERM_BG = (28, 30, 34)
TERM_FG = (223, 226, 230)
TERM_DIM = (140, 148, 158)
TERM_GREEN = (126, 200, 128)
TERM_BLUE = (114, 175, 229)
TERM_YELLOW = (226, 192, 108)
TERM_BAR = (52, 56, 62)


def _font(path, size):
    return ImageFont.truetype(str(path), size)


def _text_size(draw, text, font):
    box = draw.textbbox((0, 0), text, font=font)
    return box[2] - box[0], box[3] - box[1]


def annotate(source, out, marks, scale=None):
    """
    Draw callouts onto a screenshot.

    Each mark is a dict:

        {"at": (x, y),          where the arrow points, in image coordinates
         "text": "Click here",  what the label says
         "from": (x, y),        optional, where the arrow starts
         "align": "left"}       which side of the arrow start the label sits

    Coordinates are given against the image as it is on disk.  The screenshots
    are taken at twice normal size so they stay sharp in print, which means a
    point read off a normal sized viewer has to be doubled, and `scale` does
    that so the numbers in the manual source can be the ones a person measured.
    """
    img = Image.open(source).convert("RGB")
    draw = ImageDraw.Draw(img)
    factor = scale if scale else 1
    label_font = _font(SANS_BOLD, int(26 * factor))

    # Where labels have already been put, so the next one does not land on top.
    # Two controls sitting side by side is the normal case, not the exception:
    # buttons come in rows.  Without this the second label is drawn over the
    # first and one of them is simply unreadable, which is worse than having no
    # callout because the picture looks finished.
    placed = []

    for mark in marks:
        at = (mark["at"][0] * factor, mark["at"][1] * factor)
        align = mark.get("align", "left")
        start = mark.get("from")
        if start:
            start = (start[0] * factor, start[1] * factor)
        else:
            start = (at[0] - 220 * factor, at[1] - 90 * factor)

        w, h = _text_size(draw, mark["text"], label_font)
        pad = int(10 * factor)

        # Flip to the other side rather than run off the edge of the picture.
        if align == "left" and start[0] - w - pad * 3 < 0:
            align = "right"
            start = (at[0] + 220 * factor, start[1])
        if align == "right" and start[0] + w + pad * 3 > img.width:
            align = "left"
            start = (max(w + pad * 4, at[0] - 220 * factor), start[1])

        # Then step the label up until it is clear of the ones already drawn.
        step = h + pad * 3
        for _ in range(12):
            box = _label_box(start, w, h, pad, align)
            if not any(_overlaps(box, other) for other in placed):
                break
            start = (start[0], start[1] - step)
            if box[1] - step < 0:
                start = (start[0], at[1] + step)
        placed.append(_label_box(start, w, h, pad, align))

        _arrow(draw, start, at, width=max(3, int(4 * factor)))
        _label(draw, start, mark["text"], label_font, align=align, factor=factor)

    pathlib.Path(out).parent.mkdir(parents=True, exist_ok=True)
    img.save(out)
    return out


def _label_box(at, w, h, pad, align):
    x, y = at
    if align == "left":
        x = x - w - pad * 2
    y = y - h // 2 - pad
    return [x - pad, y - pad, x + w + pad, y + h + pad * 2]


def _overlaps(a, b):
    return not (a[2] < b[0] or b[2] < a[0] or a[3] < b[1] or b[3] < a[1])


def _arrow(draw, start, end, width=4):
    draw.line([start, end], fill=ACCENT, width=width)

    # A head that sits on the line rather than a triangle guessed at, so it
    # points where the line points however the line is angled.
    import math
    angle = math.atan2(end[1] - start[1], end[0] - start[0])
    size = width * 5
    for spread in (2.6, -2.6):
        draw.line(
            [end,
             (end[0] + size * math.cos(angle + spread),
              end[1] + size * math.sin(angle + spread))],
            fill=ACCENT, width=width)


def _label(draw, at, text, font, align="left", factor=1):
    pad = int(10 * factor)
    w, h = _text_size(draw, text, font)
    x, y = at
    if align == "left":
        x = x - w - pad * 2
    y = y - h // 2 - pad

    box = [x - pad, y - pad, x + w + pad, y + h + pad * 2]
    draw.rounded_rectangle(box, radius=int(6 * factor), fill=ACCENT)
    draw.text((x, y), text, font=font, fill=ACCENT_TEXT)


def terminal(lines, out, title="root@lb-01: ~", width=100, scale=2):
    """
    Render terminal output as a picture of a terminal.

    `lines` is a list of strings.  A line starting "$ " is drawn as something
    the reader types, and stands out from the output, because the single most
    common way to get stuck following instructions is losing track of which
    lines are yours and which are the computer's.
    """
    pad = 18 * scale
    bar = 34 * scale
    font = _font(MONO, 15 * scale)
    font_bold = _font(MONO_BOLD, 15 * scale)
    title_font = _font(SANS, 13 * scale)

    probe = Image.new("RGB", (10, 10))
    pdraw = ImageDraw.Draw(probe)
    char_w = pdraw.textlength("M", font=font)
    line_h = int(21 * scale)

    img_w = int(char_w * width + pad * 2)
    img_h = int(bar + pad * 2 + line_h * max(1, len(lines)))
    img = Image.new("RGB", (img_w, img_h), TERM_BG)
    draw = ImageDraw.Draw(img)

    draw.rectangle([0, 0, img_w, bar], fill=TERM_BAR)
    for i, colour in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        cx = pad + i * 20 * scale
        r = 6 * scale
        draw.ellipse([cx - r, bar // 2 - r, cx + r, bar // 2 + r], fill=colour)
    tw = draw.textlength(title, font=title_font)
    draw.text(((img_w - tw) / 2, bar / 2 - 8 * scale), title,
              font=title_font, fill=TERM_DIM)

    y = bar + pad
    for line in lines:
        if line.startswith("$ "):
            draw.text((pad, y), "$", font=font_bold, fill=TERM_GREEN)
            draw.text((pad + char_w * 2, y), line[2:], font=font_bold, fill=TERM_FG)
        elif line.startswith("# "):
            draw.text((pad, y), line, font=font, fill=TERM_DIM)
        elif line.startswith("[ok]"):
            draw.text((pad, y), line, font=font, fill=TERM_GREEN)
        elif line.startswith("[warn]"):
            draw.text((pad, y), line, font=font, fill=TERM_YELLOW)
        elif line.startswith("=="):
            draw.text((pad, y), line, font=font_bold, fill=TERM_BLUE)
        else:
            draw.text((pad, y), line, font=font, fill=TERM_FG)
        y += line_h

    pathlib.Path(out).parent.mkdir(parents=True, exist_ok=True)
    img.save(out)
    return out


def crop(source, out, box, scale=2):
    """
    Cut a region out of a screenshot, for when the point is one panel.

    A full page screenshot shrunk to fit a page turns six point type into
    something nobody can read.  Showing the part being talked about, at a size
    where the words are legible, is worth more than showing everything.
    """
    img = Image.open(source).convert("RGB")
    img.crop(tuple(int(v * scale) for v in box)).save(out)
    return out


def trim(path, background=(245, 245, 245), pad=24):
    """
    Cut the empty space off an image.

    A dialog sits in the middle of a large empty page, and placed in the manual
    at full width that empty space is most of a printed page while the words in
    the dialog come out too small to read.  Trimming to what is actually on the
    image means the same page space is spent on the part being talked about.

    Done after the callouts are drawn so the labels and arrows are inside the
    kept area rather than sliced off at the edge.
    """
    img = Image.open(path).convert("RGB")

    # Compare against the actual corner colour rather than an assumed one, so
    # this keeps working if the page background is ever restyled.
    corner = img.getpixel((0, 0))
    if background is not None and corner != background:
        background = corner

    mask = Image.new("L", img.size, 0)
    pixels = img.load()
    mpix = mask.load()
    step = 2                       # every other pixel is plenty to find edges
    for y in range(0, img.height, step):
        for x in range(0, img.width, step):
            p = pixels[x, y]
            if abs(p[0] - background[0]) + abs(p[1] - background[1]) + \
               abs(p[2] - background[2]) > 24:
                mpix[x, y] = 255

    box = mask.getbbox()
    if not box:
        return path
    left = max(0, box[0] - pad)
    top = max(0, box[1] - pad)
    right = min(img.width, box[2] + pad)
    bottom = min(img.height, box[3] + pad)
    img.crop((left, top, right, bottom)).save(path)
    return path
