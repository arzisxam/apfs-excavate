#!/usr/bin/env python3
"""
apfs-excavate LinkedIn carousel
Output: apfs-excavate-linkedin-carousel.pdf  (10 square slides, 612x612 pt)
Usage:  python3 tools/make_carousel.py
"""
from reportlab.pdfgen import canvas
from reportlab.lib.colors import HexColor

S = 612  # square page: 8.5 x 8.5 in at 72 dpi

# Palette
BG     = HexColor('#0B0E14')
SURF   = HexColor('#141923')
CARD   = HexColor('#1C2433')
BLUE   = HexColor('#4F9CF9')
GREEN  = HexColor('#48BB78')
AMBER  = HexColor('#F6AD55')
RED    = HexColor('#FC8181')
WHITE  = HexColor('#FFFFFF')
MUTED  = HexColor('#8897B2')
DIM    = HexColor('#4A5568')
DBLUE  = HexColor('#1E3A5F')
DGREEN = HexColor('#1A3A2A')
DRED   = HexColor('#3A1A1A')
DAMBER = HexColor('#3A2A0A')
DBLUEB = HexColor('#1A1A3A')


# ── helpers ───────────────────────────────────────────────────────────────────

def blk(c, x, y, w, h, col):
    c.setFillColor(col)
    c.rect(x, y, w, h, fill=1, stroke=0)


def rblk(c, x, y, w, h, r=8, col=CARD, stroke=None, lw=1):
    c.setFillColor(col)
    if stroke:
        c.setStrokeColor(stroke)
        c.setLineWidth(lw)
        c.roundRect(x, y, w, h, r, fill=1, stroke=1)
    else:
        c.roundRect(x, y, w, h, r, fill=1, stroke=0)


def tx(c, s, x, y, font='Helvetica', sz=16, col=WHITE, align='left'):
    c.setFont(font, sz)
    c.setFillColor(col)
    fn = {'left': c.drawString,
          'center': c.drawCentredString,
          'right': c.drawRightString}[align]
    fn(x, y, s)


def wtx(c, s, x, y, font, sz, col, mw, lh=None):
    """Word-wrap text. Returns total height consumed."""
    lh = lh or sz * 1.5
    c.setFont(font, sz)
    c.setFillColor(col)
    words = s.split()
    lines, cur, cw = [], [], 0.0
    for word in words:
        ww = c.stringWidth(word + ' ', font, sz)
        if cur and cw + ww > mw:
            lines.append(' '.join(cur))
            cur, cw = [word], ww
        else:
            cur.append(word)
            cw += ww
    if cur:
        lines.append(' '.join(cur))
    for i, line in enumerate(lines):
        c.drawString(x, y - i * lh, line)
    return len(lines) * lh


def pill(c, x, y, label, bg=BLUE, fg=None, sz=10):
    """Pill badge. Returns width+gap for chaining."""
    fg = fg or BG
    c.setFont('Helvetica-Bold', sz)
    tw = c.stringWidth(label, 'Helvetica-Bold', sz)
    w = tw + 20
    rblk(c, x, y, w, 24, r=12, col=bg)
    tx(c, label, x + 10, y + 7, 'Helvetica-Bold', sz, fg)
    return w + 10


def chrome(c, n, total=10):
    """Draw slide background, top stripe, bottom bar, progress dots."""
    blk(c, 0, 0, S, S, BG)
    # Subtle dot grid
    c.setFillColor(HexColor('#141923'))
    for gx in range(30, S, 54):
        for gy in range(72, S - 52, 54):
            c.circle(gx, gy, 1.2, fill=1, stroke=0)
    blk(c, 0, S - 4, S, 4, BLUE)     # top accent stripe
    blk(c, 0, 0, S, 48, SURF)         # bottom bar
    tx(c, 'apfs-excavate', 22, 16, 'Helvetica-Bold', 13, BLUE)
    # Progress dots
    dw = total * 16
    dx = S - 22 - dw
    for i in range(total):
        cx = dx + i * 16 + 8
        if i == n - 1:
            c.setFillColor(BLUE);  c.circle(cx, 24, 5.5, fill=1, stroke=0)
        else:
            c.setFillColor(DIM);   c.circle(cx, 24, 3.5, fill=1, stroke=0)


def left_bar(c, x, y, h, col):
    blk(c, x, y, 5, h, col)


# ── Slide 1 — HOOK ────────────────────────────────────────────────────────────

def slide_1(c):
    chrome(c, 1)

    # Decorative concentric rings (top-right)
    for rad, col in [(168, HexColor('#0F1E38')), (115, HexColor('#152B50')), (65, DBLUE), (30, BLUE)]:
        c.setFillColor(col)
        c.circle(S - 60, S - 58, rad, fill=1, stroke=0)
    tx(c, '?', S - 60, S - 74, 'Helvetica-Bold', 32, WHITE, 'center')

    # Main headline
    tx(c, 'Your Mac drive', 36, 490, 'Helvetica-Bold', 44, WHITE)
    tx(c, 'just became', 36, 440, 'Helvetica-Bold', 44, WHITE)
    tx(c, 'unreadable.', 36, 390, 'Helvetica-Bold', 44, BLUE)
    blk(c, 36, 378, 115, 4, BLUE)

    # Subtext
    wtx(c, 'Your files are likely still on the disk.', 36, 344, 'Helvetica', 17, MUTED, 420)
    wtx(c, 'macOS just lost its map to find them.', 36, 318, 'Helvetica', 17, MUTED, 420)

    # Pills
    px = 36
    px += pill(c, px, 250, 'Open Source')
    px += pill(c, px, 250, 'MIT License', GREEN)
    pill(c, px, 250, 'Free Forever', AMBER)

    tx(c, 'Swipe to see how to recover them  ->', 36, 73, 'Helvetica-Oblique', 14, MUTED)


# ── Slide 2 — THE PROBLEM ─────────────────────────────────────────────────────

def slide_2(c):
    chrome(c, 2)
    pill(c, 36, 546, 'THE PROBLEM', DRED, RED)

    tx(c, 'APFS metadata', 36, 512, 'Helvetica-Bold', 38, WHITE)
    tx(c, 'corruption is', 36, 466, 'Helvetica-Bold', 38, WHITE)
    tx(c, 'more common', 36, 420, 'Helvetica-Bold', 38, RED)
    tx(c, 'than you think.', 36, 374, 'Helvetica-Bold', 38, MUTED)
    blk(c, 36, 362, 72, 4, RED)

    causes = [
        ('Power loss during a write',
         'Filesystem journal left in an inconsistent state'),
        ('Interrupted macOS upgrade',
         'APFS B-tree structures partially rewritten mid-update'),
        ('Partition tool errors',
         'Incorrect write to superblock or checkpoint area'),
        ('Rare firmware or controller bugs',
         'A bad block in exactly the wrong metadata location'),
    ]
    y = 342
    for title, desc in causes:
        rblk(c, 36, y - 44, 540, 50, r=8, col=CARD)
        left_bar(c, 36, y - 44, 50, RED)
        tx(c, title, 52, y - 16, 'Helvetica-Bold', 13, WHITE)
        tx(c, desc,  52, y - 33, 'Helvetica', 11, MUTED)
        y -= 62


# ── Slide 3 — THE INSIGHT ─────────────────────────────────────────────────────

def slide_3(c):
    chrome(c, 3)
    pill(c, 36, 546, 'KEY INSIGHT', DGREEN, GREEN)

    # Decorative large quote mark
    tx(c, '"', 28, 564, 'Helvetica-Bold', 110, HexColor('#1C2433'))

    tx(c, 'The drive is fine.', 60, 514, 'Helvetica-Bold', 36, WHITE)
    tx(c, 'The filesystem is not.', 60, 470, 'Helvetica-Bold', 36, GREEN)
    blk(c, 60, 458, 244, 4, GREEN)

    wtx(c,
        'APFS stores its file index — inodes, B-trees, extent records — in a small '
        'region of the disk. When that region is damaged, macOS cannot mount the '
        'volume. The rest of the disk is untouched.',
        36, 428, 'Helvetica', 15, MUTED, 540, lh=24)

    # Two comparison cards
    cards = [
        (36,  175, RED,   DRED,   'What is broken',
         ['APFS metadata B-trees', '(a few MB of filesystem index)']),
        (322, 175, GREEN, DGREEN, 'What is intact',
         ['Your files - photos, docs,', 'videos, code, everything else']),
    ]
    for cx, cy, accent, dark, header, lines in cards:
        rblk(c, cx, cy, 254, 105, r=10, col=dark)
        left_bar(c, cx, cy, 105, accent)
        tx(c, header, cx + 18, cy + 80, 'Helvetica-Bold', 13, accent)
        for i, line in enumerate(lines):
            tx(c, line, cx + 18, cy + 56 - i * 21, 'Helvetica', 12, MUTED)

    wtx(c,
        'apfs-excavate bypasses the broken index and reconstructs it by scanning the raw disk.',
        36, 158, 'Helvetica-Bold', 14, BLUE, 540, lh=22)


# ── Slide 4 — THE TOOL ────────────────────────────────────────────────────────

def slide_4(c):
    chrome(c, 4)
    pill(c, 36, 546, 'THE TOOL', DBLUEB, BLUE)

    tx(c, 'Meet', 36, 512, 'Helvetica', 32, MUTED)
    tx(c, 'apfs-excavate', 36, 462, 'Helvetica-Bold', 48, BLUE)
    blk(c, 36, 450, 196, 4, BLUE)

    wtx(c,
        'A deep-recovery command-line tool that scans raw APFS disk images '
        'and extracts files even when macOS cannot mount the drive.',
        36, 418, 'Helvetica', 16, MUTED, 540, lh=26)

    # 2x3 feature grid
    feats = [
        (GREEN, 'Written in C11',       'Maximum performance, minimal overhead'),
        (BLUE,  'Multi-threaded',        'Up to 64 parallel scan threads'),
        (AMBER, 'Encrypted volumes',     'AES-XTS decryption with your password'),
        (GREEN, 'macOS and Linux',       'Runs natively on both platforms'),
        (BLUE,  'Orphan file recovery',  '40+ format auto-identification'),
        (AMBER, 'Checkpoint resume',     'Survives interruptions, picks up where stopped'),
    ]
    cw, ch = 258, 70
    for i, (col, title, sub) in enumerate(feats):
        xi = i % 2
        yi = i // 2
        x = 36 + xi * (cw + 18)
        y = 314 - yi * (ch + 10)
        rblk(c, x, y - ch, cw, ch, r=8, col=CARD)
        left_bar(c, x, y - ch, ch, col)
        tx(c, title, x + 18, y - 25, 'Helvetica-Bold', 13, WHITE)
        tx(c, sub,   x + 18, y - 44, 'Helvetica', 11, MUTED)


# ── Slide 5 — HOW IT WORKS ────────────────────────────────────────────────────

def slide_5(c):
    chrome(c, 5)
    pill(c, 36, 546, 'HOW IT WORKS', DBLUEB, BLUE)

    tx(c, 'Three steps to', 36, 512, 'Helvetica-Bold', 36, WHITE)
    tx(c, 'recover your files.', 36, 469, 'Helvetica-Bold', 36, BLUE)
    blk(c, 36, 457, 162, 4, BLUE)

    steps = [
        (BLUE,  '1', 'Create a disk image',
                'Use ddrescue or Disk Utility to safely image the drive first.'),
        (GREEN, '2', 'Run apfs-excavate',
                'Point it at the image file and choose an output folder.'),
        (AMBER, '3', 'Get your files back',
                'Named files, format-identified orphans, and a full recovery report.'),
    ]

    y = 430
    for accent, num, title, desc in steps:
        rblk(c, 36, y - 88, 540, 93, r=10, col=CARD)
        left_bar(c, 36, y - 88, 93, accent)
        # Number circle
        c.setFillColor(accent)
        c.circle(74, y - 42, 22, fill=1, stroke=0)
        tx(c, num, 74, y - 49, 'Helvetica-Bold', 22, BG, 'center')
        tx(c, title, 110, y - 26, 'Helvetica-Bold', 16, WHITE)
        wtx(c, desc, 110, y - 50, 'Helvetica', 13, MUTED, 444, lh=20)
        y -= 105

    wtx(c,
        'No special hardware. No data sent anywhere. Runs entirely on your Mac or Linux machine.',
        36, 73, 'Helvetica-Oblique', 13, MUTED, 540)


# ── Slide 6 — WHAT IT RECOVERS ────────────────────────────────────────────────

def slide_6(c):
    chrome(c, 6)
    pill(c, 36, 546, 'RECOVERY SCOPE', DGREEN, GREEN)

    tx(c, 'What can', 36, 512, 'Helvetica-Bold', 36, WHITE)
    tx(c, 'it recover?', 36, 469, 'Helvetica-Bold', 36, GREEN)
    blk(c, 36, 457, 120, 4, GREEN)
    tx(c, 'If it was on your drive, apfs-excavate goes after it.', 36, 430, 'Helvetica', 15, MUTED)

    types = [
        (BLUE,  'Photos and Images',    'JPEG, PNG, HEIC, RAW, TIFF'),
        (BLUE,  'Videos',               'MOV, MP4, AVI, M4V, MKV'),
        (GREEN, 'Documents',            'PDF, DOCX, XLSX, PPTX, Pages'),
        (GREEN, 'Source Code',          'Any text-based project or config'),
        (AMBER, 'Audio Files',          'MP3, FLAC, AAC, WAV, AIFF'),
        (AMBER, 'Archives and Backups', 'ZIP, TAR, DMG, sparseimage'),
    ]

    tw, th = 258, 70
    for i, (col, title, fmts) in enumerate(types):
        xi = i % 2
        yi = i // 2
        x = 36 + xi * (tw + 18)
        y = 390 - yi * (th + 10)
        rblk(c, x, y - th, tw, th, r=8, col=CARD)
        left_bar(c, x, y - th, th, col)
        tx(c, title, x + 18, y - 22, 'Helvetica-Bold', 13, WHITE)
        tx(c, fmts,  x + 18, y - 40, 'Helvetica', 11, MUTED)

    tx(c, '+ encrypted volumes, if you know the password', 36, 68, 'Helvetica-Bold', 13, BLUE)


# ── Slide 7 — REAL WORLD ──────────────────────────────────────────────────────

def slide_7(c):
    chrome(c, 7)
    pill(c, 36, 546, 'REAL WORLD', DAMBER, AMBER)

    tx(c, 'Tested on a real', 36, 508, 'Helvetica-Bold', 36, WHITE)
    tx(c, 'corrupted APFS volume.', 36, 464, 'Helvetica-Bold', 36, AMBER)
    blk(c, 36, 452, 162, 4, AMBER)

    # Scenario callout card
    rblk(c, 36, 368, 540, 78, r=10, col=CARD, stroke=AMBER, lw=1)
    tx(c, 'Scenario', 54, 432, 'Helvetica-Bold', 11, AMBER)
    wtx(c,
        'An APFS volume where macOS reported the disk as unreadable. '
        'The drive itself was physically healthy and electrically functional. '
        'Only the APFS filesystem metadata had been corrupted.',
        54, 413, 'Helvetica', 12, MUTED, 504, lh=20)

    stats = [
        (GREEN, 'Drive condition',    'Physically healthy, fully readable at block level'),
        (RED,   'What was broken',    'APFS B-tree metadata structures (filesystem index)'),
        (GREEN, 'Recovery result',    'Thousands of files: photos, documents, project files'),
        (BLUE,  'Encrypted volume',   'AES-XTS decryption completed with user password'),
    ]

    y = 348
    for col, label, detail in stats:
        rblk(c, 36, y - 46, 540, 50, r=8, col=CARD)
        left_bar(c, 36, y - 46, 50, col)
        tx(c, label,  52, y - 15, 'Helvetica-Bold', 13, col)
        tx(c, detail, 52, y - 33, 'Helvetica', 12, MUTED)
        y -= 60

    tx(c, 'Your results will vary with damage severity. Always image the drive first.',
       36, 68, 'Helvetica-Oblique', 13, MUTED)


# ── Slide 8 — UNDER THE HOOD ──────────────────────────────────────────────────

def slide_8(c):
    chrome(c, 8)
    pill(c, 36, 546, 'UNDER THE HOOD', DBLUEB, BLUE)

    tx(c, 'Built for', 36, 510, 'Helvetica', 30, MUTED)
    tx(c, 'performance', 36, 470, 'Helvetica-Bold', 40, WHITE)
    tx(c, 'and correctness.', 36, 425, 'Helvetica-Bold', 40, BLUE)
    blk(c, 36, 413, 100, 4, BLUE)

    tech = [
        (BLUE,  'C11',           'Written in C for maximum performance and low overhead'),
        (GREEN, '64 threads',    'Parallel multi-threaded scanner, configurable workers'),
        (AMBER, 'AES-XTS',       'Full hardware-accelerated decryption via OpenSSL'),
        (BLUE,  'LZFSE / LZVN',  'Native APFS compression formats fully supported'),
        (GREEN, 'Checkpoints',   'Scan state saved to disk - resume after any interruption'),
        (AMBER, 'macOS + Linux', 'Single codebase, tested on both platforms'),
    ]

    y = 388
    for col, label, detail in tech:
        rblk(c, 36, y - 42, 540, 47, r=8, col=CARD)
        left_bar(c, 36, y - 42, 47, col)
        c.setFont('Helvetica-Bold', 13)
        lw = c.stringWidth(label, 'Helvetica-Bold', 13)
        tx(c, label,         54, y - 12, 'Helvetica-Bold', 13, col)
        tx(c, ' - ' + detail, 54 + lw, y - 12, 'Helvetica', 12, MUTED)
        y -= 56


# ── Slide 9 — OPEN SOURCE ─────────────────────────────────────────────────────

def slide_9(c):
    chrome(c, 9)
    pill(c, 36, 546, 'OPEN SOURCE', DGREEN, GREEN)

    tx(c, 'Free.',           36, 510, 'Helvetica-Bold', 50, WHITE)
    tx(c, 'Transparent.',    36, 452, 'Helvetica-Bold', 50, GREEN)
    tx(c, 'Yours to keep.',  36, 394, 'Helvetica-Bold', 50, MUTED)
    blk(c, 36, 382, 100, 4, GREEN)

    props = [
        (GREEN, 'MIT License',
                'Use it, modify it, ship it - no strings attached'),
        (BLUE,  'No telemetry, no accounts',
                'Your data never leaves your machine, ever'),
        (BLUE,  'Single compiled binary',
                'No installer. Build it, run it, done.'),
        (AMBER, 'Full source on GitHub',
                'Read every line. Audit everything. Contribute.'),
    ]

    y = 360
    for col, label, detail in props:
        rblk(c, 36, y - 46, 540, 50, r=8, col=CARD)
        left_bar(c, 36, y - 46, 50, col)
        tx(c, label,  54, y - 15, 'Helvetica-Bold', 13, col)
        tx(c, detail, 54, y - 33, 'Helvetica', 12, MUTED)
        y -= 62

    # GitHub URL box
    rblk(c, 36, 62, 540, 46, r=10, col=CARD, stroke=BLUE, lw=1)
    tx(c, 'github.com/arzisxam/apfs-excavate',
       S // 2, 80, 'Helvetica-Bold', 15, BLUE, 'center')


# ── Slide 10 — CTA ────────────────────────────────────────────────────────────

def slide_10(c):
    chrome(c, 10)

    # Large centered headline
    tx(c, 'Know someone with', S // 2, 520, 'Helvetica-Bold', 36, WHITE, 'center')
    tx(c, 'an unreadable Mac drive?', S // 2, 476, 'Helvetica-Bold', 36, WHITE, 'center')
    blk(c, S // 2 - 80, 462, 160, 4, BLUE)

    wtx(c,
        'Share apfs-excavate. It is free, open source, and might just get their files back.',
        60, 430, 'Helvetica', 16, MUTED, 492, lh=26)

    # Big CTA button
    rblk(c, 80, 330, 452, 64, r=12, col=BLUE)
    tx(c, 'github.com/arzisxam/apfs-excavate',
       S // 2, 355, 'Helvetica-Bold', 15, BG, 'center')

    # Three action pills (centered)
    action_labels = ['Try it', 'Star it on GitHub', 'Share it']
    total_w = sum(
        c.stringWidth(l, 'Helvetica-Bold', 11) + 20 + 10
        for l in action_labels
    ) - 10
    px = S // 2 - total_w // 2
    for label in action_labels:
        c.setFont('Helvetica-Bold', 11)
        w = c.stringWidth(label, 'Helvetica-Bold', 11) + 20
        col = {'Try it': GREEN, 'Star it on GitHub': AMBER, 'Share it': BLUE}[label]
        rblk(c, px, 268, w, 28, r=14, col=col)
        tx(c, label, px + 10, 278, 'Helvetica-Bold', 11, BG)
        px += w + 10

    # Hashtags
    tags = '#OpenSource  #macOS  #DataRecovery  #APFS  #MIT  #Linux'
    tx(c, tags, S // 2, 234, 'Helvetica', 12, MUTED, 'center')

    # Footer
    tx(c, 'Command-line tool. Written in C. No GUI. No fluff. Just recovery.',
       S // 2, 73, 'Helvetica-Oblique', 13, MUTED, 'center')


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    out = 'apfs-excavate-linkedin-carousel.pdf'
    c = canvas.Canvas(out, pagesize=(S, S))
    slides = [slide_1, slide_2, slide_3, slide_4, slide_5,
              slide_6, slide_7, slide_8, slide_9, slide_10]
    for fn in slides:
        fn(c)
        c.showPage()
    c.save()
    print(f'Saved {len(slides)} slides -> {out}')


if __name__ == '__main__':
    main()
