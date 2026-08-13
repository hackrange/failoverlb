"""
Turns the manual's content into a Word document.

The content lives as data in chapters/, and this puts it in a .docx.  Keeping
the two apart is what makes the manual a living thing rather than a file
somebody has to remember to update: a feature changes, its chapter changes, and
the whole book is rebuilt with the numbering, contents and cross references
worked out again.

House style, which the writing has to follow and this cannot enforce:

  * Two spaces between sentences.
  * No em dashes.  A comma, a full stop, or brackets, whichever fits.
  * Plain words.  A reader who has never run a load balancer should get
    through it, so anything that has to be jargon is said in ordinary words
    first and named afterwards.
"""
import pathlib

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

ACCENT = RGBColor(0x1A, 0x1A, 0x1A)
MUTED = RGBColor(0x66, 0x66, 0x66)
NOTE_BG = "F2F4F7"
WARN_BG = "FFF4E5"


class Book:
    def __init__(self, title, subtitle, version):
        self.doc = Document()
        self.title = title
        self.subtitle = subtitle
        self.version = version
        self._setup_styles()
        self._setup_page()

    # ---------------------------------------------------------------- set up
    def _setup_page(self):
        for section in self.doc.sections:
            section.page_width = Inches(8.5)
            section.page_height = Inches(11)
            section.left_margin = Inches(1.0)
            section.right_margin = Inches(1.0)
            section.top_margin = Inches(0.9)
            section.bottom_margin = Inches(0.9)

    def _setup_styles(self):
        normal = self.doc.styles["Normal"]
        normal.font.name = "Calibri"
        normal.font.size = Pt(11)
        normal.paragraph_format.space_after = Pt(10)
        normal.paragraph_format.line_spacing = 1.15

        for name, size, bold, space_before in [
            ("Heading 1", 22, True, 24),
            ("Heading 2", 16, True, 18),
            ("Heading 3", 13, True, 14),
        ]:
            style = self.doc.styles[name]
            style.font.name = "Calibri"
            style.font.size = Pt(size)
            style.font.bold = bold
            style.font.color.rgb = ACCENT
            style.paragraph_format.space_before = Pt(space_before)
            style.paragraph_format.space_after = Pt(6)
            style.paragraph_format.keep_with_next = True

    # ------------------------------------------------------------ front page
    def cover(self):
        for _ in range(6):
            self.doc.add_paragraph()
        p = self.doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = p.add_run(self.title)
        run.font.size = Pt(40)
        run.font.bold = True
        run.font.color.rgb = ACCENT

        p = self.doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = p.add_run(self.subtitle)
        run.font.size = Pt(16)
        run.font.color.rgb = MUTED

        for _ in range(2):
            self.doc.add_paragraph()
        p = self.doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = p.add_run(self.version)
        run.font.size = Pt(11)
        run.font.color.rgb = MUTED
        self.page_break()

    def contents(self):
        self.doc.add_heading("Contents", level=1)
        para = self.doc.add_paragraph()
        # A real Word field, not a list typed out by hand.  Word fills it in
        # and keeps the page numbers right, and the entries become links.  A
        # hand written contents page is wrong the first time anything is added,
        # which for a manual that is meant to keep growing is every week.
        fld = OxmlElement("w:fldSimple")
        fld.set(qn("w:instr"), r'TOC \o "1-3" \h \z \u')
        placeholder = OxmlElement("w:r")
        text = OxmlElement("w:t")
        text.text = ("Right click here and choose Update Field to build the "
                     "contents.")
        placeholder.append(text)
        fld.append(placeholder)
        para._p.append(fld)

        # Ask Word to refresh fields when the file is opened, so most readers
        # never see the line above.
        settings = self.doc.settings.element
        update = OxmlElement("w:updateFields")
        update.set(qn("w:val"), "true")
        settings.append(update)
        self.page_break()

    # -------------------------------------------------------------- contents
    def h1(self, text):
        self.doc.add_heading(text, level=1)

    def h2(self, text):
        self.doc.add_heading(text, level=2)

    def h3(self, text):
        self.doc.add_heading(text, level=3)

    def para(self, text):
        return self.doc.add_paragraph(text)

    def bullets(self, items):
        for item in items:
            self.doc.add_paragraph(item, style="List Bullet")

    def numbers(self, items):
        for item in items:
            self.doc.add_paragraph(item, style="List Number")

    def steps(self, items):
        """
        Numbered instructions, spaced so somebody can follow them on a screen
        with one eye and a keyboard under the other hand.
        """
        for item in items:
            p = self.doc.add_paragraph(item, style="List Number")
            p.paragraph_format.space_after = Pt(8)

    def picture(self, path, caption, width=6.3):
        if not pathlib.Path(path).exists():
            # A missing picture becomes a visible note rather than a crash, so
            # a rebuild after a screen changes still produces a whole book and
            # says which picture needs taking again.
            self.note(f"Picture still to be taken: {pathlib.Path(path).name}")
            return
        self.doc.add_picture(str(path), width=Inches(width))
        self.doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER
        p = self.doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run = p.add_run(caption)
        run.font.size = Pt(9)
        run.font.color.rgb = MUTED
        run.italic = True

    def _shaded(self, text, colour, label=None):
        table = self.doc.add_table(rows=1, cols=1)
        cell = table.rows[0].cells[0]
        shading = OxmlElement("w:shd")
        shading.set(qn("w:fill"), colour)
        cell._tc.get_or_add_tcPr().append(shading)
        para = cell.paragraphs[0]
        if label:
            run = para.add_run(label + "  ")
            run.bold = True
        para.add_run(text)
        self.doc.add_paragraph()

    def note(self, text):
        self._shaded(text, NOTE_BG, "Worth knowing")

    def warn(self, text):
        self._shaded(text, WARN_BG, "Take care")

    def code(self, lines, caption=None):
        """
        A short block of literal text, for things meant to be typed or copied.
        Longer terminal output is a picture instead, which reads better and
        cannot be half copied by accident.
        """
        para = self.doc.add_paragraph()
        para.paragraph_format.left_indent = Inches(0.3)
        para.paragraph_format.space_after = Pt(4)
        for i, line in enumerate(lines):
            run = para.add_run(line)
            run.font.name = "Consolas"
            run.font.size = Pt(9.5)
            if i < len(lines) - 1:
                run.add_break()
        if caption:
            cap = self.doc.add_paragraph()
            cap.paragraph_format.left_indent = Inches(0.3)
            run = cap.add_run(caption)
            run.font.size = Pt(9)
            run.italic = True
            run.font.color.rgb = MUTED

    def table(self, headers, rows, widths=None):
        table = self.doc.add_table(rows=1, cols=len(headers))
        table.style = "Light Grid Accent 1"
        for i, head in enumerate(headers):
            cell = table.rows[0].cells[i]
            cell.text = ""
            run = cell.paragraphs[0].add_run(head)
            run.bold = True
        for row in rows:
            cells = table.add_row().cells
            for i, value in enumerate(row):
                cells[i].text = ""
                run = cells[i].paragraphs[0].add_run(str(value))
                run.font.size = Pt(10)
        if widths:
            for i, width in enumerate(widths):
                for row in table.rows:
                    row.cells[i].width = Inches(width)
        self.doc.add_paragraph()

    def page_break(self):
        self.doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)

    def save(self, path):
        self.doc.save(path)
        return path
