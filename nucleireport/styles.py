"""PDF styling constants — colors, fonts, layout dimensions."""

from reportlab.lib.colors import HexColor, white, black, lightgrey
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT


# Page layout
PAGE_SIZE = letter  # 8.5 x 11 inches
PAGE_WIDTH, PAGE_HEIGHT = PAGE_SIZE
MARGIN = 1 * inch
CONTENT_WIDTH = PAGE_WIDTH - 2 * MARGIN

# Severity colors
SEVERITY_COLORS = {
    "critical": HexColor("#DC2626"),
    "high": HexColor("#EA580C"),
    "medium": HexColor("#CA8A04"),
    "low": HexColor("#2563EB"),
    "info": HexColor("#6B7280"),
}

SEVERITY_BG_COLORS = {
    "critical": HexColor("#FEF2F2"),
    "high": HexColor("#FFF7ED"),
    "medium": HexColor("#FEFCE8"),
    "low": HexColor("#EFF6FF"),
    "info": HexColor("#F9FAFB"),
}

# Branding
DARK_BG = HexColor("#1E293B")
ACCENT = HexColor("#3B82F6")
LIGHT_GREY = HexColor("#F1F5F9")
BORDER_GREY = HexColor("#E2E8F0")
TEXT_PRIMARY = HexColor("#0F172A")
TEXT_SECONDARY = HexColor("#475569")

# Font sizes
FONT_TITLE = 28
FONT_SECTION = 18
FONT_HEADING = 14
FONT_SUBHEADING = 12
FONT_BODY = 10
FONT_SMALL = 8
FONT_FOOTER = 7


def get_styles():
    """Build and return all custom ParagraphStyles for the report."""
    base = getSampleStyleSheet()

    styles = {
        "cover_title": ParagraphStyle(
            "cover_title",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=FONT_TITLE,
            textColor=white,
            alignment=TA_CENTER,
            spaceAfter=12,
        ),
        "cover_subtitle": ParagraphStyle(
            "cover_subtitle",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=FONT_HEADING,
            textColor=HexColor("#94A3B8"),
            alignment=TA_CENTER,
            spaceAfter=6,
        ),
        "section_title": ParagraphStyle(
            "section_title",
            parent=base["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=FONT_SECTION,
            textColor=TEXT_PRIMARY,
            spaceBefore=16,
            spaceAfter=10,
        ),
        "heading": ParagraphStyle(
            "heading",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=FONT_HEADING,
            textColor=TEXT_PRIMARY,
            spaceBefore=8,
            spaceAfter=4,
        ),
        "subheading": ParagraphStyle(
            "subheading",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=FONT_SUBHEADING,
            textColor=TEXT_PRIMARY,
            spaceBefore=6,
            spaceAfter=2,
        ),
        "body": ParagraphStyle(
            "body",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=FONT_BODY,
            textColor=TEXT_PRIMARY,
            leading=14,
            spaceAfter=4,
        ),
        "body_secondary": ParagraphStyle(
            "body_secondary",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=FONT_BODY,
            textColor=TEXT_SECONDARY,
            leading=14,
            spaceAfter=2,
        ),
        "small": ParagraphStyle(
            "small",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=FONT_SMALL,
            textColor=TEXT_SECONDARY,
            leading=10,
        ),
        "finding_name": ParagraphStyle(
            "finding_name",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=FONT_SUBHEADING,
            textColor=TEXT_PRIMARY,
            spaceAfter=2,
            wordWrap="CJK",
        ),
        "finding_body": ParagraphStyle(
            "finding_body",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=FONT_BODY,
            textColor=TEXT_PRIMARY,
            leading=13,
            spaceAfter=2,
            wordWrap="CJK",
        ),
        "finding_label": ParagraphStyle(
            "finding_label",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=FONT_BODY,
            textColor=TEXT_SECONDARY,
            spaceAfter=1,
        ),
        "reference_link": ParagraphStyle(
            "reference_link",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=FONT_SMALL,
            textColor=ACCENT,
            leading=11,
            wordWrap="CJK",
        ),
    }
    return styles
