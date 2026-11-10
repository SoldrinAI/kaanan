from __future__ import annotations

from collections import Counter
from datetime import datetime
from pathlib import Path

from fpdf import FPDF, XPos, YPos

from kaanan.scanner import FileResult, Vulnerability


# ---------------------------------------------------------------------------
# Unicode sanitiser — strip any char latin-1 fonts cannot render
# ---------------------------------------------------------------------------

_UNICODE_MAP = {
    '\u2014': '-',   '\u2013': '-',   '\u2018': "'",  '\u2019': "'",
    '\u201c': '"',   '\u201d': '"',   '\u2026': '...','\u2022': '*',
    '\u2192': '->',  '\u2190': '<-',  '\u00b7': '.',  '\u2500': '-',
    '\u2502': '|',   '\u250c': '+',   '\u2510': '+',  '\u2514': '+',
    '\u2518': '+',   '\u251c': '+',   '\u2524': '+',  '\u252c': '+',
    '\u2534': '+',   '\u253c': '+',   '\u2550': '=',  '\u2551': '|',
    '\u00a9': '(c)', '\u00ae': '(R)', '\u00b0': 'deg','\u00d7': 'x',
    '\u00f7': '/',   '\u2248': '~=',  '\u2260': '!=', '\u2264': '<=',
    '\u2265': '>=',  '\u00b1': '+/-', '\u221a': 'sqrt',
}

def _s(text: str) -> str:
    for ch, rep in _UNICODE_MAP.items():
        text = text.replace(ch, rep)
    return text.encode('latin-1', errors='replace').decode('latin-1')


# ---------------------------------------------------------------------------
# Palette
# ---------------------------------------------------------------------------

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

SEVERITY_RGB: dict[str, tuple] = {
    "CRITICAL": (185, 28,  28),
    "HIGH":     (194, 65,  12),
    "MEDIUM":   (133, 77,  14),
    "LOW":      (21,  128, 61),
}
SEVERITY_BG: dict[str, tuple] = {
    "CRITICAL": (254, 226, 226),
    "HIGH":     (255, 237, 213),
    "MEDIUM":   (254, 249, 195),
    "LOW":      (220, 252, 231),
}

WHITE      = (255, 255, 255)
BG_PAGE    = (248, 250, 252)
BG_CARD    = (255, 255, 255)
BG_HEADER  = (15,  23,  42)
BG_CODE    = (241, 245, 249)
BG_HL      = (254, 243, 199)
BG_FIX     = (240, 253, 244)
BG_IMPACT  = (239, 246, 255)
BORDER     = (226, 232, 240)
TEXT_PRI   = (15,  23,  42)
TEXT_SEC   = (100, 116, 139)
TEXT_FIX   = (22,  101, 52)
TEXT_IMP   = (29,  78,  216)
LINE_GUT   = (226, 232, 240)
TAG_BG     = (241, 245, 249)


# ---------------------------------------------------------------------------
# Logo resolution
# ---------------------------------------------------------------------------

def _find_logo() -> Path | None:
    for candidate in (
        Path(__file__).parent / "assets" / "logo.png",
        Path(__file__).parent.parent / "assets" / "logo.png",
    ):
        if candidate.exists():
            return candidate
    return None



# ---------------------------------------------------------------------------
# PDF class
# ---------------------------------------------------------------------------

class KaananPDF(FPDF):
    def __init__(self, logo_path: Path | None):
        super().__init__(orientation="P", unit="mm", format="A4")
        self.set_auto_page_break(auto=True, margin=18)
        self.set_margins(left=15, top=22, right=15)
        self._logo = logo_path

    # Override to sanitize ALL text automatically
    def cell(self, w=0, h=0, text="", *args, **kwargs):
        super().cell(w, h, _s(str(text)), *args, **kwargs)

    def multi_cell(self, w, h=0, text="", *args, **kwargs):
        super().multi_cell(w, h, _s(str(text)), *args, **kwargs)

    def fill_rect(self, x, y, w, h, color):
        self.set_fill_color(*color)
        self.rect(x, y, w, h, style="F")

    def bordered_rect(self, x, y, w, h, fill, border):
        self.fill_rect(x, y, w, h, fill)
        self.set_draw_color(*border)
        self.rect(x, y, w, h, style="D")

    def header(self):
        self.fill_rect(0, 0, 210, 18, BG_HEADER)
        if self._logo and self._logo.exists():
            try:
                self.image(str(self._logo), x=14, y=3, h=12)
            except Exception:
                pass
        self.set_xy(0, 5)
        self.set_text_color(148, 163, 184)
        self.set_font("Helvetica", size=8)
        super().cell(0, 6, "Security Assessment Report", align="R")
        self.set_y(22)

    def footer(self):
        self.set_y(-13)
        self.fill_rect(0, self.get_y() - 1, 210, 15, BG_HEADER)
        self.set_text_color(100, 116, 139)
        self.set_font("Helvetica", size=7)
        super().cell(0, 10,
            f"Kaanan.ai  |  Confidential  |  Page {self.page_no()}  |  "
            "Results require human verification",
            align="C")

    def new_page(self):
        self.add_page()
        self.fill_rect(0, 18, 210, 279, BG_PAGE)

    def inline_tag(self, text: str, fg: tuple, bg: tuple, x: float, y: float) -> float:
        """Draws a small pill tag. Returns width used."""
        self.set_font("Helvetica", size=6.5)
        tw = self.get_string_width(_s(text)) + 4
        self.fill_rect(x, y, tw, 4.5, bg)
        self.set_draw_color(*fg)
        self.rect(x, y, tw, 4.5, style="D")
        self.set_xy(x, y)
        self.set_text_color(*fg)
        super().cell(tw, 4.5, text, align="C")
        return tw + 2


# ---------------------------------------------------------------------------
# Code snippet renderer
# ---------------------------------------------------------------------------

def _render_snippet(pdf: KaananPDF, vuln: Vulnerability,
                    source_lines: list[str]) -> None:
    """
    Renders a code snippet. Uses verified_line (found by snippet search) if
    available; falls back to the LLM-reported line; falls back to showing
    the raw code_snippet string directly.
    """
    LINE_H   = 4.2
    GUTTER   = 11
    x        = 27
    w        = 163
    CONTEXT  = 3

    display_line = vuln.verified_line or vuln.line
    sev_color    = SEVERITY_RGB.get(vuln.severity, TEXT_PRI)

    # Build the lines to display
    if display_line and source_lines and display_line <= len(source_lines):
        start      = max(0, display_line - CONTEXT - 1)
        end        = min(len(source_lines), display_line + CONTEXT)
        lines      = [(i + 1, source_lines[i]) for i in range(start, end)]
        target_num = display_line
    elif vuln.code_snippet:
        # Fallback: show LLM snippet directly, no line numbers
        lines      = [(None, l) for l in vuln.code_snippet.splitlines()]
        target_num = None
    else:
        return

    if not lines:
        return

    total_h = len(lines) * LINE_H + 4
    if pdf.get_y() + total_h > 272:
        pdf.new_page()

    y0 = pdf.get_y()
    pdf.bordered_rect(x, y0, w, total_h, BG_CODE, BORDER)

    y = y0 + 2
    for num, raw_line in lines:
        is_target = (num == target_num) if num is not None else False

        if is_target:
            pdf.fill_rect(x + 1, y, w - 2, LINE_H, BG_HL)
            pdf.fill_rect(x + 1, y, 1.5, LINE_H, sev_color)

        # Gutter
        pdf.fill_rect(x + 1, y, GUTTER, LINE_H,
                      LINE_GUT if not is_target else BG_HL)
        pdf.set_xy(x + 1, y)
        pdf.set_text_color(*TEXT_SEC)
        pdf.set_font("Courier", size=6.5)
        lbl = str(num) if num is not None else " "
        super(KaananPDF, pdf).cell(GUTTER, LINE_H, _s(lbl), align="R")

        # Code
        code = raw_line.rstrip().replace("\t", "    ")
        if len(code) > 90:
            code = code[:87] + "..."
        pdf.set_xy(x + GUTTER + 1.5, y)
        pdf.set_text_color(*sev_color if is_target else TEXT_PRI)
        pdf.set_font("Courier",
                     style="B" if is_target else "", size=6.5)
        super(KaananPDF, pdf).cell(w - GUTTER - 3, LINE_H, _s(code))
        y += LINE_H

    pdf.set_y(y0 + total_h + 2)


# ---------------------------------------------------------------------------
# Summary page
# ---------------------------------------------------------------------------

def _render_summary(pdf: KaananPDF, results: list[FileResult]) -> None:
    all_vulns = [v for r in results for v in r.vulnerabilities]
    total     = len(all_vulns)
    counts    = Counter(v.severity for v in all_vulns)
    now       = datetime.now().strftime("%B %d, %Y  %H:%M")

    if counts.get("CRITICAL"):
        risk, rc = "CRITICAL RISK", SEVERITY_RGB["CRITICAL"]
        rbg      = SEVERITY_BG["CRITICAL"]
    elif counts.get("HIGH"):
        risk, rc = "HIGH RISK", SEVERITY_RGB["HIGH"]
        rbg      = SEVERITY_BG["HIGH"]
    elif counts.get("MEDIUM"):
        risk, rc = "MEDIUM RISK", SEVERITY_RGB["MEDIUM"]
        rbg      = SEVERITY_BG["MEDIUM"]
    elif total:
        risk, rc = "LOW RISK", SEVERITY_RGB["LOW"]
        rbg      = SEVERITY_BG["LOW"]
    else:
        risk, rc = "NO ISSUES FOUND", SEVERITY_RGB["LOW"]
        rbg      = SEVERITY_BG["LOW"]

    W = 180

    # Title
    pdf.set_text_color(*TEXT_PRI)
    pdf.set_font("Helvetica", style="B", size=20)
    pdf.cell(0, 11, "Security Assessment Report",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(*TEXT_SEC)
    pdf.set_font("Helvetica", size=9)
    pdf.cell(0, 6,
             f"Generated on {now}   |   {len(results)} file(s) scanned",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    # Risk pill
    pdf.fill_rect(15, pdf.get_y(), 44, 8, rbg)
    pdf.set_draw_color(*rc)
    pdf.rect(15, pdf.get_y(), 44, 8, style="D")
    pdf.set_xy(15, pdf.get_y())
    pdf.set_text_color(*rc)
    pdf.set_font("Helvetica", style="B", size=9)
    super(KaananPDF, pdf).cell(44, 8, risk, align="C")
    pdf.ln(13)

    # Divider
    pdf.set_draw_color(*BORDER)
    pdf.line(15, pdf.get_y(), 195, pdf.get_y())
    pdf.ln(5)

    # Severity cards
    cw = W / 4
    y0 = pdf.get_y()
    for i, sev in enumerate(SEVERITY_ORDER):
        x   = 15 + i * cw
        cnt = counts.get(sev, 0)
        c   = SEVERITY_RGB[sev]
        bg  = SEVERITY_BG[sev]
        pdf.bordered_rect(x, y0, cw - 3, 22, bg, BORDER)
        pdf.fill_rect(x, y0, cw - 3, 2.5, c)
        pdf.set_xy(x, y0 + 3)
        pdf.set_text_color(*c)
        pdf.set_font("Helvetica", style="B", size=20)
        super(KaananPDF, pdf).cell(cw - 3, 9, str(cnt), align="C")
        pdf.set_xy(x, y0 + 13)
        pdf.set_text_color(*TEXT_SEC)
        pdf.set_font("Helvetica", style="B", size=7)
        super(KaananPDF, pdf).cell(cw - 3, 6, sev, align="C")

    pdf.set_y(y0 + 26)
    pdf.set_text_color(*TEXT_SEC)
    pdf.set_font("Helvetica", size=8)
    stats = (
        f"Total findings: {total}      "
        f"Files affected: {sum(1 for r in results if r.vulnerabilities)}      "
        f"Clean files: {sum(1 for r in results if not r.vulnerabilities and not r.error)}      "
        f"Scan errors: {sum(1 for r in results if r.error)}"
    )
    pdf.cell(0, 6, stats, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(3)

    # Token usage block
    total_prompt     = sum(r.prompt_tokens     for r in results)
    total_completion = sum(r.completion_tokens for r in results)
    total_tokens     = total_prompt + total_completion
    model_name       = next((r.model for r in results if r.model), "unknown")

    ty = pdf.get_y()
    pdf.bordered_rect(15, ty, W, 10, (248, 250, 252), BORDER)
    pdf.set_xy(17, ty + 1.5)
    pdf.set_text_color(*TEXT_SEC)
    pdf.set_font("Helvetica", style="B", size=7)
    super(KaananPDF, pdf).cell(30, 4, "TOKEN USAGE")
    pdf.set_font("Helvetica", size=7)
    token_line = (
        f"Model: {model_name}      "
        f"Prompt: {total_prompt:,}      "
        f"Completion: {total_completion:,}      "
        f"Total: {total_tokens:,} tokens"
    )
    super(KaananPDF, pdf).cell(0, 4, _s(token_line), align="R")
    pdf.set_y(ty + 13)

    pdf.set_draw_color(*BORDER)
    pdf.line(15, pdf.get_y(), 195, pdf.get_y())
    pdf.ln(5)


# ---------------------------------------------------------------------------
# File block
# ---------------------------------------------------------------------------

def _render_file_block(pdf: KaananPDF, result: FileResult) -> None:
    W = 180

    if pdf.get_y() > 255:
        pdf.new_page()

    # File header bar
    y_hdr = pdf.get_y()
    pdf.bordered_rect(15, y_hdr, W, 9, (238, 242, 255), BORDER)

    if result.error:
        icon, pc = "[!] ", SEVERITY_RGB["CRITICAL"]
    elif not result.vulnerabilities:
        icon, pc = "[ok]", SEVERITY_RGB["LOW"]
    else:
        icon, pc = "[>>]", TEXT_PRI

    pdf.set_xy(17, y_hdr + 1.5)
    pdf.set_text_color(*pc)
    pdf.set_font("Courier", style="B", size=8)
    path_str = icon + "  " + result.filepath
    if len(path_str) > 70:
        path_str = path_str[:67] + "..."
    super(KaananPDF, pdf).cell(130, 6, _s(path_str))

    if result.error:
        status, sc = "SCAN ERROR", SEVERITY_RGB["CRITICAL"]
    elif not result.vulnerabilities:
        status, sc = "No issues found", SEVERITY_RGB["LOW"]
    else:
        counts = Counter(v.severity for v in result.vulnerabilities)
        parts  = [f"{counts[s]}{s[0]}" for s in SEVERITY_ORDER if counts.get(s)]
        status = "  ".join(parts) + f"   {len(result.vulnerabilities)} issue(s)"
        sc     = TEXT_SEC

    pdf.set_xy(15, y_hdr + 1.5)
    pdf.set_text_color(*sc)
    pdf.set_font("Helvetica", size=7)
    super(KaananPDF, pdf).cell(W - 2, 6, _s(status), align="R")
    pdf.set_y(y_hdr + 11)

    if result.error:
        pdf.set_x(17)
        pdf.set_text_color(*SEVERITY_RGB["HIGH"])
        pdf.set_font("Helvetica", size=8)
        pdf.multi_cell(W - 4, 5, result.error[:300],
                       new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)
        return

    if not result.vulnerabilities:
        pdf.ln(3)
        return

    sorted_vulns = sorted(
        result.vulnerabilities,
        key=lambda v: SEVERITY_ORDER.index(v.severity)
        if v.severity in SEVERITY_ORDER else 99,
    )

    for vuln in sorted_vulns:
        # Estimate card height
        desc_h   = max(1, len(vuln.description) // 88 + 1) * 4.5
        impact_h = max(1, len(vuln.impact)      // 88 + 1) * 4.5 if vuln.impact else 0
        fix_h    = max(1, len(vuln.remediation) // 88 + 1) * 4.5
        snip_h   = 7 * 4.2 + 4 + 4  # ~7 snippet lines
        needed   = 16 + desc_h + impact_h + fix_h + snip_h + 14

        if pdf.get_y() + needed > 265:
            pdf.new_page()

        sev_c  = SEVERITY_RGB.get(vuln.severity, TEXT_PRI)
        sev_bg = SEVERITY_BG.get(vuln.severity, (245, 245, 245))
        y_card = pdf.get_y()

        # Card border
        pdf.set_draw_color(*BORDER)
        pdf.bordered_rect(17, y_card, W - 4, needed, BG_CARD, BORDER)
        # Left severity accent
        pdf.fill_rect(17, y_card, 3, needed, sev_c)

        # ── Row 1: Badge | Type | Line ────────────────────────────────
        badge_w = 22
        pdf.fill_rect(22, y_card + 3, badge_w, 5.5, sev_c)
        pdf.set_xy(22, y_card + 3)
        pdf.set_text_color(*WHITE)
        pdf.set_font("Helvetica", style="B", size=7)
        super(KaananPDF, pdf).cell(badge_w, 5.5, vuln.severity, align="C")

        pdf.set_xy(46, y_card + 3)
        pdf.set_text_color(*TEXT_PRI)
        pdf.set_font("Helvetica", style="B", size=10)
        super(KaananPDF, pdf).cell(100, 5.5, vuln.type)

        display_line = vuln.verified_line or vuln.line
        if display_line:
            pdf.set_xy(162, y_card + 3)
            pdf.set_text_color(*TEXT_SEC)
            pdf.set_font("Helvetica", size=7)
            super(KaananPDF, pdf).cell(28, 5.5,
                f"Line {display_line}", align="R")

        # ── Row 2: CWE + OWASP tags ───────────────────────────────────
        tag_y = y_card + 10
        tx    = 22.0
        if vuln.cwe:
            tw = pdf.inline_tag(vuln.cwe, (67, 56, 202), (237, 233, 254), tx, tag_y)
            tx += tw
        if vuln.owasp:
            pdf.inline_tag(vuln.owasp[:35], (15, 23, 42), TAG_BG, tx, tag_y)

        pdf.set_y(tag_y + 7)

        # ── Description ───────────────────────────────────────────────
        pdf.set_x(22)
        pdf.set_text_color(*TEXT_SEC)
        pdf.set_font("Helvetica", style="B", size=7)
        super(KaananPDF, pdf).cell(16, 4.5, "Issue:")
        pdf.set_xy(38, pdf.get_y())
        pdf.set_text_color(*TEXT_PRI)
        pdf.set_font("Helvetica", size=8)
        pdf.multi_cell(W - 24, 4.5, vuln.description,
                       new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(1.5)

        # ── Impact ────────────────────────────────────────────────────
        if vuln.impact:
            imp_y = pdf.get_y()
            imp_h_est = max(1, len(vuln.impact) // 88 + 1) * 4.5 + 6
            pdf.bordered_rect(22, imp_y, W - 10, imp_h_est, BG_IMPACT,
                               (191, 219, 254))
            pdf.fill_rect(22, imp_y, 2.5, imp_h_est, TEXT_IMP)
            pdf.set_xy(27, imp_y + 1.5)
            pdf.set_text_color(*TEXT_SEC)
            pdf.set_font("Helvetica", style="B", size=7)
            super(KaananPDF, pdf).cell(14, 4.5, "Impact:")
            pdf.set_xy(41, imp_y + 1.5)
            pdf.set_text_color(*TEXT_IMP)
            pdf.set_font("Helvetica", size=8)
            pdf.multi_cell(W - 28, 4.5, vuln.impact,
                           new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(1.5)

        # ── Code snippet ──────────────────────────────────────────────
        _render_snippet(pdf, vuln, result.source_lines)

        # ── Remediation ───────────────────────────────────────────────
        fix_y   = pdf.get_y() + 1
        fix_est = max(1, len(vuln.remediation) // 88 + 1) * 4.5 + 6
        pdf.bordered_rect(22, fix_y, W - 10, fix_est, BG_FIX, (187, 247, 208))
        pdf.fill_rect(22, fix_y, 2.5, fix_est, TEXT_FIX)
        pdf.set_xy(27, fix_y + 1.5)
        pdf.set_text_color(*TEXT_SEC)
        pdf.set_font("Helvetica", style="B", size=7)
        super(KaananPDF, pdf).cell(12, 4.5, "Fix:")
        pdf.set_xy(39, fix_y + 1.5)
        pdf.set_text_color(*TEXT_FIX)
        pdf.set_font("Helvetica", size=8)
        pdf.multi_cell(W - 26, 4.5, vuln.remediation,
                       new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.set_y(pdf.get_y() + 6)

    pdf.ln(3)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def generate_report(results: list[FileResult], output_path: Path) -> None:
    pdf  = KaananPDF(logo_path=_find_logo())
    pdf.new_page()

    _render_summary(pdf, results)

    pdf.set_text_color(*TEXT_SEC)
    pdf.set_font("Helvetica", style="B", size=8)
    pdf.cell(0, 5, "FINDINGS BY FILE",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    def sort_key(r: FileResult):
        if r.error:
            return (-1, 0)
        if not r.vulnerabilities:
            return (99, 0)
        worst = min(
            SEVERITY_ORDER.index(v.severity)
            for v in r.vulnerabilities
            if v.severity in SEVERITY_ORDER
        )
        return (worst, -len(r.vulnerabilities))

    for result in sorted(results, key=sort_key):
        _render_file_block(pdf, result)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(output_path))