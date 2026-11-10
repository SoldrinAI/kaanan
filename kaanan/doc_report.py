from __future__ import annotations

from datetime import datetime
from pathlib import Path

from fpdf import XPos, YPos

from kaanan.doc_scanner import (
    DocFileResult, BackendEndpoint, FrontendDoc,
    FrontendElement, UserFlow, APIBinding,
)
from kaanan.report import (
    KaananPDF, _s,
    WHITE, BG_PAGE, BG_CARD, BG_HEADER, BORDER,
    TEXT_PRI, TEXT_SEC, TEXT_FIX, BG_FIX, BG_IMPACT, TEXT_IMP,
    TAG_BG,
)


# ---------------------------------------------------------------------------
# Palette extensions for UAT report
# ---------------------------------------------------------------------------

# HTTP method badge colours
_METHOD_RGB: dict[str, tuple] = {
    "GET":     (21,  128, 61),
    "POST":    (29,  78,  216),
    "PUT":     (194, 65,  12),
    "DELETE":  (185, 28,  28),
    "PATCH":   (133, 77,  14),
    "HEAD":    (100, 116, 139),
    "OPTIONS": (100, 116, 139),
}
_METHOD_BG: dict[str, tuple] = {
    "GET":     (220, 252, 231),
    "POST":    (219, 234, 254),
    "PUT":     (255, 237, 213),
    "DELETE":  (254, 226, 226),
    "PATCH":   (254, 249, 195),
    "HEAD":    (241, 245, 249),
    "OPTIONS": (241, 245, 249),
}
_METHOD_RGB_DEFAULT = (100, 116, 139)
_METHOD_BG_DEFAULT  = (241, 245, 249)

# Classification stat-box colours
_CLASS_RGB: dict[str, tuple] = {
    "Backend":       (29,  78,  216),
    "Frontend-Web":  (109, 40,  217),
    "Frontend-App":  (157, 23,  77),
    "Non-Code":      (100, 116, 139),
    "Error":         (185, 28,  28),
}
_CLASS_BG: dict[str, tuple] = {
    "Backend":       (219, 234, 254),
    "Frontend-Web":  (237, 233, 254),
    "Frontend-App":  (252, 231, 243),
    "Non-Code":      (241, 245, 249),
    "Error":         (254, 226, 226),
}

# Section-specific backgrounds
BG_CURL  = (30,  41,  59)    # dark navy — terminal / curl block
FG_CURL  = (134, 239, 172)   # green monospace text
BG_FLOW  = (240, 249, 255)   # light sky — user flows
FG_FLOW  = (3,   105, 161)
ACC_FLOW = (56,  189, 248)   # flow accent bar
BG_BIND  = (240, 253, 244)   # mint — API bindings
FG_BIND  = (22,  101, 52)
ACC_BIND = (74,  222, 128)   # binding accent bar
BG_ELEM  = (250, 250, 255)   # off-white — elements table
BG_AUTH  = (255, 251, 235)   # warm yellow — auth row
FG_AUTH  = (120, 53,  15)
BG_REQ   = (240, 253, 244)
BG_RES   = (239, 246, 255)


# ---------------------------------------------------------------------------
# DocPDF — KaananPDF subclass with UAT-specific header / footer
# ---------------------------------------------------------------------------

class DocPDF(KaananPDF):
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
        super(KaananPDF, self).cell(0, 6, "UAT Documentation Report", align="R")
        self.set_y(22)

    def footer(self):
        self.set_y(-13)
        self.fill_rect(0, self.get_y() - 1, 210, 15, BG_HEADER)
        self.set_text_color(100, 116, 139)
        self.set_font("Helvetica", size=7)
        super(KaananPDF, self).cell(
            0, 10,
            f"Kaanan.ai  |  UAT Documentation  |  Page {self.page_no()}  |  "
            "For QA engineers and UAT testers",
            align="C",
        )


# ---------------------------------------------------------------------------
# Logo resolution helper (mirrors report.py's approach)
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
# Summary page
# ---------------------------------------------------------------------------

def _render_doc_summary(pdf: DocPDF, results: list[DocFileResult]) -> None:
    from collections import Counter
    now    = datetime.now().strftime("%B %d, %Y  %H:%M")
    counts = Counter(r.classification for r in results)

    total_endpoints = sum(len(r.endpoints) for r in results)
    total_screens   = sum(1 for r in results if r.frontend is not None)

    W = 180

    # Title
    pdf.set_text_color(*TEXT_PRI)
    pdf.set_font("Helvetica", style="B", size=20)
    pdf.cell(0, 11, "UAT Documentation Report",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_text_color(*TEXT_SEC)
    pdf.set_font("Helvetica", size=9)
    pdf.cell(
        0, 6,
        f"Generated on {now}   |   {len(results)} file(s) analysed",
        new_x=XPos.LMARGIN, new_y=YPos.NEXT,
    )
    pdf.ln(4)

    # Divider
    pdf.set_draw_color(*BORDER)
    pdf.line(15, pdf.get_y(), 195, pdf.get_y())
    pdf.ln(5)

    # Classification stat boxes (4 columns)
    labels = ["Backend", "Frontend-Web", "Frontend-App", "Non-Code"]
    cw     = W / 4
    y0     = pdf.get_y()
    for i, label in enumerate(labels):
        x   = 15 + i * cw
        cnt = counts.get(label, 0)
        c   = _CLASS_RGB.get(label, (100, 116, 139))
        bg  = _CLASS_BG.get(label,  (241, 245, 249))
        pdf.bordered_rect(x, y0, cw - 3, 22, bg, BORDER)
        pdf.fill_rect(x, y0, cw - 3, 2.5, c)
        pdf.set_xy(x, y0 + 3)
        pdf.set_text_color(*c)
        pdf.set_font("Helvetica", style="B", size=20)
        super(KaananPDF, pdf).cell(cw - 3, 9, str(cnt), align="C")
        pdf.set_xy(x, y0 + 13)
        pdf.set_text_color(*TEXT_SEC)
        pdf.set_font("Helvetica", style="B", size=6)
        super(KaananPDF, pdf).cell(cw - 3, 6, label.upper(), align="C")

    pdf.set_y(y0 + 26)
    pdf.set_text_color(*TEXT_SEC)
    pdf.set_font("Helvetica", size=8)
    stats = (
        f"Total endpoints documented: {total_endpoints}      "
        f"UI screens documented: {total_screens}      "
        f"Errors: {counts.get('Error', 0)}"
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
    super(KaananPDF, pdf).cell(
        0, 4,
        f"Model: {model_name}      "
        f"Prompt: {total_prompt:,}      "
        f"Completion: {total_completion:,}      "
        f"Total: {total_tokens:,} tokens",
        align="R",
    )
    pdf.set_y(ty + 13)

    pdf.set_draw_color(*BORDER)
    pdf.line(15, pdf.get_y(), 195, pdf.get_y())
    pdf.ln(5)


# ---------------------------------------------------------------------------
# File header bar (shared between backend and frontend blocks)
# ---------------------------------------------------------------------------

def _render_file_header(pdf: DocPDF, result: DocFileResult) -> None:
    W     = 180
    y_hdr = pdf.get_y()
    pdf.bordered_rect(15, y_hdr, W, 9, (238, 242, 255), BORDER)

    # Icon + filepath
    icon_color = (
        _CLASS_RGB.get("Error",   TEXT_PRI) if result.classification == "Error"
        else _CLASS_RGB.get(result.classification, TEXT_PRI)
    )
    icon = "[!] " if result.classification == "Error" else "[>>]"
    path_str = icon + "  " + result.filepath
    if len(path_str) > 70:
        path_str = path_str[:67] + "..."

    pdf.set_xy(17, y_hdr + 1.5)
    pdf.set_text_color(*icon_color)
    pdf.set_font("Courier", style="B", size=8)
    super(KaananPDF, pdf).cell(130, 6, _s(path_str))

    # Classification badge (right-aligned)
    badge_text = result.classification
    pdf.set_xy(15, y_hdr + 1.5)
    pdf.set_text_color(*TEXT_SEC)
    pdf.set_font("Helvetica", size=7)
    super(KaananPDF, pdf).cell(W - 2, 6, _s(badge_text), align="R")

    pdf.set_y(y_hdr + 11)


# ---------------------------------------------------------------------------
# Curl block renderer
# ---------------------------------------------------------------------------

def _render_curl_block(pdf: DocPDF, curl: str) -> None:
    if not curl.strip():
        return

    LINE_H = 4.5
    x, w   = 27, 163

    lines = []
    # Wrap long curl commands at word boundaries
    words = curl.strip().split()
    current = ""
    for word in words:
        test = (current + " " + word).strip()
        pdf.set_font("Courier", size=6.5)
        if pdf.get_string_width(_s(test)) > w - 8:
            if current:
                lines.append(current)
            current = word
        else:
            current = test
    if current:
        lines.append(current)

    if not lines:
        return

    total_h = len(lines) * LINE_H + 6
    if pdf.get_y() + total_h > 272:
        pdf.new_page()

    y0 = pdf.get_y()
    # Dark terminal background
    pdf.fill_rect(x, y0, w, total_h, BG_CURL)
    pdf.set_draw_color(55, 65, 81)
    pdf.rect(x, y0, w, total_h, style="D")

    # "$ curl" prompt label
    pdf.set_xy(x + 2, y0 + 1.5)
    pdf.set_text_color(156, 163, 175)
    pdf.set_font("Courier", style="B", size=6)
    super(KaananPDF, pdf).cell(12, LINE_H, "cURL")

    y = y0 + 2
    for line in lines:
        pdf.set_xy(x + 3, y)
        pdf.set_text_color(*FG_CURL)
        pdf.set_font("Courier", size=6.5)
        super(KaananPDF, pdf).cell(w - 6, LINE_H, _s(line))
        y += LINE_H

    pdf.set_y(y0 + total_h + 3)


# ---------------------------------------------------------------------------
# Backend endpoint card
# ---------------------------------------------------------------------------

def _render_endpoint_card(pdf: DocPDF, ep: BackendEndpoint) -> None:
    W      = 170
    x_card = 20
    m_rgb  = _METHOD_RGB.get(ep.method, _METHOD_RGB_DEFAULT)
    m_bg   = _METHOD_BG.get(ep.method,  _METHOD_BG_DEFAULT)

    # Rough height estimate
    auth_h    = 6
    payload_h = max(1, len(ep.request_payload)    // 90 + 1) * 4.5 + 8
    resp_h    = max(1, len(ep.response_scenarios) // 90 + 1) * 4.5 + 8
    curl_lines = max(1, len(ep.curl_command) // 80 + 1)
    curl_h    = curl_lines * 4.5 + 9
    needed    = 14 + auth_h + payload_h + resp_h + curl_h + 6

    if pdf.get_y() + needed > 265:
        pdf.new_page()

    y_card = pdf.get_y()

    # Card border + left accent bar coloured by method
    pdf.bordered_rect(x_card, y_card, W, needed, BG_CARD, BORDER)
    pdf.fill_rect(x_card, y_card, 3, needed, m_rgb)

    # ── Method badge + path ─────────────────────────────────────────────
    badge_w = 20
    pdf.fill_rect(x_card + 5, y_card + 3, badge_w, 6, m_bg)
    pdf.set_draw_color(*m_rgb)
    pdf.rect(x_card + 5, y_card + 3, badge_w, 6, style="D")
    pdf.set_xy(x_card + 5, y_card + 3)
    pdf.set_text_color(*m_rgb)
    pdf.set_font("Courier", style="B", size=7)
    super(KaananPDF, pdf).cell(badge_w, 6, ep.method, align="C")

    pdf.set_xy(x_card + 27, y_card + 3)
    pdf.set_text_color(*TEXT_PRI)
    pdf.set_font("Courier", style="B", size=9)
    path_display = ep.path if len(ep.path) <= 55 else ep.path[:52] + "..."
    super(KaananPDF, pdf).cell(W - 32, 6, _s(path_display))

    pdf.set_y(y_card + 11)

    # ── Authentication ─────────────────────────────────────────────────
    auth_y = pdf.get_y()
    pdf.bordered_rect(x_card + 4, auth_y, W - 8, auth_h + 1, BG_AUTH, (253, 230, 138))
    pdf.set_xy(x_card + 7, auth_y + 1)
    pdf.set_text_color(120, 53, 15)
    pdf.set_font("Helvetica", style="B", size=7)
    super(KaananPDF, pdf).cell(22, 4, "Auth:")
    pdf.set_xy(x_card + 29, auth_y + 1)
    pdf.set_font("Helvetica", size=7)
    super(KaananPDF, pdf).cell(W - 36, 4, _s(ep.authentication[:80]))
    pdf.set_y(auth_y + auth_h + 2)

    # ── Request payload ────────────────────────────────────────────────
    req_y = pdf.get_y()
    pdf.set_xy(x_card + 7, req_y)
    pdf.set_text_color(*TEXT_SEC)
    pdf.set_font("Helvetica", style="B", size=7)
    super(KaananPDF, pdf).cell(0, 5, "Request Payload", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    req_body_y = pdf.get_y()
    pdf.bordered_rect(x_card + 4, req_body_y, W - 8,
                      payload_h - 5, BG_REQ, (187, 247, 208))
    pdf.fill_rect(x_card + 4, req_body_y, 2, payload_h - 5, TEXT_FIX)
    pdf.set_xy(x_card + 8, req_body_y + 1)
    pdf.set_text_color(*TEXT_PRI)
    pdf.set_font("Helvetica", size=7.5)
    pdf.multi_cell(
        W - 14, 4.5, ep.request_payload,
        new_x=XPos.LMARGIN, new_y=YPos.NEXT,
    )
    pdf.ln(2)

    # ── Response scenarios ─────────────────────────────────────────────
    res_y = pdf.get_y()
    pdf.set_xy(x_card + 7, res_y)
    pdf.set_text_color(*TEXT_SEC)
    pdf.set_font("Helvetica", style="B", size=7)
    super(KaananPDF, pdf).cell(0, 5, "Response Scenarios", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    res_body_y = pdf.get_y()
    pdf.bordered_rect(x_card + 4, res_body_y, W - 8,
                      resp_h - 5, BG_IMPACT, (191, 219, 254))
    pdf.fill_rect(x_card + 4, res_body_y, 2, resp_h - 5, TEXT_IMP)
    pdf.set_xy(x_card + 8, res_body_y + 1)
    pdf.set_text_color(*TEXT_PRI)
    pdf.set_font("Helvetica", size=7.5)
    pdf.multi_cell(
        W - 14, 4.5, ep.response_scenarios,
        new_x=XPos.LMARGIN, new_y=YPos.NEXT,
    )
    pdf.ln(2)

    # ── cURL command ───────────────────────────────────────────────────
    pdf.set_x(x_card + 7)
    pdf.set_text_color(*TEXT_SEC)
    pdf.set_font("Helvetica", style="B", size=7)
    super(KaananPDF, pdf).cell(0, 5, "Executable cURL", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    _render_curl_block(pdf, ep.curl_command)

    pdf.set_y(y_card + needed + 3)


# ---------------------------------------------------------------------------
# Frontend screen block
# ---------------------------------------------------------------------------

def _render_frontend_block(pdf: DocPDF, doc: FrontendDoc) -> None:
    W      = 170
    x_card = 20

    # ── Screen identity banner ─────────────────────────────────────────
    screen_h = 10
    if pdf.get_y() + screen_h > 272:
        pdf.new_page()

    sy = pdf.get_y()
    pdf.bordered_rect(x_card, sy, W, screen_h, (245, 243, 255), (196, 181, 253))
    pdf.fill_rect(x_card, sy, 3, screen_h, (109, 40, 217))
    pdf.set_xy(x_card + 7, sy + 2)
    pdf.set_text_color(109, 40, 217)
    pdf.set_font("Helvetica", style="B", size=9)
    super(KaananPDF, pdf).cell(80, 6, _s(doc.screen_name))
    pdf.set_xy(x_card + 90, sy + 2)
    pdf.set_text_color(*TEXT_SEC)
    pdf.set_font("Helvetica", size=7)
    super(KaananPDF, pdf).cell(W - 95, 6, _s(f"Route: {doc.route}"), align="R")
    pdf.set_y(sy + screen_h + 3)

    # ── Testable elements ──────────────────────────────────────────────
    if doc.elements:
        if pdf.get_y() + 10 > 272:
            pdf.new_page()

        pdf.set_x(x_card)
        pdf.set_text_color(*TEXT_SEC)
        pdf.set_font("Helvetica", style="B", size=7)
        super(KaananPDF, pdf).cell(
            0, 5, "TESTABLE ELEMENTS & SELECTORS",
            new_x=XPos.LMARGIN, new_y=YPos.NEXT,
        )

        for elem in doc.elements:
            row_h = max(1, (len(elem.validation) // 70 + 1)) * 4 + 8

            if pdf.get_y() + row_h > 272:
                pdf.new_page()

            ry = pdf.get_y()
            pdf.bordered_rect(x_card + 3, ry, W - 6, row_h, BG_ELEM, BORDER)
            pdf.fill_rect(x_card + 3, ry, 2, row_h, (109, 40, 217))

            # Element name
            pdf.set_xy(x_card + 7, ry + 2)
            pdf.set_text_color(*TEXT_PRI)
            pdf.set_font("Helvetica", style="B", size=7.5)
            name_display = elem.name if len(elem.name) <= 30 else elem.name[:27] + "..."
            super(KaananPDF, pdf).cell(45, 4, _s(name_display))

            # Selector type + value
            pdf.set_xy(x_card + 52, ry + 2)
            pdf.set_text_color(109, 40, 217)
            pdf.set_font("Courier", size=7)
            sel_str = f"{elem.selector_type} = {elem.selector_value}"
            if len(sel_str) > 55:
                sel_str = sel_str[:52] + "..."
            super(KaananPDF, pdf).cell(W - 60, 4, _s(sel_str))

            # Validation
            pdf.set_xy(x_card + 7, ry + 6)
            pdf.set_text_color(*TEXT_SEC)
            pdf.set_font("Helvetica", size=7)
            pdf.multi_cell(
                W - 14, 3.8, _s(f"Validation: {elem.validation}"),
                new_x=XPos.LMARGIN, new_y=YPos.NEXT,
            )
            pdf.set_y(ry + row_h + 2)

        pdf.ln(2)

    # ── User flows ─────────────────────────────────────────────────────
    if doc.user_flows:
        if pdf.get_y() + 10 > 272:
            pdf.new_page()

        pdf.set_x(x_card)
        pdf.set_text_color(*TEXT_SEC)
        pdf.set_font("Helvetica", style="B", size=7)
        super(KaananPDF, pdf).cell(
            0, 5, "USER FLOWS & UI STATES",
            new_x=XPos.LMARGIN, new_y=YPos.NEXT,
        )

        for flow in doc.user_flows:
            trigger_h = max(1, len(flow.trigger)         // 70 + 1) * 4
            state_h   = max(1, len(flow.resulting_state) // 70 + 1) * 4
            row_h     = trigger_h + state_h + 9

            if pdf.get_y() + row_h > 272:
                pdf.new_page()

            fy = pdf.get_y()
            pdf.bordered_rect(x_card + 3, fy, W - 6, row_h, BG_FLOW, (186, 230, 253))
            pdf.fill_rect(x_card + 3, fy, 2, row_h, ACC_FLOW)

            pdf.set_xy(x_card + 7, fy + 2)
            pdf.set_text_color(*TEXT_SEC)
            pdf.set_font("Helvetica", style="B", size=6.5)
            super(KaananPDF, pdf).cell(20, 4, "Trigger:")
            pdf.set_xy(x_card + 27, fy + 2)
            pdf.set_text_color(*FG_FLOW)
            pdf.set_font("Helvetica", size=7.5)
            pdf.multi_cell(
                W - 30, 4, flow.trigger,
                new_x=XPos.LMARGIN, new_y=YPos.NEXT,
            )

            sep_y = fy + trigger_h + 4
            pdf.set_draw_color(186, 230, 253)
            pdf.line(x_card + 7, sep_y, x_card + W - 7, sep_y)

            pdf.set_xy(x_card + 7, sep_y + 1)
            pdf.set_text_color(*TEXT_SEC)
            pdf.set_font("Helvetica", style="B", size=6.5)
            super(KaananPDF, pdf).cell(30, 4, "Resulting State:")
            pdf.set_xy(x_card + 37, sep_y + 1)
            pdf.set_text_color(*TEXT_PRI)
            pdf.set_font("Helvetica", size=7.5)
            pdf.multi_cell(
                W - 40, 4, flow.resulting_state,
                new_x=XPos.LMARGIN, new_y=YPos.NEXT,
            )
            pdf.set_y(fy + row_h + 2)

        pdf.ln(2)

    # ── API bindings ───────────────────────────────────────────────────
    if doc.api_bindings:
        if pdf.get_y() + 10 > 272:
            pdf.new_page()

        pdf.set_x(x_card)
        pdf.set_text_color(*TEXT_SEC)
        pdf.set_font("Helvetica", style="B", size=7)
        super(KaananPDF, pdf).cell(
            0, 5, "API BINDINGS",
            new_x=XPos.LMARGIN, new_y=YPos.NEXT,
        )

        for binding in doc.api_bindings:
            action_h = max(1, len(binding.action)          // 60 + 1) * 4
            ep_h     = max(1, len(binding.target_endpoint) // 60 + 1) * 4
            row_h    = action_h + ep_h + 8

            if pdf.get_y() + row_h > 272:
                pdf.new_page()

            by = pdf.get_y()
            pdf.bordered_rect(x_card + 3, by, W - 6, row_h, BG_BIND, (187, 247, 208))
            pdf.fill_rect(x_card + 3, by, 2, row_h, ACC_BIND)

            pdf.set_xy(x_card + 7, by + 2)
            pdf.set_text_color(*TEXT_SEC)
            pdf.set_font("Helvetica", style="B", size=6.5)
            super(KaananPDF, pdf).cell(18, 4, "Action:")
            pdf.set_xy(x_card + 25, by + 2)
            pdf.set_text_color(*TEXT_PRI)
            pdf.set_font("Helvetica", size=7.5)
            pdf.multi_cell(
                W - 28, 4, binding.action,
                new_x=XPos.LMARGIN, new_y=YPos.NEXT,
            )

            arrow_y = by + action_h + 3
            pdf.set_xy(x_card + 7, arrow_y)
            pdf.set_text_color(*TEXT_SEC)
            pdf.set_font("Helvetica", style="B", size=6.5)
            super(KaananPDF, pdf).cell(28, 4, "Target Endpoint:")
            pdf.set_xy(x_card + 35, arrow_y)
            pdf.set_text_color(*FG_BIND)
            pdf.set_font("Courier", style="B", size=7.5)
            pdf.multi_cell(
                W - 38, 4, binding.target_endpoint,
                new_x=XPos.LMARGIN, new_y=YPos.NEXT,
            )
            pdf.set_y(by + row_h + 2)

        pdf.ln(2)


# ---------------------------------------------------------------------------
# Full file block dispatcher
# ---------------------------------------------------------------------------

def _render_doc_file_block(pdf: DocPDF, result: DocFileResult) -> None:
    if pdf.get_y() > 255:
        pdf.new_page()

    _render_file_header(pdf, result)

    if result.classification == "Error":
        pdf.set_x(17)
        pdf.set_text_color(185, 28, 28)
        pdf.set_font("Helvetica", size=8)
        pdf.multi_cell(176, 5, result.error or "Unknown error",
                       new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)
        return

    if result.classification == "Non-Code":
        pdf.set_x(17)
        pdf.set_text_color(*TEXT_SEC)
        pdf.set_font("Helvetica", style="I", size=8)
        super(KaananPDF, pdf).cell(
            0, 6,
            "File type not applicable for UAT code analysis.",
            new_x=XPos.LMARGIN, new_y=YPos.NEXT,
        )
        pdf.ln(3)
        return

    if result.classification == "Backend":
        if not result.endpoints:
            pdf.set_x(17)
            pdf.set_text_color(*TEXT_SEC)
            pdf.set_font("Helvetica", style="I", size=8)
            super(KaananPDF, pdf).cell(
                0, 6,
                "Backend file - no route handlers detected (utility / model / config module).",
                new_x=XPos.LMARGIN, new_y=YPos.NEXT,
            )
            pdf.ln(3)
            return
        for ep in result.endpoints:
            _render_endpoint_card(pdf, ep)
        return

    # Frontend-Web / Frontend-App
    if result.frontend:
        _render_frontend_block(pdf, result.frontend)
    pdf.ln(3)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def generate_doc_report(results: list[DocFileResult], output_path: Path) -> None:
    logo = _find_logo()
    pdf  = DocPDF(logo_path=logo)
    pdf.new_page()

    _render_doc_summary(pdf, results)

    pdf.set_text_color(*TEXT_SEC)
    pdf.set_font("Helvetica", style="B", size=8)
    pdf.cell(0, 5, "FILE DOCUMENTATION", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    # Sort: errors first, then Backend, Frontend-Web, Frontend-App, Non-Code
    _order = {"Error": 0, "Backend": 1, "Frontend-Web": 2, "Frontend-App": 3, "Non-Code": 4}

    def _sort_key(r: DocFileResult) -> tuple:
        return (_order.get(r.classification, 5), r.filepath)

    for result in sorted(results, key=_sort_key):
        _render_doc_file_block(pdf, result)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(output_path))