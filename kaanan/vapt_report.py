"""vapt_report.py — Kaanan VAPT PDF Report Generator"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Optional

from fpdf import FPDF, XPos, YPos

from kaanan.vapt_scanner import (
    AttackAttempt, VaptEndpointResult, VaptFinding, VaptScanResult,
)
from kaanan.report import KaananPDF, _s, _find_logo


# ──────────────────────────────────────────────────────────────────────────────
# Colour palette
# ──────────────────────────────────────────────────────────────────────────────

WHITE       = (255, 255, 255)
BG_PAGE     = (248, 250, 252)
BG_CARD     = (255, 255, 255)
BG_HEADER   = (15,  23,  42)
BORDER      = (226, 232, 240)
TEXT_PRI    = (15,  23,  42)
TEXT_SEC    = (100, 116, 139)
TEXT_FIX    = (22,  101, 52)
TEXT_IMP    = (29,  78,  216)
BG_FIX      = (240, 253, 244)
BG_IMPACT   = (239, 246, 255)
BG_EVIDENCE = (255, 251, 235)
TEXT_EVID   = (120, 53,  15)
ACC_EVID    = (245, 158, 11)
TAG_BG      = (241, 245, 249)

# Attack log entry states
BG_CONFIRMED   = (254, 226, 226)   # red tint — confirmed finding
BG_TESTED      = (248, 250, 252)   # neutral — tested, not confirmed
BORDER_CONF    = (185, 28,  28)
BORDER_TESTED  = (226, 232, 240)
ACC_CONFIRMED  = (185, 28,  28)
ACC_TESTED     = (148, 163, 184)
TEXT_CONFIRMED = (185, 28,  28)
TEXT_TESTED    = (100, 116, 139)

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
_RISK_LABEL = {
    "CRITICAL": "CRITICAL RISK",
    "HIGH":     "HIGH RISK",
    "MEDIUM":   "MEDIUM RISK",
    "LOW":      "LOW RISK",
}
_METHOD_RGB: dict[str, tuple] = {
    "GET":    (21,  128, 61),
    "POST":   (29,  78,  216),
    "PUT":    (194, 65,  12),
    "DELETE": (185, 28,  28),
    "PATCH":  (133, 77,  14),
}
_METHOD_BG: dict[str, tuple] = {
    "GET":    (220, 252, 231),
    "POST":   (219, 234, 254),
    "PUT":    (255, 237, 213),
    "DELETE": (254, 226, 226),
    "PATCH":  (254, 249, 195),
}
_METHOD_RGB_DEF = (100, 116, 139)
_METHOD_BG_DEF  = (241, 245, 249)


# ──────────────────────────────────────────────────────────────────────────────
# VaptPDF subclass
# ──────────────────────────────────────────────────────────────────────────────

class VaptPDF(KaananPDF):
    def header(self) -> None:
        self.fill_rect(0, 0, 210, 18, BG_HEADER)
        logo = _find_logo()
        if logo and logo.exists():
            try:
                self.image(str(logo), x=14, y=3, h=12)
            except Exception:
                pass
        self.set_xy(0, 5)
        self.set_text_color(148, 163, 184)
        self.set_font("Helvetica", size=8)
        super(KaananPDF, self).cell(0, 6, "VAPT Assessment Report", align="R")
        self.set_y(22)

    def footer(self) -> None:
        self.set_y(-13)
        self.fill_rect(0, self.get_y() - 1, 210, 15, BG_HEADER)
        self.set_text_color(100, 116, 139)
        self.set_font("Helvetica", size=7)
        super(KaananPDF, self).cell(
            0, 10,
            f"Kaanan.ai  |  Confidential  |  Page {self.page_no()}  |  "
            "Results require professional verification before remediation",
            align="C",
        )


# ──────────────────────────────────────────────────────────────────────────────
# Summary page
# ──────────────────────────────────────────────────────────────────────────────

def _render_vapt_summary(pdf: VaptPDF, result: VaptScanResult) -> None:
    W = 180

    pdf.set_text_color(*TEXT_PRI)
    pdf.set_font("Helvetica", style="B", size=22)
    pdf.cell(0, 10, "VAPT Assessment Report",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", size=9)
    pdf.set_text_color(*TEXT_SEC)
    pdf.cell(0, 5,
             "Vulnerability Assessment and Penetration Testing — Live Endpoint Analysis",
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    # Target info box
    info_y = pdf.get_y()
    pdf.bordered_rect(15, info_y, W, 24, (238, 242, 255), BORDER)
    pdf.fill_rect(15, info_y, 3, 24, (99, 102, 241))

    pdf.set_xy(21, info_y + 2)
    pdf.set_text_color(*TEXT_SEC)
    pdf.set_font("Helvetica", style="B", size=7)
    super(KaananPDF, pdf).cell(25, 4, "Target URL")
    pdf.set_text_color(*TEXT_PRI)
    pdf.set_font("Helvetica", size=8)
    super(KaananPDF, pdf).cell(75, 4, _s(result.target_url))

    pdf.set_xy(130, info_y + 2)
    pdf.set_text_color(*TEXT_SEC)
    pdf.set_font("Helvetica", style="B", size=7)
    super(KaananPDF, pdf).cell(20, 4, "Entry Point")
    pdf.set_text_color(*TEXT_PRI)
    pdf.set_font("Helvetica", size=8)
    super(KaananPDF, pdf).cell(50, 4, _s(result.target_file))

    pdf.set_xy(21, info_y + 8)
    pdf.set_text_color(*TEXT_SEC)
    pdf.set_font("Helvetica", style="B", size=7)
    super(KaananPDF, pdf).cell(25, 4, "Scan Date")
    pdf.set_text_color(*TEXT_PRI)
    pdf.set_font("Helvetica", size=8)
    super(KaananPDF, pdf).cell(75, 4, _s(datetime.now().strftime("%Y-%m-%d %H:%M UTC")))

    pdf.set_xy(130, info_y + 8)
    pdf.set_text_color(*TEXT_SEC)
    pdf.set_font("Helvetica", style="B", size=7)
    super(KaananPDF, pdf).cell(20, 4, "Model")
    pdf.set_text_color(*TEXT_PRI)
    pdf.set_font("Helvetica", size=8)
    super(KaananPDF, pdf).cell(50, 4, _s(result.model))

    # Row 3: Auth status + SAST
    auth_label = ("YES — " + result.auth_endpoint) if result.authenticated else "NO"
    auth_col   = (21, 128, 61) if result.authenticated else (220, 38, 38)
    pdf.set_xy(21, info_y + 14)
    pdf.set_text_color(*TEXT_SEC)
    pdf.set_font("Helvetica", style="B", size=7)
    super(KaananPDF, pdf).cell(25, 4, "Auth")
    pdf.set_text_color(*auth_col)
    pdf.set_font("Helvetica", size=8)
    super(KaananPDF, pdf).cell(75, 4, _s(auth_label))

    sast_total = getattr(result, "sast_findings_total", 0)
    pdf.set_xy(130, info_y + 14)
    pdf.set_text_color(*TEXT_SEC)
    pdf.set_font("Helvetica", style="B", size=7)
    super(KaananPDF, pdf).cell(20, 4, "SAST Intelligence")
    pdf.set_text_color(*TEXT_PRI)
    pdf.set_font("Helvetica", size=8)
    sast_label = (
        f"{sast_total} finding(s) used to guide targeted attacks"
        if sast_total > 0 else "None — contextual analysis only"
    )
    super(KaananPDF, pdf).cell(50, 4, _s(sast_label))

    pdf.set_y(info_y + 28)

    # Stats grid
    all_findings = [f for ep in result.endpoint_results for f in ep.findings]
    sev_counts   = Counter(f.severity for f in all_findings)
    total_eps    = len(result.endpoint_results)
    total_attacks= sum(ep.attacks_fired for ep in result.endpoint_results)
    total_finds  = len(all_findings)
    unreachable  = sum(1 for ep in result.endpoint_results if ep.error)

    stats = [
        ("Endpoints",  str(total_eps),
         (99, 102, 241), (237, 233, 254)),
        ("Attacks",    str(total_attacks),
         (14, 116, 144), (207, 250, 254)),
        ("Findings",   str(total_finds),
         (185, 28,  28), (254, 226, 226)),
        ("CRITICAL",   str(sev_counts.get("CRITICAL", 0)),
         SEVERITY_RGB["CRITICAL"], SEVERITY_BG["CRITICAL"]),
        ("HIGH",       str(sev_counts.get("HIGH", 0)),
         SEVERITY_RGB["HIGH"],     SEVERITY_BG["HIGH"]),
        ("MED / LOW",
         f"{sev_counts.get('MEDIUM', 0)} / {sev_counts.get('LOW', 0)}",
         SEVERITY_RGB["MEDIUM"], SEVERITY_BG["MEDIUM"]),
    ]

    box_w  = W / len(stats)
    grid_y = pdf.get_y()
    for i, (label, value, fg, bg) in enumerate(stats):
        bx = 15 + i * box_w
        pdf.bordered_rect(bx, grid_y, box_w - 1, 18, bg, BORDER)
        pdf.set_xy(bx, grid_y + 2)
        pdf.set_text_color(*fg)
        pdf.set_font("Helvetica", style="B", size=14)
        super(KaananPDF, pdf).cell(box_w - 1, 8, value, align="C")
        pdf.set_xy(bx, grid_y + 11)
        pdf.set_text_color(*TEXT_SEC)
        pdf.set_font("Helvetica", size=6.5)
        super(KaananPDF, pdf).cell(box_w - 1, 4, label, align="C")

    pdf.set_y(grid_y + 22)

    # Overall risk badge
    worst_sev: Optional[str] = None
    for sev in SEVERITY_ORDER:
        if sev_counts.get(sev, 0) > 0:
            worst_sev = sev
            break

    risk_y     = pdf.get_y()
    risk_fg    = SEVERITY_RGB.get(worst_sev, TEXT_SEC) if worst_sev else TEXT_SEC
    risk_bg    = SEVERITY_BG.get(worst_sev, TAG_BG)    if worst_sev else TAG_BG
    risk_label = _RISK_LABEL.get(worst_sev, "INFORMATIONAL") if worst_sev else "CLEAN"

    pdf.bordered_rect(15, risk_y, W, 10, risk_bg, BORDER)
    pdf.fill_rect(15, risk_y, 3, 10, risk_fg)
    pdf.set_xy(21, risk_y + 2)
    pdf.set_text_color(*TEXT_SEC)
    pdf.set_font("Helvetica", style="B", size=7)
    super(KaananPDF, pdf).cell(30, 5, "Overall Risk")
    pdf.set_text_color(*risk_fg)
    pdf.set_font("Helvetica", style="B", size=9)
    summary_str = (
        f"{risk_label}  —  {total_finds} finding(s) confirmed across "
        f"{total_eps} endpoint(s)  |  {total_attacks} attack(s) fired"
    )
    if unreachable:
        summary_str += f"  |  {unreachable} unreachable"
    super(KaananPDF, pdf).cell(0, 5, _s(summary_str))
    pdf.set_y(risk_y + 14)

    # Token usage
    tok_y = pdf.get_y()
    pdf.bordered_rect(15, tok_y, W, 10, (248, 250, 252), BORDER)
    pdf.set_xy(17, tok_y + 1.5)
    pdf.set_text_color(*TEXT_SEC)
    pdf.set_font("Helvetica", style="B", size=7)
    super(KaananPDF, pdf).cell(30, 4, "TOKEN USAGE")
    pdf.set_font("Helvetica", size=7)
    tok_str = (
        f"Model: {result.model}      "
        f"Total VAPT tokens: {result.total_tokens_used:,}"
    )
    super(KaananPDF, pdf).cell(0, 4, _s(tok_str), align="R")
    pdf.set_y(tok_y + 14)

    pdf.set_draw_color(*BORDER)
    pdf.line(15, pdf.get_y(), 195, pdf.get_y())
    pdf.ln(6)


# ──────────────────────────────────────────────────────────────────────────────
# Attack log entry
# ──────────────────────────────────────────────────────────────────────────────

def _render_attack_log_entry(pdf: VaptPDF, attempt: AttackAttempt, W: int = 180) -> None:
    ENTRY_X = 19
    ENTRY_W = W - 6
    LINE_H  = 4.3
    PAD     = 2.0

    # ── Height estimate ────────────────────────────────────────────────────
    # Row 1: vector + status + verdict (fixed)
    # Row 2: mutation description (may wrap)
    # Row 3: payload (fixed, truncated to 1 line)
    # Rows 4+: analyst reasoning (may wrap)
    mut_lines  = max(1, len(attempt.mutation_description) // 92 + 1)
    mut_lines  = min(mut_lines, 2)
    reas_lines = max(1, len(attempt.reasoning) // 92 + 1)
    reas_lines = min(reas_lines, 4)
    entry_h    = LINE_H * (1 + mut_lines + 1 + reas_lines) + PAD * 2 + 2

    if pdf.get_y() + entry_h > 272:
        pdf.new_page()

    entry_y = pdf.get_y()

    # ── Background and accent ──────────────────────────────────────────────
    if attempt.is_baseline_analysis:
        # Warm amber — baseline content issue, no attack required
        bg  = (255, 251, 235)
        bdr = (245, 158, 11)
        acc = (217, 119, 6)
    elif attempt.confirmed and attempt.finding:
        sev = attempt.finding.severity
        bg  = SEVERITY_BG.get(sev, BG_CONFIRMED)
        bdr = SEVERITY_RGB.get(sev, BORDER_CONF)
        acc = SEVERITY_RGB.get(sev, ACC_CONFIRMED)
    else:
        bg  = BG_TESTED
        bdr = BORDER_TESTED
        acc = ACC_TESTED

    pdf.bordered_rect(ENTRY_X, entry_y, ENTRY_W, entry_h, bg, bdr)
    pdf.fill_rect(ENTRY_X, entry_y, 2.5, entry_h, acc)

    y = entry_y + PAD

    # ── Row 1: Vector | Status / Source label | Verdict ────────────────────
    pdf.set_xy(ENTRY_X + 5, y)
    pdf.set_text_color(*acc)
    pdf.set_font("Helvetica", style="B", size=7)
    vector_str = attempt.vector
    if attempt.cwe:
        vector_str += f"  ({attempt.cwe})"
    super(KaananPDF, pdf).cell(70, LINE_H, _s(vector_str))

    # Centre label — different for baseline analysis vs live attack
    if attempt.is_baseline_analysis:
        centre_str = f"{attempt.method}  baseline={attempt.baseline_status or '?'}  [PASSIVE — no attack fired]"
    else:
        centre_str = (
            f"{attempt.method}  "
            f"baseline={attempt.baseline_status or '?'}  →  "
            f"attack={attempt.attack_status or 'err'}"
        )
        if attempt.attack_time_ms is not None:
            centre_str += f"  {attempt.attack_time_ms}ms"
    pdf.set_text_color(*TEXT_SEC)
    pdf.set_font("Helvetica", size=6.5)
    pdf.set_xy(ENTRY_X + 5, y)
    super(KaananPDF, pdf).cell(ENTRY_W - 10, LINE_H, _s(centre_str), align="C")

    # Verdict badge
    if attempt.is_baseline_analysis and attempt.finding:
        verdict     = f"BASELINE EXPOSURE — {attempt.finding.severity}"
        verdict_col = (217, 119, 6)
    elif attempt.confirmed and attempt.finding:
        verdict     = f"CONFIRMED — {attempt.finding.severity}"
        verdict_col = SEVERITY_RGB.get(attempt.finding.severity, TEXT_PRI)
    else:
        verdict     = "NOT CONFIRMED"
        verdict_col = TEXT_SEC

    pdf.set_xy(ENTRY_X + 5, y)
    pdf.set_text_color(*verdict_col)
    pdf.set_font("Helvetica", style="B", size=6.5)
    super(KaananPDF, pdf).cell(ENTRY_W - 10, LINE_H, _s(verdict), align="R")

    y += LINE_H

    # ── Row 2: Mutation description ────────────────────────────────────────
    if attempt.mutation_description:
        pdf.set_xy(ENTRY_X + 5, y)
        pdf.set_text_color(*TEXT_PRI)
        pdf.set_font("Helvetica", style="I", size=7)
        # Render as multi_cell but cap at 2 lines width
        desc_text = attempt.mutation_description
        pdf.multi_cell(
            ENTRY_W - 10, LINE_H,
            _s(desc_text),
            new_x=XPos.LMARGIN, new_y=YPos.NEXT,
        )
        y = pdf.get_y()
    else:
        y += LINE_H

    # ── Row 3: Attack payload ──────────────────────────────────────────────
    pdf.set_xy(ENTRY_X + 5, y)
    pdf.set_text_color(*TEXT_SEC)
    pdf.set_font("Helvetica", style="B", size=6.5)
    super(KaananPDF, pdf).cell(14, LINE_H, "Payload:")

    pdf.set_xy(ENTRY_X + 19, y)
    if attempt.is_baseline_analysis:
        payload_str = "[no attack fired — baseline response content analysed passively]"
    else:
        payload_str = attempt.attack_body.replace("\n", " ").replace("  ", " ").strip()
        if not payload_str:
            payload_str = f"[no body]  path={attempt.path}"
        if len(payload_str) > 100:
            payload_str = payload_str[:97] + "..."
    pdf.set_text_color(*TEXT_PRI)
    pdf.set_font("Courier", size=6.5)
    super(KaananPDF, pdf).cell(ENTRY_W - 24, LINE_H, _s(payload_str))
    y += LINE_H + 0.5

    # ── Row 4+: Analyst reasoning ──────────────────────────────────────────
    pdf.set_xy(ENTRY_X + 5, y)
    pdf.set_text_color(*TEXT_SEC)
    pdf.set_font("Helvetica", style="B", size=6.5)
    super(KaananPDF, pdf).cell(14, LINE_H, "Analyst:")

    pdf.set_xy(ENTRY_X + 19, y)
    pdf.set_text_color(*TEXT_PRI)
    pdf.set_font("Helvetica", size=7)
    reasoning = attempt.reasoning
    # Flatten for display
    reasoning_flat = reasoning.replace("\n", " ").strip()
    pdf.multi_cell(
        ENTRY_W - 24, LINE_H,
        _s(reasoning_flat),
        new_x=XPos.LMARGIN, new_y=YPos.NEXT,
    )

    pdf.set_y(entry_y + entry_h + 1.5)


# ──────────────────────────────────────────────────────────────────────────────
# Attack log section
# ──────────────────────────────────────────────────────────────────────────────

def _render_attack_log(pdf: VaptPDF, attempts: list[AttackAttempt], W: int = 180) -> None:
    if not attempts:
        return

    if pdf.get_y() > 260:
        pdf.new_page()

    confirmed_count = sum(1 for a in attempts if a.confirmed)
    tested_count    = len(attempts) - confirmed_count

    pdf.set_x(17)
    pdf.set_text_color(*TEXT_SEC)
    pdf.set_font("Helvetica", style="B", size=7)
    log_header = (
        f"ATTACK LOG  —  {len(attempts)} attempt(s)  "
        f"|  {confirmed_count} confirmed  "
        f"|  {tested_count} not confirmed"
    )
    pdf.cell(0, 4, log_header, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1.5)

    for attempt in attempts:
        _render_attack_log_entry(pdf, attempt, W)

    pdf.ln(3)


# ──────────────────────────────────────────────────────────────────────────────
# Confirmed finding card
# ──────────────────────────────────────────────────────────────────────────────

def _render_finding_card(pdf: VaptPDF, finding: VaptFinding, W: int = 180) -> None:
    sev_c  = SEVERITY_RGB.get(finding.severity, TEXT_PRI)
    sev_bg = SEVERITY_BG.get(finding.severity, (245, 245, 245))

    desc_h = max(1, len(finding.description)    // 88 + 1) * 4.5
    evid_h = max(1, len(finding.evidence)        // 88 + 1) * 4.5 + 6
    imp_h  = max(1, len(finding.impact)          // 88 + 1) * 4.5 + 6
    fix_h  = max(1, len(finding.remediation)     // 88 + 1) * 4.5 + 6
    body_h = max(1, len(finding.attack_body or "") // 60 + 1) * 4.2 + 4
    needed = 22 + desc_h + evid_h + imp_h + fix_h + body_h + 10

    if pdf.get_y() + needed > 265:
        pdf.new_page()

    y_card = pdf.get_y()
    card_x = 19

    pdf.bordered_rect(card_x, y_card, W - 6, needed, BG_CARD, BORDER)
    pdf.fill_rect(card_x, y_card, 3, needed, sev_c)

    # Row 1: badge + vector
    badge_w = 22
    pdf.fill_rect(card_x + 5, y_card + 3, badge_w, 5.5, sev_c)
    pdf.set_xy(card_x + 5, y_card + 3)
    pdf.set_text_color(*WHITE)
    pdf.set_font("Helvetica", style="B", size=7)
    super(KaananPDF, pdf).cell(badge_w, 5.5, finding.severity, align="C")

    pdf.set_xy(card_x + 30, y_card + 3)
    pdf.set_text_color(*TEXT_PRI)
    pdf.set_font("Helvetica", style="B", size=10)
    super(KaananPDF, pdf).cell(100, 5.5, _s(finding.vector))

    if finding.sast_confirmed:
        badge_w = pdf.get_string_width("SAST CONFIRMED") + 6
        badge_x = card_x + 165
        pdf.fill_rect(badge_x, y_card + 3, badge_w, 5.5, (30, 64, 175))
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", style="B", size=6)
        pdf.set_xy(badge_x, y_card + 3)
        super(KaananPDF, pdf).cell(badge_w, 5.5, "SAST CONFIRMED", align="C")

    # Status compare
    if finding.baseline_status is not None or finding.attack_status is not None:
        pdf.set_xy(card_x + 130, y_card + 3)
        pdf.set_text_color(*TEXT_SEC)
        pdf.set_font("Helvetica", size=7)
        st = (f"baseline={finding.baseline_status or '?'}  "
              f"attack={finding.attack_status or 'err'}")
        super(KaananPDF, pdf).cell(40, 5.5, _s(st), align="R")

    # CWE + OWASP tags
    tag_y = y_card + 10
    tx    = float(card_x + 5)
    if finding.cwe:
        tw = pdf.inline_tag(finding.cwe, (67, 56, 202), (237, 233, 254), tx, tag_y)
        tx += tw
    if finding.owasp:
        pdf.inline_tag(finding.owasp[:38], TEXT_PRI, TAG_BG, tx, tag_y)

    pdf.set_y(tag_y + 7)

    # Mutation description
    if finding.mutation_description:
        pdf.set_x(card_x + 5)
        pdf.set_text_color(*TEXT_SEC)
        pdf.set_font("Helvetica", style="I", size=7.5)
        pdf.multi_cell(W - 14, 4, _s(f"Payload: {finding.mutation_description}"),
                       new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(1)

    # Description
    if finding.description:
        pdf.set_x(card_x + 5)
        pdf.set_text_color(*TEXT_SEC)
        pdf.set_font("Helvetica", style="B", size=7)
        super(KaananPDF, pdf).cell(16, 4.5, "Issue:")
        pdf.set_xy(card_x + 21, pdf.get_y())
        pdf.set_text_color(*TEXT_PRI)
        pdf.set_font("Helvetica", size=8)
        pdf.multi_cell(W - 30, 4.5, _s(finding.description),
                       new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(1.5)

    # Evidence
    if finding.evidence:
        ev_y = pdf.get_y()
        ev_h = max(1, len(finding.evidence) // 88 + 1) * 4.5 + 6
        pdf.bordered_rect(card_x + 5, ev_y, W - 14, ev_h, BG_EVIDENCE, (253, 230, 138))
        pdf.fill_rect(card_x + 5, ev_y, 2.5, ev_h, ACC_EVID)
        pdf.set_xy(card_x + 10, ev_y + 1.5)
        pdf.set_text_color(*TEXT_SEC)
        pdf.set_font("Helvetica", style="B", size=7)
        super(KaananPDF, pdf).cell(16, 4.5, "Evidence:")
        pdf.set_xy(card_x + 26, ev_y + 1.5)
        pdf.set_text_color(*TEXT_EVID)
        pdf.set_font("Helvetica", size=8)
        pdf.multi_cell(W - 36, 4.5, _s(finding.evidence),
                       new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(1.5)

    # Attack payload (dark code block)
    if finding.attack_body:
        pl_lines = finding.attack_body.splitlines()[:8]
        pl_h     = len(pl_lines) * 4.2 + 4
        if pdf.get_y() + pl_h < 272:
            pl_y = pdf.get_y()
            pdf.bordered_rect(card_x + 5, pl_y, W - 14, pl_h, (30, 41, 59), BORDER)
            y_pl = pl_y + 2
            for ln in pl_lines:
                if len(ln) > 80:
                    ln = ln[:77] + "..."
                pdf.set_xy(card_x + 7, y_pl)
                pdf.set_text_color(134, 239, 172)
                pdf.set_font("Courier", size=6.5)
                super(KaananPDF, pdf).cell(W - 18, 4.2, _s(ln))
                y_pl += 4.2
            pdf.set_y(pl_y + pl_h + 1.5)

    # Impact
    if finding.impact:
        imp_y = pdf.get_y()
        imp_h = max(1, len(finding.impact) // 88 + 1) * 4.5 + 6
        pdf.bordered_rect(card_x + 5, imp_y, W - 14, imp_h, BG_IMPACT, (191, 219, 254))
        pdf.fill_rect(card_x + 5, imp_y, 2.5, imp_h, TEXT_IMP)
        pdf.set_xy(card_x + 10, imp_y + 1.5)
        pdf.set_text_color(*TEXT_SEC)
        pdf.set_font("Helvetica", style="B", size=7)
        super(KaananPDF, pdf).cell(14, 4.5, "Impact:")
        pdf.set_xy(card_x + 24, imp_y + 1.5)
        pdf.set_text_color(*TEXT_IMP)
        pdf.set_font("Helvetica", size=8)
        pdf.multi_cell(W - 34, 4.5, _s(finding.impact),
                       new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(1.5)

    # Remediation
    if finding.remediation:
        fix_y = pdf.get_y() + 1
        fix_h = max(1, len(finding.remediation) // 88 + 1) * 4.5 + 6
        pdf.bordered_rect(card_x + 5, fix_y, W - 14, fix_h, BG_FIX, (187, 247, 208))
        pdf.fill_rect(card_x + 5, fix_y, 2.5, fix_h, TEXT_FIX)
        pdf.set_xy(card_x + 10, fix_y + 1.5)
        pdf.set_text_color(*TEXT_SEC)
        pdf.set_font("Helvetica", style="B", size=7)
        super(KaananPDF, pdf).cell(12, 4.5, "Fix:")
        pdf.set_xy(card_x + 22, fix_y + 1.5)
        pdf.set_text_color(*TEXT_FIX)
        pdf.set_font("Helvetica", size=8)
        pdf.multi_cell(W - 32, 4.5, _s(finding.remediation),
                       new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_y(pdf.get_y() + 5)


# ──────────────────────────────────────────────────────────────────────────────
# Endpoint block (header + findings + attack log)
# ──────────────────────────────────────────────────────────────────────────────

def _render_endpoint_block(pdf: VaptPDF, ep: VaptEndpointResult) -> None:
    W = 180

    if pdf.get_y() > 255:
        pdf.new_page()

    # ── Endpoint header bar ───────────────────────────────────────────────
    hdr_y = pdf.get_y()
    pdf.bordered_rect(15, hdr_y, W, 14, (238, 242, 255), BORDER)

    # Method badge
    m_fg = _METHOD_RGB.get(ep.method.upper(), _METHOD_RGB_DEF)
    m_bg = _METHOD_BG.get(ep.method.upper(), _METHOD_BG_DEF)
    badge_w = pdf.get_string_width(ep.method) + 6
    pdf.fill_rect(17, hdr_y + 2.5, badge_w, 8, m_bg)
    pdf.set_draw_color(*m_fg)
    pdf.rect(17, hdr_y + 2.5, badge_w, 8, style="D")
    pdf.set_xy(17, hdr_y + 2.5)
    pdf.set_text_color(*m_fg)
    pdf.set_font("Helvetica", style="B", size=8)
    super(KaananPDF, pdf).cell(badge_w, 8, ep.method, align="C")

    # Path
    pdf.set_xy(17 + badge_w + 3, hdr_y + 4)
    pdf.set_text_color(*TEXT_PRI)
    pdf.set_font("Courier", style="B", size=9)
    path_str = ep.path if len(ep.path) <= 60 else ep.path[:57] + "..."
    super(KaananPDF, pdf).cell(100, 6, _s(path_str))

    # Right side: status + attack count
    if ep.error:
        right_str = "UNREACHABLE"
        right_col = SEVERITY_RGB["CRITICAL"]
    else:
        parts = []
        if ep.baseline_status is not None:
            parts.append(f"baseline={ep.baseline_status}")
        if ep.attacks_fired:
            parts.append(f"{ep.attacks_fired} attacks")
        if ep.budget_exhausted:
            parts.append("budget limit")
        right_str = "  |  ".join(parts)
        right_col = TEXT_SEC

    pdf.set_xy(15, hdr_y + 3)
    pdf.set_text_color(*right_col)
    pdf.set_font("Helvetica", size=7)
    super(KaananPDF, pdf).cell(W - 2, 6, _s(right_str), align="R")

    # Finding count
    if ep.findings:
        fc   = len(ep.findings)
        crit = sum(1 for f in ep.findings if f.severity == "CRITICAL")
        high = sum(1 for f in ep.findings if f.severity == "HIGH")
        fc_str = f"{fc} finding(s)"
        if crit or high:
            fc_str += f" [{crit}C/{high}H]"
        col = SEVERITY_RGB["CRITICAL"] if crit else SEVERITY_RGB["HIGH"] if high else TEXT_SEC
        pdf.set_xy(15, hdr_y + 8)
        pdf.set_text_color(*col)
        pdf.set_font("Helvetica", style="B", size=7)
        super(KaananPDF, pdf).cell(W - 2, 5, _s(fc_str), align="R")

    pdf.set_y(hdr_y + 17)

    # Auth + source
    if ep.authentication and ep.authentication != "Unknown":
        auth_d = (ep.authentication if len(ep.authentication) <= 65
                  else ep.authentication[:62] + "...")
        pdf.set_x(17)
        pdf.set_text_color(*TEXT_SEC)
        pdf.set_font("Helvetica", style="I", size=7)
        pdf.cell(0, 4, _s(f"Auth: {auth_d}"),
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_x(17)
    pdf.set_text_color(148, 163, 184)
    pdf.set_font("Helvetica", size=6.5)
    pdf.cell(0, 4, _s(f"Source: {ep.file_source}"),
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(1.5)

    # Error
    if ep.error:
        pdf.set_x(17)
        pdf.set_text_color(*SEVERITY_RGB["HIGH"])
        pdf.set_font("Helvetica", size=8)
        pdf.multi_cell(W - 4, 5, _s(ep.error[:300]),
                       new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)
        return

    # ── Confirmed finding cards ───────────────────────────────────────────
    if ep.findings:
        pdf.set_x(17)
        pdf.set_text_color(*SEVERITY_RGB["HIGH"])
        pdf.set_font("Helvetica", style="B", size=7.5)
        pdf.cell(0, 4, f"CONFIRMED VULNERABILITIES ({len(ep.findings)})",
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(1)

        sorted_findings = sorted(
            ep.findings,
            key=lambda f: SEVERITY_ORDER.index(f.severity)
            if f.severity in SEVERITY_ORDER else 99,
        )
        for finding in sorted_findings:
            _render_finding_card(pdf, finding)

        pdf.ln(1)

    # ── Attack log ────────────────────────────────────────────────────────
    if ep.attack_attempts:
        _render_attack_log(pdf, ep.attack_attempts)
    elif not ep.findings and not ep.error:
        # No attempts and no error — explain why
        pdf.set_x(17)
        pdf.set_text_color(*TEXT_SEC)
        pdf.set_font("Helvetica", style="I", size=7.5)
        pdf.cell(0, 5,
                 "No attacks were generated (endpoint may require specific context "
                 "or is a utility endpoint with no exploitable surface).",
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(3)

    pdf.ln(3)


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────

def generate_vapt_report(result: VaptScanResult, output_path: Path) -> None:
    pdf = VaptPDF(logo_path=_find_logo())
    pdf.new_page()

    _render_vapt_summary(pdf, result)

    if not result.endpoint_results:
        pdf.set_text_color(*TEXT_SEC)
        pdf.set_font("Helvetica", size=10)
        pdf.cell(0, 8, "No endpoints were tested.",
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        pdf.output(str(output_path))
        return

    # Sort: endpoints with confirmed findings first (worst severity), then clean
    def _sort_key(ep: VaptEndpointResult) -> tuple:
        if ep.error:
            return (-1, 0)
        if not ep.findings:
            return (99, 0)
        worst = min(
            SEVERITY_ORDER.index(f.severity)
            for f in ep.findings
            if f.severity in SEVERITY_ORDER
        )
        return (worst, -len(ep.findings))

    finding_eps = [ep for ep in result.endpoint_results if ep.findings or ep.error]
    clean_eps   = [ep for ep in result.endpoint_results if not ep.findings and not ep.error]

    if finding_eps:
        pdf.set_text_color(*SEVERITY_RGB["HIGH"])
        pdf.set_font("Helvetica", style="B", size=8)
        pdf.cell(0, 5, "CONFIRMED VULNERABILITIES — BY ENDPOINT",
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)
        for ep in sorted(finding_eps, key=_sort_key):
            _render_endpoint_block(pdf, ep)

    if clean_eps:
        if pdf.get_y() > 250:
            pdf.new_page()
        pdf.set_draw_color(*BORDER)
        pdf.line(15, pdf.get_y(), 195, pdf.get_y())
        pdf.ln(4)
        pdf.set_text_color(*TEXT_SEC)
        pdf.set_font("Helvetica", style="B", size=8)
        pdf.cell(0, 5, "TESTED ENDPOINTS — NO VULNERABILITIES CONFIRMED",
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(4)
        for ep in clean_eps:
            _render_endpoint_block(pdf, ep)

    if not finding_eps and not clean_eps:
        pdf.set_text_color(21, 128, 61)
        pdf.set_font("Helvetica", style="B", size=12)
        pdf.cell(0, 10, "No endpoints were tested.",
                 new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(output_path))