import os
import logging
import html
import json
import re
from datetime import datetime
from auditor.core.engine import Finding
from auditor.core.policy import Decision
from .base_reporter import BaseReporter
from .framework_mapper import FrameworkMapper

logger = logging.getLogger(__name__)


class HTMLReporter(BaseReporter):
    MAX_FINDINGS_PER_REPORT = 50000

    def _load_ai_data(self):
        # Try reports/ai_runs/raw_response.txt (absolute from project root)
        ai_path_abs = os.path.join(
            os.path.dirname(__file__),
            "..",
            "..",
            "reports",
            "ai_runs",
            "raw_response.txt",
        )
        ai_path_rel = os.path.join("auditor", "ai", "raw_response.txt")
        ai_path = ai_path_abs if os.path.exists(ai_path_abs) else ai_path_rel
        ai_map = {}

        if not os.path.exists(ai_path):
            return ai_map

        try:
            with open(ai_path, "r", encoding="utf-8") as f:
                content = f.read()

            def _extract_items(text):
                """Parse JSON items from text - handles both raw JSON and markdown fences."""
                items = []
                # Try markdown fenced blocks first
                blocks = re.findall(r"```json\s*([\s\S]*?)```", text)
                if not blocks:
                    # No fences - treat entire text as raw JSON chunks separated by session markers
                    blocks = re.split(r"--- START OF SESSION.*?---", text)

                for block in blocks:
                    clean = block.strip()
                    if not clean:
                        continue
                    try:
                        data = json.loads(clean)
                        parsed = data if isinstance(data, list) else [data]
                        items.extend([i for i in parsed if isinstance(i, dict)])
                    except (json.JSONDecodeError, TypeError):
                        # Fallback: extract objects one by one via regex
                        raw_objects = re.findall(
                            r'\{[^{}]*"finding_id"[^{}]*\}',
                            clean,
                            re.DOTALL,
                        )
                        for obj_str in raw_objects:
                            try:
                                items.append(json.loads(obj_str))
                            except (json.JSONDecodeError, TypeError):
                                continue
                return items

            for item in _extract_items(content):
                fid = str(item.get("finding_id", "")).strip()
                if fid:
                    ai_map[fid] = item

            logger.info(f"📊 HTML Reporter: Mapped {len(ai_map)} AI findings.")
        except Exception as e:
            logger.error(f"Failed to load AI data: {e}")
        return ai_map

    def generate(
        self,
        findings,
        decision,
        output_path,
        project_name="Auditor Core V2",
        ai_recommendations=None,  # Can be passed manually or left as None
    ):
        if not self._validate_inputs(findings, decision):
            return

        full_path = self._get_safe_path(output_path, project_name, "html")

        # --- AI MAP RESOLUTION ---
        # Priority: explicitly passed list (contains verified intel fields) > file fallback.
        # _load_ai_data() reads raw_response.txt which pre-dates verification — never use it
        # when the caller has already passed the enriched recommendations list.
        if ai_recommendations is None:
            ai_map = self._load_ai_data()
        elif isinstance(ai_recommendations, dict):
            # Already a {fid: item} dict
            ai_map = ai_recommendations
        elif isinstance(ai_recommendations, list):
            # Convert list [{"finding_id": "...", ...}] to dict — preserves all intel_* fields
            ai_map = {}
            for r in ai_recommendations:
                if isinstance(r, dict):
                    fid = str(r.get("finding_id") or r.get("id", "")).strip()
                    if fid:
                        ai_map[fid] = r
        else:
            ai_map = self._load_ai_data()

        # --- FIX: Define missing variables for dashboard ---
        # 1. Extract metadata from decision object
        meta = getattr(decision, "meta", {})
        rca = meta.get("rca", {})

        # 2. Credibility metrics
        cred_score = getattr(decision, "credibility_score", 100)
        cred_status = "STABLE" if cred_score > 80 else "UNSTABLE"

        # 3. Context distribution
        # Use .get() with default 0 to avoid errors when data is missing
        core_contribution = rca.get("core_contribution", 0)
        test_contribution = rca.get("test_contribution", 0)

        # 4. Reachability — computed directly from findings, not from rca dict
        # rca.get("reach_perc") is never populated because reach_status was not
        # propagated through the pipeline. Read it from each Finding instead.
        findings_list = list(findings)
        _total_f = len(findings_list) or 1
        _reach_count = sum(
            1
            for f in findings_list
            if getattr(f, "reach_status", "UNKNOWN") == "REACHABLE"
        )
        _safe_count = sum(
            1
            for f in findings_list
            if getattr(f, "reach_status", "UNKNOWN") == "STATIC_SAFE"
        )
        _unknown_count = _total_f - _reach_count - _safe_count

        reach_perc = round(_reach_count / _total_f * 100, 1)
        safe_perc = round(_safe_count / _total_f * 100, 1)
        unknown_perc = round(_unknown_count / _total_f * 100, 1)

        # Metrics calculation
        # findings_list already built above for reachability calc
        # total_weighted_exp = (
        #     sum(float(getattr(f, "cvss_score", 0.0)) for f in findings_list) or 1.0
        # )
        stats = decision.summary
        total_findings = sum(stats.values())

        # Sorting
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(
            findings_list[: self.MAX_FINDINGS_PER_REPORT],
            key=lambda x: sev_order.get(x.severity.upper(), 99),
        )

        mapper = FrameworkMapper()
        finding_rows = ""
        for finding in sorted_findings:
            fid = str(getattr(finding, "id", "")).strip()
            sev_class = str(finding.severity).lower()

            # AI data for this specific finding
            ai_data = ai_map.get(fid)

            # FIX: Ensure ai_data is a dict, not a string
            if ai_data and not isinstance(ai_data, dict):
                try:
                    ai_data = json.loads(ai_data) if isinstance(ai_data, str) else {}
                except (json.JSONDecodeError, TypeError, ValueError):
                    ai_data = {}

            ai_badge = ""
            if ai_data and isinstance(ai_data, dict):
                v = ai_data.get("verdict", "UNKNOWN")
                conf = html.escape(str(ai_data.get("confidence", 0)))
                intel_reach = ai_data.get("intel_reachability", "")

                color = "var(--critical)" if v == "SUPPORTED" else "var(--neutral)"
                label = "🔥 AI VERIFIED" if v == "SUPPORTED" else "🛡️ AI FALSE POSITIVE"
                ai_badge = f'<br><span class="badge" style="background:{color}; color:white; font-size:9px;">{label} ({conf}%)</span>'

                # Verification badge — only shown when IntelligenceEngine data is present
                if intel_reach:
                    reach_color = {
                        "REACHABLE": "var(--critical)",
                        "POTENTIALLY_REACHABLE": "var(--high)",
                        "STATIC_SAFE": "var(--low)",
                        "UNKNOWN": "var(--neutral)",
                    }.get(intel_reach, "var(--neutral)")
                    ai_badge += (
                        f'<br><span class="badge" style="background:{reach_color}; '
                        f'color:white; font-size:9px;">⚙️ INTEL: {html.escape(intel_reach)}</span>'
                    )

            # Chain badge
            chain_badge = ""
            if "chain_id" in finding.meta:
                chain_risk = finding.meta.get("chain_risk", "HIGH")
                chain_rule = finding.meta.get("chain_rule", "")
                chain_original = finding.meta.get("chain_original_severity", "")
                chain_color = (
                    "var(--critical)" if chain_risk == "CRITICAL" else "var(--high)"
                )
                orig_label = (
                    f" ↑{chain_original}"
                    if chain_original and chain_original != finding.severity
                    else ""
                )
                chain_badge = (
                    f'<br><span class="badge" style="background:{chain_color}; color:white; font-size:9px;" '
                    f'title="Chain rule: {html.escape(chain_rule)} | Partner: {html.escape(str(finding.meta.get("chain_partner", "")))}">'
                    f'🔗 CHAIN: {html.escape(str(finding.meta["chain_id"]))} ({html.escape(chain_risk)}{html.escape(orig_label)})</span>'
                )

            # Main row
            finding_rows += f"""
            <tr class="severity-{sev_class} finding-row" data-severity="{sev_class}">
                <td>
                    <span class="badge badge-{sev_class}">{finding.severity}</span>
                    {ai_badge}
                    {chain_badge}
                </td>
                <td><code>{html.escape(str(finding.rule_id))}</code></td>
                <td><code>{html.escape(str(finding.file_path))}:{finding.line}</code></td>
                <td><code>{html.escape(finding.detector)}</code></td>
                <td>{html.escape(str(finding.description))}</td>
                <td style="text-align:center;">{html.escape(str(getattr(finding, "cwe", "CWE-UNKNOWN")))}</td>
                <td style="text-align: center; font-weight: bold;">{float(getattr(finding, "cvss_score", 0.0))}</td>
            </tr>
            """

            # Compliance framework mapping row
            cwe_val = str(
                getattr(finding, "cwe", "") or finding.meta.get("cwe", "")
                if hasattr(finding, "meta")
                else ""
            )
            cm = mapper.map(
                rule_id=str(finding.rule_id),
                cwe=cwe_val,
                severity=str(finding.severity),
                description=str(finding.description),
            )
            soc2_tags = " &nbsp;".join(
                f'<span style="background:#1A3A5C;color:#A8C8E8;padding:1px 5px;'
                f'border-radius:3px;font-size:8px;font-family:monospace;">{x["id"]}</span>'
                for x in cm.get("soc2", [])
            )
            cis_tags = " &nbsp;".join(
                f'<span style="background:#1A3A1A;color:#A8E8A8;padding:1px 5px;'
                f'border-radius:3px;font-size:8px;font-family:monospace;">{x["id"]}</span>'
                for x in cm.get("cis", [])
            )
            iso_tags = " &nbsp;".join(
                f'<span style="background:#3A1A3A;color:#E8A8E8;padding:1px 5px;'
                f'border-radius:3px;font-size:8px;font-family:monospace;">{x["id"]}</span>'
                for x in cm.get("iso27001", [])
            )
            if soc2_tags or cis_tags or iso_tags:
                finding_rows += f"""
                <tr class="finding-row severity-{sev_class} ai-details" data-severity="{sev_class}">
                    <td colspan="7" style="padding:4px 20px 6px 20px; background:#0d1117;">
                        <span style="font-size:8px; color:var(--text-dim); margin-right:8px;">SOC2:</span>{soc2_tags}
                        &nbsp;&nbsp;
                        <span style="font-size:8px; color:var(--text-dim); margin-right:8px;">CIS:</span>{cis_tags}
                        &nbsp;&nbsp;
                        <span style="font-size:8px; color:var(--text-dim); margin-right:8px;">ISO:</span>{iso_tags}
                    </td>
                </tr>
                """

            # Insert full analysis block
            if ai_data:
                reasoning = html.escape(
                    str(ai_data.get("reasoning") or ai_data.get("advice", ""))
                )
                # Ensure verdict affects styling
                verdict_style = (
                    "border-left: 4px solid var(--critical);"
                    if ai_data.get("verdict") == "SUPPORTED"
                    else "border-left: 4px solid var(--low);"
                )

                chain = ai_data.get("exploit_chain") or {}
                if isinstance(chain, dict) and chain:
                    source = html.escape(str(chain.get("source", "")))
                    sink = html.escape(str(chain.get("sink", "")))
                    chain_html = f'<div style="margin-top:10px; font-size:10px; color:var(--cyber-blue); font-family:monospace;"><b>PATH:</b> {source} ➔ {sink}</div>'
                else:
                    chain_html = ""

                # Verification panel — rendered only when IntelligenceEngine data is present
                verification_html = ""
                v_note = ai_data.get("verification_note", "")
                intel_reach = ai_data.get("intel_reachability", "")
                taint_sources = ai_data.get("intel_taint_sources") or []
                intel_func = ai_data.get("intel_func_name", "")
                intel_reason = ai_data.get("intel_reason", "")

                if intel_reach:
                    reach_color = {
                        "REACHABLE": "var(--critical)",
                        "POTENTIALLY_REACHABLE": "var(--high)",
                        "STATIC_SAFE": "var(--low)",
                        "UNKNOWN": "var(--neutral)",
                    }.get(intel_reach, "var(--neutral)")

                    taint_html = ""
                    if taint_sources:
                        taint_items = "".join(
                            f'<code style="background:#0e1422; padding:1px 5px; border-radius:3px; margin-right:4px;">'
                            f"{html.escape(str(t))}</code>"
                            for t in taint_sources
                        )
                        taint_html = f'<div style="margin-top:6px;"><b>Taint sources:</b> {taint_items}</div>'

                    func_html = (
                        f'<span style="color:var(--text-dim); margin-left:12px;">'
                        f"in <code>{html.escape(intel_func)}</code></span>"
                        if intel_func and intel_func != "unknown"
                        else ""
                    )

                    note_html = (
                        f'<div style="margin-top:6px; font-style:italic; color:var(--text-dim);">'
                        f"{html.escape(v_note)}</div>"
                        if v_note
                        else ""
                    )

                    reason_html = (
                        f'<div style="margin-top:4px; font-size:10px; color:var(--text-dim);">'
                        f"{html.escape(intel_reason)}</div>"
                        if intel_reason
                        else ""
                    )

                    verification_html = f"""
                        <div style="margin-top:12px; padding:10px 14px; background:#0e1422;
                                    border-radius:8px; border-left:3px solid {reach_color};
                                    font-size:11px;">
                            <b style="color:{reach_color};">⚙️ INTELLIGENCE ENGINE</b>
                            <span style="margin-left:8px; background:{reach_color}; color:#fff;
                                         padding:1px 7px; border-radius:10px; font-size:10px;">
                                {html.escape(intel_reach)}
                            </span>
                            {func_html}
                            {taint_html}
                            {reason_html}
                            {note_html}
                        </div>"""

                finding_rows += f"""
                <tr class="finding-row severity-{sev_class} ai-details" data-severity="{sev_class}">
                    <td colspan="7">
                        <div class="ai-guidance" style="{verdict_style}">
                            <div class="ai-title">🧠 ARCHITECTURAL ANALYSIS (Verdict: {ai_data.get('verdict')})</div>
                            <div class="ai-content">{reasoning}</div>
                            {chain_html}
                            {verification_html}
                        </div>
                    </td>
                </tr>
                """

        branding_title = html.escape(project_name)
        _action_val = (
            getattr(decision, "action", None)
            and getattr(decision.action, "value", "").upper()
            or "PASS"
        )
        _verdict_map = {
            "PASS": "&#x2705; ASSESSMENT RESULT: PASS",
            "WARN": "&#x26A0; ASSESSMENT RESULT: REQUIRES REMEDIATION",
            "BLOCK": "&#x1F6A8; ASSESSMENT RESULT: CRITICAL &#8212; Immediate action required",
            "FAIL": "&#x26A0; ASSESSMENT RESULT: REQUIRES REMEDIATION",
        }
        verdict_label_html = _verdict_map.get(
            _action_val, "&#x26A0; ASSESSMENT RESULT: REQUIRES REMEDIATION"
        )
        exposure_capped = rca.get("exposure_capped", 0.0)
        dynamic_k = rca.get("dynamic_k", 1.0)
        sensitive_spi = rca.get("sensitive_spi", "N/A")

        # Decision logic
        decision_color = "#00ffa6" if getattr(decision, "passed", False) else "#ff4d6d"

        chains_map = {}
        for f in findings:
            c_id = f.meta.get("chain_id")
            if c_id:
                if c_id not in chains_map:
                    chains_map[c_id] = {
                        "rule": f.meta.get("chain_rule"),
                        "findings": [],
                    }
                chains_map[c_id]["findings"].append(f)

        chains_html = ""
        if chains_map:
            chain_cards_html = ""
            for c_id, data in chains_map.items():
                chain_findings = data["findings"]
                chain_risk = (
                    chain_findings[0].meta.get("chain_risk", "HIGH")
                    if chain_findings
                    else "HIGH"
                )
                chain_rule = data["rule"] or ""
                risk_color = (
                    "var(--critical)" if chain_risk == "CRITICAL" else "var(--high)"
                )
                risk_bg = (
                    "rgba(255,77,109,0.07)"
                    if chain_risk == "CRITICAL"
                    else "rgba(255,158,79,0.07)"
                )

                # Build step boxes for each finding in the chain
                steps_html = ""
                for idx, cf in enumerate(chain_findings):
                    orig_sev = cf.meta.get("chain_original_severity", cf.severity)
                    escalated = orig_sev != cf.severity
                    sev_color_map = {
                        "CRITICAL": "var(--critical)",
                        "HIGH": "var(--high)",
                        "MEDIUM": "var(--medium)",
                        "LOW": "var(--low)",
                        "INFO": "var(--info)",
                    }
                    sev_color = sev_color_map.get(cf.severity, "var(--text-dim)")
                    escalation_badge = (
                        f'<span style="font-size:9px;color:var(--medium);margin-left:4px;" '
                        f'title="Escalated from {html.escape(orig_sev)}">↑{html.escape(orig_sev)}</span>'
                        if escalated
                        else ""
                    )
                    step_label = (
                        "TRIGGER"
                        if idx == 0
                        else (
                            "CONSEQUENCE" if idx == len(chain_findings) - 1 else "LINK"
                        )
                    )
                    step_label_color = (
                        "var(--critical)"
                        if step_label == "CONSEQUENCE"
                        else (
                            "var(--medium)"
                            if step_label == "TRIGGER"
                            else "var(--text-dim)"
                        )
                    )
                    steps_html += (
                        f'<div class="chain-step" style="background:var(--bg-main);border:1px solid {risk_color};'
                        f'border-radius:6px;padding:10px 14px;min-width:200px;max-width:260px;position:relative;">'
                        f'<div style="font-size:9px;font-weight:700;color:{step_label_color};letter-spacing:.08em;margin-bottom:4px;">{step_label}</div>'
                        f'<code style="color:{risk_color};font-size:11px;word-break:break-all;">{html.escape(cf.rule_id)}</code>'
                        f'<div style="margin-top:6px;font-size:10px;color:var(--text-dim);word-break:break-all;">'
                        f'{html.escape(cf.file_path)}<span style="color:var(--border)">:</span><span style="color:var(--cyber-blue)">{cf.line}</span></div>'
                        f'<div style="margin-top:4px;font-size:10px;">'
                        f'<span style="color:{sev_color};font-weight:600;">{html.escape(cf.severity)}</span>'
                        f"{escalation_badge}"
                        f'<span style="color:var(--text-dim);margin-left:6px;">CVSS {cf.cvss_score:.1f}</span>'
                        f"</div></div>"
                    )
                    if idx < len(chain_findings) - 1:
                        steps_html += (
                            f'<div style="display:flex;align-items:center;color:{risk_color};'
                            f'font-size:22px;flex-shrink:0;padding:0 4px;">⟶</div>'
                        )

                # Collapsible chain card
                card_id = f"chain-card-{html.escape(c_id)}"
                chain_cards_html += f"""
<div class="chain-card" style="border:1px solid {risk_color};border-radius:10px;
    margin-bottom:18px;background:{risk_bg};overflow:hidden;">
  <div class="chain-card-header" onclick="toggleChain('{card_id}')"
       style="display:flex;justify-content:space-between;align-items:center;
              padding:14px 18px;cursor:pointer;user-select:none;">
    <div style="display:flex;align-items:center;gap:12px;">
      <span style="font-size:18px;">🔗</span>
      <strong style="color:{risk_color};font-size:15px;">{html.escape(c_id)}</strong>
      <span style="background:{risk_color};color:white;padding:2px 9px;border-radius:12px;
                   font-size:10px;font-weight:700;letter-spacing:.06em;">{html.escape(chain_risk)}</span>
      <span style="color:var(--text-dim);font-size:12px;">{len(chain_findings)} finding{'s' if len(chain_findings) != 1 else ''}</span>
    </div>
    <div style="display:flex;align-items:center;gap:14px;">
      <span style="color:var(--text-dim);font-size:12px;font-style:italic;">{html.escape(chain_rule)}</span>
      <span class="chain-toggle" id="{card_id}-toggle"
            style="color:{risk_color};font-size:18px;transition:transform .2s;">▾</span>
    </div>
  </div>
  <div id="{card_id}" style="padding:0 18px 16px 18px;">
    <div style="display:flex;align-items:flex-start;gap:8px;overflow-x:auto;padding-bottom:8px;flex-wrap:nowrap;">
      {steps_html}
    </div>
    <p style="margin:10px 0 0;font-size:11px;color:var(--text-dim);">
      <strong style="color:var(--text-main);">Attack logic:</strong>
      The <em>{html.escape(chain_rule)}</em> chain links a credential/secret exposure (trigger)
      to a runtime exploit (consequence). An attacker who controls the trigger input
      can directly influence the consequence execution path.
    </p>
  </div>
</div>"""

            chains_html = f"""
<div class="attack-paths-container" style="margin-top:40px;">
  <div style="display:flex;align-items:center;gap:14px;margin-bottom:6px;">
    <h2 style="color:var(--critical);margin:0;font-size:18px;letter-spacing:.03em;">
      ⚡ Attack Path Analysis
    </h2>
    <span style="background:rgba(255,77,109,0.15);color:var(--critical);
                 padding:3px 10px;border-radius:12px;font-size:11px;font-weight:700;">
      {len(chains_map)} CHAIN{'S' if len(chains_map) != 1 else ''} DETECTED
    </span>
  </div>
  <p style="color:var(--text-dim);font-size:12px;margin:0 0 18px;">
    Multi-step exploitation paths where individual low-severity findings
    combine into a critical attack vector. Each chain shows trigger → consequence flow.
    Click a chain header to collapse/expand.
  </p>
  {chain_cards_html}
</div>
<script>
function toggleChain(id) {{
  var el = document.getElementById(id);
  var toggle = document.getElementById(id + '-toggle');
  if (!el) return;
  var isOpen = el.style.display !== 'none';
  el.style.display = isOpen ? 'none' : '';
  if (toggle) toggle.style.transform = isOpen ? 'rotate(-90deg)' : '';
}}
</script>"""

        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>DataWizual Lab - Auditor Core: {branding_title}</title>
            <style>

            /* =========================
            FONTS
            ========================= */
            @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=JetBrains+Mono:wght@400;500&display=swap');

            :root{{
                --bg-main:#0b0f19;
                --bg-card:#161b28;
                --border:#242b3d;

                --text-main:#e6edf3;
                --text-dim:#8b949e;

                --cyber-blue:#3ea6ff;
                --neon-green:#00ffa6;
                --neon-purple:#9b87ff;

                --critical:#ff4d6d;
                --high:#ff9e4f;
                --medium:#ffd166;
                --low:#06d6a0;
                --info:#4dabf7;

                --neutral:#3a4258;
            }}

            /* =========================
            BASE
            ========================= */

            body{{
                margin:0;
                font-family:'Inter',system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;
                background:var(--bg-main);
                color:var(--text-main);
                -webkit-font-smoothing:antialiased;
            }}

            .step-box {{ box-shadow: 0 4px 12px rgba(0,0,0,0.5); }}
            .attack-paths-container {{ animation: fadeIn 0.8s ease-out; }}
            @keyframes fadeIn {{ from {{ opacity: 0; transform: translateY(10px); }} to {{ opacity: 1; transform: translateY(0); }} }}

            .container{{
                max-width:1500px;
                margin:auto;
                padding:28px;
            }}

            /* =========================
            HEADER
            ========================= */

            .header{{
                background:linear-gradient(145deg,#121726,#0d1320);
                border:1px solid var(--border);
                border-radius:14px;
                padding:28px 32px;
                display:flex;
                justify-content:space-between;
                align-items:center;
                box-shadow:0 10px 30px rgba(0,0,0,.45);

                position:sticky;
                top:0;
                z-index:100;
            }}

            .header h1{{
                margin:0;
                font-weight:600;
                letter-spacing:.4px;
            }}

            /* =========================
            CARDS
            ========================= */

            .decision-box{{
                background:var(--bg-card);
                border:1px solid var(--border);
                border-radius:14px;
                padding:22px;
                margin-top:22px;
                backdrop-filter:blur(6px);
            }}

            .methodology-grid{{
                display:grid;
                grid-template-columns:repeat(auto-fit,minmax(320px,1fr));
                gap:18px;
            }}

            .methodology-card{{
                background:rgba(20,25,38,.85);
                border:1px solid var(--border);
                border-radius:12px;
                padding:16px;
                transition:.25s ease;
            }}

            .methodology-card:hover{{
                border-color:var(--cyber-blue);
                box-shadow:0 0 18px rgba(62,166,255,.15);
            }}

            /* =========================
            FORMULA (FIXED VISIBILITY)
            ========================= */

            .math-formula{{
                font-family:'JetBrains Mono','Fira Code','Consolas',monospace;
                background:#0e1422;
                border:1px solid #2b3550;
                border-radius:10px;
                padding:14px;
                text-align:center;
                margin:12px 0;
                color:var(--neon-green);
            }}

            /* =========================
            SENSITIVITY SNAPSHOT FIX
            ========================= */

            .sensitivity{{
                background:linear-gradient(145deg,#0f1424,#0c1120);
                border:1px solid #2b3550;
                border-radius:12px;
                padding:14px;
            }}

            .sensitivity-value{{
                font-size:30px;
                font-weight:600;
                color:var(--critical);
            }}

            /* =========================
            SPI DISPLAY
            ========================= */

            .spi-display{{
                font-size:54px;
                font-weight:600;
            }}

            .grade-badge{{
                background:#0f1629;
                border:1px solid var(--cyber-blue);
                border-radius:8px;
                padding:4px 12px;
                margin-left:10px;
            }}

            /* =========================
            BADGES (CYBER STYLE)
            ========================= */

            .badge{{
                display:inline-block;
                padding:4px 9px;
                border-radius:8px;
                font-size:10px;
                letter-spacing:.6px;
                border:1px solid transparent;
                transition:.2s;
            }}

            .badge:hover{{
                box-shadow:0 0 8px currentColor;
            }}

            .badge-critical{{background:rgba(255,77,109,.15);color:var(--critical);}}
            .badge-high{{background:rgba(255,158,79,.15);color:var(--high);}}
            .badge-medium{{background:rgba(255,209,102,.15);color:var(--medium);}}
            .badge-low{{background:rgba(6,214,160,.15);color:var(--low);}}
            .badge-info{{background:rgba(77,171,247,.15);color:var(--info);}}

            .badge-reach-safe{{color:var(--neon-green);}}
            .badge-reach-risk{{color:var(--critical);}}
            .badge-reach-unknown{{color:var(--text-dim);}}

            /* =========================
            TABLE (FIXED RESPONSIVE)
            ========================= */

            table{{
                width:100%;
                border-collapse:collapse;
                table-layout:fixed;
                margin-top:24px;
                background:var(--bg-card);
                border:1px solid var(--border);
                border-radius:12px;
                overflow:hidden;
            }}

            th{{
                text-align:left;
                padding:14px;
                font-size:11px;
                color:var(--text-dim);
                border-bottom:1px solid var(--border);
                letter-spacing:.5px;
            }}

            td{{
                padding:14px;
                font-size:13px;
                border-bottom:1px solid #1f2636;
                vertical-align:top;

                /* prevents layout breaking by long paths / hashes */
                word-wrap:break-word;      /* legacy fallback */
                overflow-wrap:anywhere;    /* modern browsers */
            }}

            tr:hover{{
                background:rgba(62,166,255,.08);
            }}

            /* =========================
            PROGRESS BARS
            ========================= */

            .progress-fill{{
                transition: width .6s ease;
            }}

            /* =========================
            CODE STYLE
            ========================= */

            code{{
                font-family:'JetBrains Mono','Fira Code','Consolas',monospace;
                background:rgba(255,255,255,.04);
                padding:3px 6px;
                border-radius:6px;
                color:#9cdcfe;
            }}

            /* =========================
            AI TERMINAL BLOCK
            ========================= */

            .ai-guidance {{
                background: #0d1117; /* Deep black background for contrast */
                border: 1px solid rgba(62, 166, 255, 0.3); /* Thin blue border */
                border-left: 4px solid var(--cyber-blue); /* Accent stripe on the left */
                border-radius: 8px;
                padding: 20px;
                margin: 10px 20px 20px 20px; /* Spacing to prevent block from touching table edges */
                font-family: 'JetBrains Mono', 'Fira Code', monospace;
                line-height: 1.6;
                box-shadow: 0 4px 20px rgba(0, 0, 0, 0.5);
                position: relative;
                overflow: hidden;
            }}

            .ai-guidance::before {{
                content: "AI_ANALYSIS_VERIFIED";
                position: absolute;
                top: 5px;
                right: 10px;
                font-size: 8px;
                color: var(--cyber-blue);
                opacity: 0.5;
                letter-spacing: 1px;
            }}

            .ai-title {{
                color: var(--cyber-blue); /* Brand primary color */
                font-weight: 600;
                font-size: 0.85rem;
                margin-bottom: 12px;
                display: flex;
                align-items: center;
                gap: 8px;
                text-transform: uppercase;
                letter-spacing: 1px;
            }}

            .ai-content {{
                color: #d1d5db; /* Light gray text for readability */
                font-size: 0.85rem;
                white-space: pre-wrap; /* Preserves line breaks from Python output */
            }}

            /* =========================
            FILTER BUTTONS
            ========================= */

            .filter-btn{{
                background:#121726;
                border:1px solid var(--border);
                color:var(--text-main);
                padding:8px 14px;
                border-radius:10px;
                cursor:pointer;
                transition:.25s;
            }}

            .filter-btn:hover{{
                border-color:var(--cyber-blue);
            }}

            .filter-btn.active{{
                background:rgba(62,166,255,.15);
                border-color:var(--cyber-blue);
                box-shadow:0 0 12px rgba(62,166,255,.3);
            }}

            /* =========================
            FOOTER
            ========================= */

            .footer{{
                text-align:center;
                margin-top:40px;
                color:var(--text-dim);
                font-size:12px;
            }}

            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <div><h1>{branding_title}</h1><p>DataWizual Lab - Auditor Core Enterprise</p></div>
                    <div style="text-align: right;"><p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}</p></div>
                </div>

                <div class="decision-box" style="display: flex; justify-content: space-between; align-items: center; margin-top:20px;">
                    <div style="flex: 2;">
                        <h2>Enterprise Security Posture</h2>
                        <p><strong>Project:</strong> {branding_title} | <strong>Findings:</strong> {total_findings}</p>
                        <p><strong>Credibility:</strong> {cred_status} ({cred_score}/100)</p>
                    </div>
                    <div style="flex: 1; text-align: center; border-left: 1px solid var(--border);">
                        <p style="font-size: 12px; color: var(--text-dim);">SECURITY POSTURE INDEX (SPI)</p>
                        <h2 class="spi-display">{getattr(decision, 'posture_index', 0.0)} <span class="grade-badge">{getattr(decision, 'posture_grade', 'N/A')}</span></h2>
                        <p style="font-weight: bold; color: var(--cyber-blue);">{getattr(decision, 'posture_label', 'Unknown')}</p>
                        <p style="font-size:11px; margin-top:8px; padding:6px 12px; border-radius:8px; background:rgba(0,0,0,0.3);">
                            {verdict_label_html}
                        </p>
                    </div>
                </div>

                <div class="decision-box" style="border-left-color: var(--neutral);">
                    <h3>🛡️ WSPM v2.2 Methodology Declaration</h3>
                    <div class="methodology-grid">
                        <div class="methodology-card" style="grid-column: span 2; border-left: 5px solid #17a2b8;">
                            <strong>🧠 Strategic Model Identification</strong><br>
                            <span style="font-size: 0.85em;">Model: Stabilized Multiplicative Risk with Dynamic K-Factor (WSPM v2.2)</span>
                        </div>

                        <div class="methodology-card" style="border-left: 5px solid var(--info);">
                            <strong>📐 Risk Exposure Formula</strong>
                            <div class="math-formula" style="font-size: 1.1em; margin: 10px 0;">
                                SPI = 100 &times; e<sup>-({exposure_capped} / {dynamic_k})</sup>
                            </div>
                            <div style="font-size: 10px; color: var(--text-dim); border-top: 1px solid var(--border); pt-5px; margin-top: 5px;">
                                Weighted Exposure: <b>{exposure_capped}</b> | K: <b>{dynamic_k}</b>
                            </div>
                        </div>

                        <div class="methodology-card" style="border-left: 5px solid var(--cyber-blue);">
                            <strong>📊 Context Distribution</strong>

                            <div style="margin-top:10px; font-size:11px;">

                                <div style="margin-bottom:8px;">
                                    Core/Prod: {core_contribution}%
                                    <div style="background:var(--border); height:8px; border-radius:4px; margin-top:4px;">
                                        <div class="progress-fill"
                                            style="background:var(--critical); width:{core_contribution}%; height:100%; border-radius:4px;">
                                        </div>
                                    </div>
                                </div>

                                <div>
                                    Test/Noise: {test_contribution}%
                                    <div style="background:var(--border); height:8px; border-radius:4px; margin-top:4px;">
                                        <div class="progress-fill"
                                            style="background:var(--neutral); width:{test_contribution}%; height:100%; border-radius:4px;">
                                        </div>
                                    </div>
                                </div>

                            </div>
                        </div>

                        <div class="methodology-card" style="border-left: 5px solid var(--neutral);">
                            <strong>🔗 Reachability Breakdown</strong>
                            <div style="margin-top:10px; font-size:11px;">
                                Reachable: {reach_perc}% 
                                <div style="background:var(--border); height:6px; border-radius:3px; margin-bottom:4px;">
                                    <div style="background:var(--critical); width:{reach_perc}%; height:100%; border-radius:3px;"></div>
                                </div>
                                Static-Safe: {safe_perc}% 
                                <div style="background:var(--border); height:6px; border-radius:3px; margin-bottom:4px;">
                                    <div style="background:var(--low); width:{safe_perc}%; height:100%; border-radius:3px;"></div>
                                </div>
                                Unknown: {unknown_perc}% 
                                <div style="background:var(--border); height:6px; border-radius:3px;">
                                    <div style="background:var(--neutral); width:{unknown_perc}%; height:100%; border-radius:3px;"></div>
                                </div>
                            </div>
                        </div>

                        <div class="methodology-card sensitivity">
                            <strong>🔬 Sensitivity Snapshot</strong>
                            <div style="margin-top:5px; font-size:11px; line-height: 1.4;">
                                <span style="color:var(--text-dim);">Worst-case scenario: if all unverified findings
                                became confirmed exploitable, SPI would drop to:</span><br>
                                <div class="sensitivity-value">
                                    {sensitive_spi}
                                </div>
                                <span style="font-size:10px; color:var(--text-dim);">
                                    ⚠️ Hypothetical — not the current score
                                </span>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="decision-box" style="border-left-color: #1a2a3a;">
                    <h3 style="margin-top:0; font-size:14px;">🔎 Quick Analysis Filters</h3>
                    <button class="filter-btn active" style="background:#1a2a3a; color:white;" onclick="filterTable('all', this)">ALL ({total_findings})</button>
                    <button class="filter-btn" style="background:#ff4d4d; color:white;" onclick="filterTable('critical', this)">CRITICAL ({stats.get('CRITICAL', 0)})</button>
                    <button class="filter-btn" style="background:#ff944d; color:white;" onclick="filterTable('high', this)">HIGH ({stats.get('HIGH', 0)})</button>
                    <button class="filter-btn" style="background:#ffdb4d; color:#333;" onclick="filterTable('medium', this)">MEDIUM ({stats.get('MEDIUM', 0)})</button>
                    <button class="filter-btn" style="background:#4dff88; color:#333;" onclick="filterTable('low', this)">LOW ({stats.get('LOW', 0)})</button>
                    <button class="filter-btn" style="background:var(--cyber-blue); color:white;" onclick="filterTable('info', this)">INFO ({stats.get('INFO', 0)})</button>
                </div>

                <table>
                    <thead>
                        <tr><th style="width:120px;">Severity</th><th style="width:180px;">Rule ID</th><th style="width:250px;">Location</th><th>Detector</th><th>Description</th><th style="width:90px;">CWE</th><th style="width:60px;">CVSS</th></tr>
                    </thead>
                    <tbody id="findings-table">
                        {finding_rows}
                    </tbody>
                </table>
                
                <div class="footer">
                    &copy; {datetime.now().year} DataWizual Lab - Auditor Core Enterprise.<br>
                    <span style="font-size:10px;">This report does not constitute a formal SOC 2 audit opinion. For SOC 2 Type I/II certification, engage a licensed CPA firm. Confidential — for named recipient only.</span>
                </div>
            </div>

            <script>
                function filterTable(severity, btn) {{
                    // Update buttons
                    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                    btn.classList.add('active');
                    
                    // Filter rows
                    const rows = document.querySelectorAll('.finding-row');
                    rows.forEach(row => {{
                        if (severity === 'all' || row.getAttribute('data-severity') === severity) {{
                            row.style.display = '';
                        }} else {{
                            row.style.display = 'none';
                        }}
                    }});
                }}
            </script>
        </body>
        </html>
        """

        try:
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            # Use report_file instead of f to avoid variable name conflict
            with open(full_path, "w", encoding="utf-8") as report_file:
                report_file.write(html_content)
            logger.info(f"HTML Reporter: Success. Report saved at {full_path}")
            return full_path
        except Exception as e:
            logger.error(f"HTML Reporter: Write failure: {e}")
