#!/usr/bin/env python3
"""
generate_briefing_powerpoint.py
Generates an enterprise-grade 16:9 widescreen PowerPoint presentation (.pptx)
for VulnFlow AI Enterprise Architecture Briefing (13 Slides) using pure Python
standard library (zipfile + OpenXML). Zero external pip dependencies required.
"""

import os
import zipfile

def create_shape(sp_id, name, x, y, cx, cy, fill_color=None, border_color=None, border_w=19050):
    fill_xml = f'<a:solidClr><a:srgbClr val="{fill_color}"/></a:solidClr>' if fill_color else '<a:noFill/>'
    ln_xml = f'''<a:ln w="{border_w}">
      <a:solidClr><a:srgbClr val="{border_color}"/></a:solidClr>
    </a:ln>''' if border_color else '<a:ln><a:noFill/></a:ln>'
    
    return f'''<p:sp>
      <p:nvSpPr>
        <p:cNvPr id="{sp_id}" name="{name}"/>
        <p:cNvSpPr/>
        <p:nvPr/>
      </p:nvSpPr>
      <p:spPr>
        <a:xfrm><a:off x="{x}" y="{y}"/><a:ext cx="{cx}" cy="{cy}"/></a:xfrm>
        <a:prstGeom prst="roundRect"><a:avLst><a:gd name="adj" fmla="val 2000"/></a:avLst></a:prstGeom>
        {fill_xml}
        {ln_xml}
      </p:spPr>
    </p:sp>'''

def create_textbox(sp_id, name, x, y, cx, cy, paragraphs):
    p_xml_list = []
    for p_runs in paragraphs:
        runs_xml = ""
        for (text, sz, bold, color, mono) in p_runs:
            b_attr = ' b="1"' if bold else ''
            font_family = "ui-monospace" if mono else "Helvetica Neue"
            escaped_text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            runs_xml += f'''<a:r>
              <a:rPr lang="en-US" sz="{sz}"{b_attr}>
                <a:solidClr><a:srgbClr val="{color}"/></a:solidClr>
                <a:latin typeface="{font_family}"/>
              </a:rPr>
              <a:t>{escaped_text}</a:t>
            </a:r>'''
        p_xml_list.append(f'<a:p><a:pPr marL="0" indent="0"/>{runs_xml}</a:p>')

    all_p = "".join(p_xml_list)
    return f'''<p:sp>
      <p:nvSpPr>
        <p:cNvPr id="{sp_id}" name="{name}"/>
        <p:cNvSpPr><a:spLocks noGrp="1"/></p:cNvSpPr>
        <p:nvPr/>
      </p:nvSpPr>
      <p:spPr>
        <a:xfrm><a:off x="{x}" y="{y}"/><a:ext cx="{cx}" cy="{cy}"/></a:xfrm>
        <a:prstGeom prst="rect"><a:avLst/></a:prstGeom>
        <a:noFill/>
      </p:spPr>
      <p:txBody>
        <a:bodyPr vert="horz" lIns="91440" tIns="91440" rIns="91440" bIns="91440" rtlCol="0"/>
        <a:lstStyle/>
        {all_p}
      </p:txBody>
    </p:sp>'''

def generate_slide_xml(slide_num, title, tagline, subtitle, body_shapes_xml):
    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
       xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
       xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:cSld>
    <p:bg>
      <p:bgPr>
        <a:solidClr><a:srgbClr val="080C14"/></a:solidClr>
      </p:bgPr>
    </p:bg>
    <p:spTree>
      <p:nvGrpSpPr>
        <p:cNvPr id="1" name=""/>
        <p:cNvGrpSpPr/>
        <p:nvPr/>
      </p:nvGrpSpPr>
      <p:grpSpPr>
        <a:xfrm><a:off x="0" y="0"/><a:ext cx="12192000" cy="6858000"/></a:xfrm>
      </p:grpSpPr>

      <!-- Top Header / Title -->
      {create_textbox(2, "Header", 600000, 380000, 10980000, 1300000, [
          [(tagline.upper(), 1050, True, "10B981", False)],
          [(title, 2500, True, "F8FAFC", False)],
          [(subtitle, 1250, False, "94A3B8", False)]
      ])}

      <!-- Custom Body Shapes -->
      {body_shapes_xml}

      <!-- Footer -->
      {create_textbox(999, "Footer", 600000, 6300000, 10980000, 400000, [
          [(f"VULNFLOW AI ARCHITECTURE BRIEFING • SLIDE {slide_num:02d} / 13", 950, False, "64748B", False)]
      ])}
    </p:spTree>
  </p:cSld>
  <p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr>
</p:sld>'''

def build_presentation_pptx(output_path):
    slides_xml = []

    # ==========================================
    # SLIDE 1: Title / Hero
    # ==========================================
    s1_shapes = f"""
    {create_shape(10, "Card1", 600000, 2200000, 3450000, 2400000, fill_color="0F172A", border_color="06B6D4")}
    {create_textbox(11, "T1", 750000, 2350000, 3150000, 2100000, [
        [("🤖 LLM Agents Propose", 1500, True, "38BDF8", False)],
        [("", 400, False, "000000", False)],
        [("Specialized AI agents inspect advisory vectors, traverse dependency trees, and formulate targeted remediation candidates.", 1200, False, "CBD5E1", False)]
    ])}

    {create_shape(20, "Card2", 4360000, 2200000, 3450000, 2400000, fill_color="0F172A", border_color="10B981")}
    {create_textbox(21, "T2", 4510000, 2350000, 3150000, 2100000, [
        [("⚙️ Deterministic Code Executes", 1500, True, "34D399", False)],
        [("", 400, False, "000000", False)],
        [("Hard policy enforcement, SemVer constraints, and package whitelists run strictly in deterministic code—never hallucinated by an LLM.", 1200, False, "CBD5E1", False)]
    ])}

    {create_shape(30, "Card3", 8120000, 2200000, 3450000, 2400000, fill_color="0F172A", border_color="8B5CF6")}
    {create_textbox(31, "T3", 8270000, 2350000, 3150000, 2100000, [
        [("🔍 Scanners Verify", 1500, True, "C084FC", False)],
        [("", 400, False, "000000", False)],
        [("Patches are built and pre-tested in isolated ephemeral sandboxes, then rescanned to mathematically verify CVE elimination before opening PRs.", 1200, False, "CBD5E1", False)]
    ])}

    {create_shape(40, "PillStrip", 600000, 4900000, 10980000, 800000, fill_color="111827", border_color="334155")}
    {create_textbox(41, "PT", 800000, 5050000, 10580000, 500000, [
        [("LangGraph State Machine   •   FastMCP Tool Isolation   •   Supabase Durable Approvals   •   Neo4j Dependency Graph", 1200, True, "10B981", True)]
    ])}
    """
    slides_xml.append(generate_slide_xml(1, "VulnFlow AI", "Enterprise Architecture Briefing", "Agentic vulnerability remediation: from scanner noise to verified pull requests", s1_shapes))

    # ==========================================
    # SLIDE 2: Problem Statement
    # ==========================================
    s2_shapes = f"""
    {create_shape(10, "Banner", 600000, 1900000, 10980000, 950000, fill_color="1E1B2E", border_color="F43F5E")}
    {create_textbox(11, "BT", 800000, 2020000, 10580000, 750000, [
        [("THE CORE PROBLEM:", 1200, True, "FB7185", False)],
        [("Scanners tell teams what is vulnerable, but turning findings into safe, policy-compliant, verified fixes is still manual, slow and risky at scale.", 1350, True, "F8FAFC", False)]
    ])}

    {create_shape(20, "P1", 600000, 3050000, 3450000, 2900000, fill_color="0F172A", border_color="F43F5E")}
    {create_textbox(21, "PT1", 750000, 3200000, 3150000, 2600000, [
        [("👥 Who Feels It", 1400, True, "FB7185", False)],
        [("", 300, False, "000000", False)],
        [("• Developers lose sprint hours to triage and manual lockfile upgrades.", 1150, False, "CBD5E1", False)],
        [("• Security cannot see which cascading findings share a single fix.", 1150, False, "CBD5E1", False)],
        [("• Leaders see escalating CVE backlogs, not verified closure.", 1150, False, "CBD5E1", False)]
    ])}

    {create_shape(30, "P2", 4360000, 3050000, 3450000, 2900000, fill_color="0F172A", border_color="F59E0B")}
    {create_textbox(31, "PT2", 4510000, 3200000, 3150000, 2600000, [
        [("⚠️ Why Tools Fall Short", 1400, True, "FBBF24", False)],
        [("", 300, False, "000000", False)],
        [("• Scanners stop at detection, leaving 100% of the fix toil to engineers.", 1150, False, "CBD5E1", False)],
        [("• Bump bots bump versions blindly without root-cause or policy context.", 1150, False, "CBD5E1", False)],
        [("• Blind upgrades are rarely compiled, tested, or rescanned first.", 1150, False, "CBD5E1", False)]
    ])}

    {create_shape(40, "P3", 8120000, 3050000, 3450000, 2900000, fill_color="0F172A", border_color="10B981")}
    {create_textbox(41, "PT3", 8270000, 3200000, 3150000, 2600000, [
        [("🎯 What Solution Must Do", 1400, True, "34D399", False)],
        [("", 300, False, "000000", False)],
        [("• Group findings by direct transitive root cause.", 1150, False, "CBD5E1", False)],
        [("• Enforce policy in code (whitelists, SemVer, licenses).", 1150, False, "CBD5E1", False)],
        [("• Test in a sandbox and verify by rescan diff.", 1150, False, "CBD5E1", False)],
        [("• Keep humans in the loop on high-risk major changes.", 1150, False, "CBD5E1", False)]
    ])}
    """
    slides_xml.append(generate_slide_xml(2, "Problem Statement", "The Gap VulnFlow is Built to Close", "Scanners tell teams what is vulnerable, but turning findings into verified fixes remains manual.", s2_shapes))

    # ==========================================
    # SLIDE 3: Detection is Mature
    # ==========================================
    s3_shapes = f"""
    {create_shape(10, "P1", 600000, 2000000, 3450000, 2400000, fill_color="0F172A", border_color="F43F5E")}
    {create_textbox(11, "PT1", 750000, 2150000, 3150000, 2100000, [
        [("🔔 Alert Noise", 1400, True, "FB7185", False)],
        [("", 300, False, "000000", False)],
        [("Every scanner reports every CVE in every location. Repositories accumulate hundreds of duplicated alerts and backlogs outgrow human triage bandwidth.", 1150, False, "CBD5E1", False)]
    ])}

    {create_shape(20, "P2", 4360000, 2000000, 3450000, 2400000, fill_color="0F172A", border_color="F59E0B")}
    {create_textbox(21, "PT2", 4510000, 2150000, 3150000, 2100000, [
        [("🌳 Duplicate Root Causes", 1400, True, "FBBF24", False)],
        [("", 300, False, "000000", False)],
        [("One outdated direct dependency fans out into dozens of transitive findings across lockfiles that share a single common root-cause fix.", 1150, False, "CBD5E1", False)]
    ])}

    {create_shape(30, "P3", 8120000, 2000000, 3450000, 2400000, fill_color="0F172A", border_color="8B5CF6")}
    {create_textbox(31, "PT3", 8270000, 2150000, 3150000, 2100000, [
        [("🛠️ Toil and Risk", 1400, True, "C084FC", False)],
        [("", 300, False, "000000", False)],
        [("Triage, policy checks, sandbox testing, and PR writing are manual. Blind bot upgrades break builds and stall CI/CD pipelines.", 1150, False, "CBD5E1", False)]
    ])}

    {create_shape(40, "MetricBox", 600000, 4650000, 10980000, 1350000, fill_color="0B132B", border_color="10B981")}
    {create_textbox(41, "MT", 850000, 4800000, 10480000, 1050000, [
        [("REAL SCAN DATA POINT:", 1100, True, "10B981", False)],
        [("426 findings analyzed ➔ 43 root causes identified", 1800, True, "F8FAFC", False)],
        [("Single test repository, shown for illustration. Not an average. 10x noise reduction by grouping transitive findings by direct manifest.", 1150, False, "94A3B8", False)]
    ])}
    """
    slides_xml.append(generate_slide_xml(3, "Detection is Mature. Remediation is Still Manual.", "The Operational Reality", "Where the gap shows up: three pain points and one real data point.", s3_shapes))

    # ==========================================
    # SLIDE 4: How VulnFlow Differs
    # ==========================================
    s4_shapes = f"""
    {create_shape(10, "TableCard", 600000, 1950000, 10980000, 3850000, fill_color="0F172A", border_color="334155")}
    {create_textbox(11, "TT", 800000, 2100000, 10580000, 3550000, [
        [("CAPABILITY                                   SCANNERS       BUMP BOTS       VENDOR AUTOFIX     VULNFLOW AI", 1150, True, "94A3B8", True)],
        [("---------------------------------------------------------------------------------------------------------------------------------", 900, False, "475569", True)],
        [("Ingests findings from many scanners          Built in       Not a focus     Partial            ✅ Built in", 1100, False, "F8FAFC", True)],
        [("Groups findings into root causes             Partial        Not a focus     Partial            ✅ Built in", 1100, False, "F8FAFC", True)],
        [("Enforces org policy as code                  Partial        Partial         Partial            ✅ Built in", 1100, False, "F8FAFC", True)],
        [("Tests fix in sandbox before PR               Not a focus    Partial         Partial            ✅ Built in", 1100, False, "F8FAFC", True)],
        [("Rescans to prove fix worked                  Partial        Not a focus     Partial            ✅ Built in", 1100, False, "F8FAFC", True)],
        [("Gated approvals with audit trail             Not a focus    Partial         Partial            ✅ Built in", 1100, False, "F8FAFC", True)],
        [("Agent retries when fix fails                 Not a focus    Not a focus     Partial            ✅ Built in", 1100, False, "F8FAFC", True)]
    ])}
    {create_textbox(20, "Note", 600000, 5900000, 10980000, 350000, [
        [("Note: Category-level view; capabilities vary by product. Bump bots: Dependabot / Renovate style. Vendor autofix: scanner remediation features.", 950, False, "64748B", False)]
    ])}
    """
    slides_xml.append(generate_slide_xml(4, "How VulnFlow Differs from Existing Tools", "Market Differentiation", "Detection, bump bots and vendor autofix each cover part of the loop. VulnFlow closes it.", s4_shapes))

    # ==========================================
    # SLIDE 5: Four Tiers with Hard Boundaries
    # ==========================================
    s5_shapes = f"""
    {create_shape(10, "Tier1", 600000, 2000000, 2550000, 2500000, fill_color="0F172A", border_color="06B6D4")}
    {create_textbox(11, "T1", 750000, 2150000, 2250000, 2200000, [
        [("TIER 1 • INGEST", 1000, True, "38BDF8", False)],
        [("Ingest & Redaction", 1300, True, "F8FAFC", False)],
        [("", 200, False, "000000", False)],
        [("• Reads Trivy, Grype, Gitleaks, Snyk", 1100, False, "CBD5E1", False)],
        [("• Redacts secrets at edge", 1100, False, "CBD5E1", False)],
        [("• Fingerprints & dedupes", 1100, False, "CBD5E1", False)]
    ])}

    {create_shape(20, "Tier2", 3410000, 2000000, 2550000, 2500000, fill_color="0F172A", border_color="10B981")}
    {create_textbox(21, "T2", 3560000, 2150000, 2250000, 2200000, [
        [("TIER 2 • ORCHESTRATION", 1000, True, "34D399", False)],
        [("Agent Orchestration", 1300, True, "F8FAFC", False)],
        [("", 200, False, "000000", False)],
        [("• LangGraph, 10 nodes", 1100, False, "CBD5E1", False)],
        [("• Triage, planner, fixer, verifier", 1100, False, "CBD5E1", False)],
        [("• Human approval gate", 1100, False, "CBD5E1", False)]
    ])}

    {create_shape(30, "Tier3", 6220000, 2000000, 2550000, 2500000, fill_color="0F172A", border_color="F59E0B")}
    {create_textbox(31, "T3", 6370000, 2150000, 2250000, 2200000, [
        [("TIER 3 • TOOLS (MCP)", 1000, True, "FBBF24", False)],
        [("FastMCP Tool Servers", 1300, True, "F8FAFC", False)],
        [("", 200, False, "000000", False)],
        [("• Stdio servers, zero pip deps", 1100, False, "CBD5E1", False)],
        [("• git, build, scan, policy tools", 1100, False, "CBD5E1", False)],
        [("• All side effects live here", 1100, False, "CBD5E1", False)]
    ])}

    {create_shape(40, "Tier4", 9030000, 2000000, 2550000, 2500000, fill_color="0F172A", border_color="8B5CF6")}
    {create_textbox(41, "T4", 9180000, 2150000, 2250000, 2200000, [
        [("TIER 4 • VERIFICATION", 1000, True, "C084FC", False)],
        [("Sandbox & Knowledge", 1300, True, "F8FAFC", False)],
        [("", 200, False, "000000", False)],
        [("• Docker sandbox runs tests", 1100, False, "CBD5E1", False)],
        [("• Neo4j dependency graph RAG", 1100, False, "CBD5E1", False)],
        [("• Vector RAG: advisories", 1100, False, "CBD5E1", False)]
    ])}

    {create_shape(50, "BottomBar", 600000, 4800000, 10980000, 1100000, fill_color="111827", border_color="334155")}
    {create_textbox(51, "BBT", 800000, 4950000, 10580000, 800000, [
        [("Outputs: PR with cited evidence, Jira exception, audit log, OTel traces   •   CI-native: Container step for GH Actions/GitLab", 1100, False, "38BDF8", False)],
        [("Model-agnostic: NVIDIA NIM, Claude, OpenAI, Bedrock, Ollama   •   Control plane: React UI + Supabase durable approvals", 1100, False, "34D399", False)]
    ])}
    """
    slides_xml.append(generate_slide_xml(5, "Four Tiers with Hard Boundaries", "Architectural Boundaries", "Only Tier 2 calls an LLM. Everything that touches code, policy or scans is deterministic.", s5_shapes))

    # ==========================================
    # SLIDE 6: 10-Node Workflow
    # ==========================================
    s6_shapes = f"""
    {create_shape(10, "Row1", 600000, 2000000, 10980000, 1300000, fill_color="0F172A", border_color="334155")}
    {create_textbox(11, "R1T", 750000, 2100000, 10680000, 1100000, [
        [("PHASE 1: INGESTION, DEDUPLICATION & PLANNING", 1100, True, "10B981", False)],
        [("01 Ingest (Code) ➔ 02 Dedupe (Code) ➔ 03 Root Cause (Agent) ➔ 04 Policy Check (Code) ➔ 05 Plan (Agent)", 1250, True, "F8FAFC", True)],
        [("Reads Trivy/Grype/Snyk reports ➔ collapses duplicates ➔ Neo4j graph finds parent ➔ policy whitelist checks ➔ candidate plan formulated", 1050, False, "94A3B8", False)]
    ])}

    {create_shape(20, "Row2", 600000, 3500000, 10980000, 1300000, fill_color="0F172A", border_color="F59E0B")}
    {create_textbox(21, "R2T", 750000, 3600000, 10680000, 1100000, [
        [("PHASE 2: APPROVAL GATE, SANDBOX LOOP & VERIFICATION", 1100, True, "FBBF24", False)],
        [("06 Approval Gate (Human) ➔ 07 Sandbox Loop (Agent) ➔ 08 Pull Request (Code) ➔ 09 Verify (Code) ➔ 10 Audit", 1250, True, "F8FAFC", True)],
        [("Exit code 10 pauses on risky changes ➔ Docker runs tests ➔ PR opened with citations ➔ rescan diff proves CVE count is 0", 1050, False, "94A3B8", False)]
    ])}

    {create_shape(30, "Legend", 600000, 5000000, 10980000, 900000, fill_color="111827", border_color="10B981")}
    {create_textbox(31, "LT", 800000, 5150000, 10580000, 600000, [
        [("LEGEND:  🤖 Agent: LLM reasoning (3 nodes)    |    ⚙️ Deterministic code: Hard rails (6 nodes)    |    🚦 Human decision: Exit 10 (1 node)", 1150, True, "38BDF8", False)]
    ])}
    """
    slides_xml.append(generate_slide_xml(6, "The 10-Node Remediation Workflow", "Operational State Machine", "A checkpointed LangGraph state machine. Each node is an agent, deterministic code, or a human.", s6_shapes))

    # ==========================================
    # SLIDE 7: Agentic AI
    # ==========================================
    s7_shapes = f"""
    {create_shape(10, "A1", 600000, 2000000, 3450000, 1750000, fill_color="0F172A", border_color="06B6D4")}
    {create_textbox(11, "AT1", 750000, 2100000, 3150000, 1550000, [
        [("🎯 Triage Agent", 1300, True, "38BDF8", False)],
        [("Sorts deduplicated findings so the right ones reach planning. Uses fast routing models.", 1100, False, "CBD5E1", False)]
    ])}

    {create_shape(20, "A2", 4360000, 2000000, 3450000, 1750000, fill_color="0F172A", border_color="10B981")}
    {create_textbox(21, "AT2", 4510000, 2100000, 3150000, 1550000, [
        [("🌳 Root-Cause Agent", 1300, True, "34D399", False)],
        [("Traces transitive CVEs to the direct parent using Neo4j graph. Cannot override graph facts.", 1100, False, "CBD5E1", False)]
    ])}

    {create_shape(30, "A3", 8120000, 2000000, 3450000, 1750000, fill_color="0F172A", border_color="8B5CF6")}
    {create_textbox(31, "AT3", 8270000, 2100000, 3150000, 1550000, [
        [("📝 Planner Agent", 1300, True, "C084FC", False)],
        [("Proposes target version & cites vector advisories. The policy engine can reject the plan.", 1100, False, "CBD5E1", False)]
    ])}

    {create_shape(40, "A4", 600000, 3950000, 3450000, 1750000, fill_color="0F172A", border_color="F59E0B")}
    {create_textbox(41, "AT4", 750000, 4050000, 3150000, 1550000, [
        [("🔄 Self-Correcting Fixer", 1300, True, "FBBF24", False)],
        [("Reads compiler logs on test failure, rolls back, and retries safer versions in the sandbox.", 1100, False, "CBD5E1", False)]
    ])}

    {create_shape(50, "A5", 4360000, 3950000, 3450000, 1750000, fill_color="0F172A", border_color="10B981")}
    {create_textbox(51, "AT5", 4510000, 4050000, 3150000, 1550000, [
        [("✅ Verifier Agent", 1300, True, "34D399", False)],
        [("Rescans container diffs before and after. Never reports a failed scan as success.", 1100, False, "CBD5E1", False)]
    ])}

    {create_shape(60, "A6", 8120000, 3950000, 3450000, 1750000, fill_color="0F172A", border_color="F43F5E")}
    {create_textbox(61, "AT6", 8270000, 4050000, 3150000, 1550000, [
        [("🔐 Secrets & Expiry Agents", 1300, True, "FB7185", False)],
        [("Drafts secret rotation checklists & cert warnings. Sees fingerprints, never raw secrets.", 1100, False, "CBD5E1", False)]
    ])}
    """
    slides_xml.append(generate_slide_xml(7, "Agentic AI: Specialized Agents, Bounded Roles", "Multi-Agent Intelligence", "Each agent has one job, its own tools, and a hard limit on what it can decide.", s7_shapes))

    # ==========================================
    # SLIDE 8: Self-Correction Loop
    # ==========================================
    s8_shapes = f"""
    {create_shape(10, "FlowBox", 600000, 1950000, 10980000, 1600000, fill_color="0F172A", border_color="10B981")}
    {create_textbox(11, "FBT", 800000, 2050000, 10580000, 1400000, [
        [("ILLUSTRATIVE ERROR RECOVERY SCENARIO:", 1100, True, "10B981", False)],
        [("1. Patch manifest (Django 4.2 ➔ 5.2)  ➔  2. Docker tests fail [FAIL ❌]  ➔  3. Fixer reads logs & rolls back", 1250, True, "F8FAFC", True)],
        [("4. Fixer retries safer version (Django 5.0.12)  ➔  5. Docker tests pass [PASS ✅]  ➔  6. PR opened with advisory citations", 1250, True, "34D399", True)]
    ])}

    {create_shape(20, "G1", 600000, 3800000, 3450000, 2100000, fill_color="0F172A", border_color="10B981")}
    {create_textbox(21, "GT1", 750000, 3950000, 3150000, 1800000, [
        [("🛡️ No Broken PRs", 1400, True, "34D399", False)],
        [("", 300, False, "000000", False)],
        [("Developers receive a pull request that already passed build and test validation in Docker.", 1150, False, "CBD5E1", False)]
    ])}

    {create_shape(30, "G2", 4360000, 3800000, 3450000, 2100000, fill_color="0F172A", border_color="06B6D4")}
    {create_textbox(31, "GT2", 4510000, 3950000, 3150000, 1800000, [
        [("📦 Safe by Construction", 1400, True, "38BDF8", False)],
        [("", 300, False, "000000", False)],
        [("Patches run in an ephemeral container, never on main branch or developer laptops.", 1150, False, "CBD5E1", False)]
    ])}

    {create_shape(40, "G3", 8120000, 3800000, 3450000, 2100000, fill_color="0F172A", border_color="8B5CF6")}
    {create_textbox(41, "GT3", 8270000, 3950000, 3150000, 1800000, [
        [("📜 Evidence with Fix", 1400, True, "C084FC", False)],
        [("", 300, False, "000000", False)],
        [("The PR cites the advisories behind the chosen version and includes exact test pass proof.", 1150, False, "CBD5E1", False)]
    ])}
    """
    slides_xml.append(generate_slide_xml(8, "Self-Correction: The Loop That Removes Broken PRs", "Autonomous Error Recovery", "When tests fail, the agent reads the evidence and retries before any PR opens.", s8_shapes))

    # ==========================================
    # SLIDE 9: Governance
    # ==========================================
    s9_shapes = f"""
    {create_shape(10, "Col1", 600000, 2000000, 5290000, 3900000, fill_color="0F172A", border_color="F59E0B")}
    {create_textbox(11, "C1T", 800000, 2150000, 4890000, 3600000, [
        [("🚦 Risk Model Enforced in Code", 1400, True, "FBBF24", False)],
        [("", 300, False, "000000", False)],
        [("• AUTO:", 1250, True, "34D399", False)],
        [("  Minor and patch bumps that pass sandbox tests open a PR directly.", 1150, False, "CBD5E1", False)],
        [("", 200, False, "000000", False)],
        [("• REVIEW:", 1250, True, "FBBF24", False)],
        [("  Major upgrades and unknown packages pause the run (Exit Code 10).", 1150, False, "CBD5E1", False)],
        [("", 200, False, "000000", False)],
        [("• BLOCKED:", 1250, True, "FB7185", False)],
        [("  Banned packages open a Jira exception ticket (Exit Code 20).", 1150, False, "CBD5E1", False)],
        [("", 300, False, "000000", False)],
        [("Hard policy code eliminates LLM hallucination and legal license risks.", 1100, True, "94A3B8", False)]
    ])}

    {create_shape(20, "Col2", 6300000, 2000000, 5280000, 3900000, fill_color="0F172A", border_color="06B6D4")}
    {create_textbox(21, "C2T", 6500000, 2150000, 4880000, 3600000, [
        [("📋 Approval Workflow & Roadmap", 1400, True, "38BDF8", False)],
        [("", 300, False, "000000", False)],
        [("• BUILT: Supabase Durable Persistence", 1250, True, "10B981", False)],
        [("  Approval state and checkpoints survive across ephemeral CI workers.", 1150, False, "CBD5E1", False)],
        [("", 300, False, "000000", False)],
        [("• ROADMAP: Enterprise Controls", 1250, True, "38BDF8", False)],
        [("  - SSO identity and group membership routing", 1150, False, "CBD5E1", False)],
        [("  - Per-risk routing with sequential or quorum steps", 1150, False, "CBD5E1", False)],
        [("  - Separation of duties with append-only audit trail", 1150, False, "CBD5E1", False)],
        [("  - Expiry, escalation, and delegation rules", 1150, False, "CBD5E1", False)]
    ])}
    """
    slides_xml.append(generate_slide_xml(9, "Governance: Policy in Code, Humans at the Gates", "Safety & Compliance", "Rules load from YAML, Artifactory, Nexus or OPA. The model never makes the call.", s9_shapes))

    # ==========================================
    # SLIDE 10: Developer Productivity
    # ==========================================
    s10_shapes = f"""
    {create_shape(10, "CompCard", 600000, 1950000, 10980000, 3900000, fill_color="0F172A", border_color="10B981")}
    {create_textbox(11, "CCT", 800000, 2100000, 10580000, 3600000, [
        [("TASK                    TODAY: MANUAL TOIL                             WITH VULNFLOW AI", 1150, True, "10B981", True)],
        [("------------------------------------------------------------------------------------------------------------------------", 900, False, "334155", True)],
        [("🔍 Triage alerts        Sort raw alerts by hand across tools           Agent groups findings into root causes", 1100, False, "F8FAFC", True)],
        [("🌳 Find the cause       Trace deep dependency locks manually           Graph traversal names direct parent", 1100, False, "F8FAFC", True)],
        [("⚖️ Check policy         Cross-reference wikis and spreadsheets         Policy engine checks rules in code", 1100, False, "F8FAFC", True)],
        [("🧪 Test the upgrade     Upgrade, build, test, find breakage            Sandbox tests first; agent retries", 1100, False, "F8FAFC", True)],
        [("📝 Write the PR         Draft PR description, hunt advisory links      PR opens with cited advisory evidence", 1100, False, "F8FAFC", True)],
        [("✅ Prove it is fixed    Merge on green CI and hope rescan passes       Rescan diff mathematically verifies", 1100, False, "F8FAFC", True)]
    ])}
    """
    slides_xml.append(generate_slide_xml(10, "Developer Productivity: From Toil to Review", "Engineering Velocity", "Developer time shifts from doing remediation work to reviewing a verified result.", s10_shapes))

    # ==========================================
    # SLIDE 11: Real Run End to End
    # ==========================================
    s11_shapes = f"""
    {create_shape(10, "M1", 600000, 1950000, 2550000, 1200000, fill_color="0F172A", border_color="F43F5E")}
    {create_textbox(11, "MT1", 750000, 2050000, 2250000, 1000000, [
        [("426", 2200, True, "FB7185", False)],
        [("Findings Analyzed", 1000, True, "94A3B8", False)]
    ])}

    {create_shape(20, "M2", 3410000, 1950000, 2550000, 1200000, fill_color="0F172A", border_color="06B6D4")}
    {create_textbox(21, "MT2", 3560000, 2050000, 2250000, 1000000, [
        [("43", 2200, True, "38BDF8", False)],
        [("Root Causes Grouped", 1000, True, "94A3B8", False)]
    ])}

    {create_shape(30, "M3", 6220000, 1950000, 2550000, 1200000, fill_color="0F172A", border_color="10B981")}
    {create_textbox(31, "MT3", 6370000, 2050000, 2250000, 1000000, [
        [("3", 2200, True, "34D399", False)],
        [("Fixes Formulated", 1000, True, "94A3B8", False)]
    ])}

    {create_shape(40, "M4", 9030000, 1950000, 2550000, 1200000, fill_color="0F172A", border_color="8B5CF6")}
    {create_textbox(41, "MT4", 9180000, 2050000, 2250000, 1000000, [
        [("1", 2200, True, "C084FC", False)],
        [("Verified PR Opened", 1000, True, "94A3B8", False)]
    ])}

    {create_shape(50, "DiffCard", 600000, 3350000, 10980000, 1250000, fill_color="050811", border_color="334155")}
    {create_textbox(51, "DT", 800000, 3450000, 10580000, 1050000, [
        [("package.json:      - \"lodash\": \"4.17.4\"   ➔   + \"lodash\": \"4.18.0\"", 1100, False, "38BDF8", True)],
        [("requirements.txt:  - requests==2.6.0       ➔   + requests==2.33.0", 1100, False, "34D399", True)],
        [("(2 of 3 applied manifest bumps shown • passed all sandbox unit tests)", 950, False, "64748B", True)]
    ])}

    {create_shape(60, "Takeaways", 600000, 4800000, 10980000, 1100000, fill_color="111827", border_color="10B981")}
    {create_textbox(61, "TT", 800000, 4950000, 10580000, 800000, [
        [("Applied: Safe bumps written to manifests and opened as 1 PR   •   Held: Major upgrades paused for approval", 1100, True, "F8FAFC", False)],
        [("Next gate: Rescan diff verification proves target CVEs eliminated before merging to production.", 1100, False, "34D399", False)]
    ])}
    """
    slides_xml.append(generate_slide_xml(11, "A Real Run, End to End", "Execution Case Study", "Output of one VulnFlow run in PR mode on a test repository (Illustrative, not an average).", s11_shapes))

    # ==========================================
    # SLIDE 12: Roadmap & Pilot Metrics
    # ==========================================
    s12_shapes = f"""
    {create_shape(10, "Roadmap", 600000, 2000000, 5290000, 3900000, fill_color="0F172A", border_color="06B6D4")}
    {create_textbox(11, "RT", 800000, 2150000, 4890000, 3600000, [
        [("🗺️ Roadmap Milestones", 1400, True, "38BDF8", False)],
        [("", 300, False, "000000", False)],
        [("• Next: SSO Multi-Approver Workflow", 1250, True, "34D399", False)],
        [("  Routing, append-only audit trail, and escalation.", 1150, False, "CBD5E1", False)],
        [("", 200, False, "000000", False)],
        [("• Then: Org-Wide Campaigns", 1250, True, "38BDF8", False)],
        [("  Multi-repo portfolio view and global waiver policy.", 1150, False, "CBD5E1", False)],
        [("", 200, False, "000000", False)],
        [("• Always: Stable-Release Target Versions", 1250, True, "C084FC", False)],
        [("  Rescan verification on every single execution run.", 1150, False, "CBD5E1", False)]
    ])}

    {create_shape(20, "Metrics", 6300000, 2000000, 5280000, 3900000, fill_color="0F172A", border_color="10B981")}
    {create_textbox(21, "MT", 6500000, 2150000, 4880000, 3600000, [
        [("📊 Pilot Metrics We Will Instrument", 1400, True, "34D399", False)],
        [("", 300, False, "000000", False)],
        [("• ⏱️ Time from scan to PR", 1200, False, "CBD5E1", False)],
        [("• 👨‍💻 Developer review time per PR", 1200, False, "CBD5E1", False)],
        [("• 🚢 PRs merged without edits", 1200, False, "CBD5E1", False)],
        [("• 🧪 First-attempt build pass rate", 1200, False, "CBD5E1", False)],
        [("• 🌳 Findings per root cause", 1200, False, "CBD5E1", False)],
        [("• 🔍 Rescan-verified closures", 1200, False, "CBD5E1", False)],
        [("", 300, False, "000000", False)],
        [("We report measured pilot results. We do not publish projections.", 1050, True, "94A3B8", False)]
    ])}
    """
    slides_xml.append(generate_slide_xml(12, "Roadmap and How We Will Prove the Impact", "Measurable Pilot", "We report measured results from a pilot. We do not publish unverified projections.", s12_shapes))

    # ==========================================
    # SLIDE 13: Summary & Conclusion
    # ==========================================
    s13_shapes = f"""
    {create_shape(10, "Arch", 600000, 2000000, 3450000, 2400000, fill_color="0F172A", border_color="06B6D4")}
    {create_textbox(11, "AT", 750000, 2150000, 3150000, 2100000, [
        [("🏛️ Architecture", 1400, True, "38BDF8", False)],
        [("", 300, False, "000000", False)],
        [("Four tiers with hard boundaries: only agents use an LLM, and nothing the model proposes is applied without code and tests.", 1150, False, "CBD5E1", False)]
    ])}

    {create_shape(20, "Agentic", 4360000, 2000000, 3450000, 2400000, fill_color="0F172A", border_color="8B5CF6")}
    {create_textbox(21, "AGT", 4510000, 2150000, 3150000, 2100000, [
        [("🤖 Agentic AI", 1400, True, "C084FC", False)],
        [("", 300, False, "000000", False)],
        [("Specialized, bounded agents, a self-correcting fixer, and human gates where risk is high.", 1150, False, "CBD5E1", False)]
    ])}

    {create_shape(30, "Devs", 8120000, 2000000, 3450000, 2400000, fill_color="0F172A", border_color="10B981")}
    {create_textbox(31, "DT", 8270000, 2150000, 3150000, 2100000, [
        [("👥 Developers", 1400, True, "34D399", False)],
        [("", 300, False, "000000", False)],
        [("One evidence-backed PR per root cause instead of a long list of alerts to triage.", 1150, False, "CBD5E1", False)]
    ])}

    {create_shape(40, "CTA", 600000, 4650000, 10980000, 1250000, fill_color="111827", border_color="10B981")}
    {create_textbox(41, "CTAT", 800000, 4800000, 10580000, 950000, [
        [("PROPOSED NEXT STEP: A pilot on two or three repositories, measured as on slide 12.", 1250, True, "10B981", False)],
        [("Commands: vulnflow scan --repo . --mode report     •     vulnflow serve", 1200, True, "F8FAFC", True)]
    ])}
    """
    slides_xml.append(generate_slide_xml(13, "Agents Propose. Code Decides. Scanners Verify.", "Conclusion & Pilot Next Step", "Transforming vulnerability management from manual toil into verified, autonomous velocity.", s13_shapes))

    # ==========================================
    # SLIDE 14: THANK YOU / Q&A & DISCUSSION
    # ==========================================
    s14_shapes = f"""
    {create_shape(10, "Card1", 600000, 2000000, 3450000, 2600000, fill_color="0F172A", border_color="10B981")}
    {create_textbox(11, "C1T", 750000, 2150000, 3150000, 2300000, [
        [("🚀 Pilot Deployment", 1400, True, "34D399", False)],
        [("", 300, False, "000000", False)],
        [("Deploy on 2-3 target repositories to instrument cycle-time reduction, pass rates, and verified closures.", 1150, False, "CBD5E1", False)]
    ])}

    {create_shape(20, "Card2", 4360000, 2000000, 3450000, 2600000, fill_color="0F172A", border_color="06B6D4")}
    {create_textbox(21, "C2T", 4510000, 2150000, 3150000, 2300000, [
        [("⚡ CLI & Dashboard", 1400, True, "38BDF8", False)],
        [("", 300, False, "000000", False)],
        [("Run report or PR mode natively in CI/CD:", 1150, False, "CBD5E1", False)],
        [("", 200, False, "000000", False)],
        [("vulnflow scan --repo . --mode pr", 1100, True, "10B981", True)]
    ])}

    {create_shape(30, "Card3", 8120000, 2000000, 3450000, 2600000, fill_color="0F172A", border_color="8B5CF6")}
    {create_textbox(31, "C3T", 8270000, 2150000, 3150000, 2300000, [
        [("💬 Q&A & Architecture", 1400, True, "C084FC", False)],
        [("", 300, False, "000000", False)],
        [("Open for discussion on agentic orchestration, FastMCP sandboxes, and Supabase persistent governance.", 1150, False, "CBD5E1", False)]
    ])}
    """
    slides_xml.append(generate_slide_xml(14, "Thank You", "VulnFlow AI Briefing", "Turning security scanner noise into safe, verified, policy-compliant pull requests.", s14_shapes))

    # ==========================================
    # Package into OpenXML PPTX
    # ==========================================
    total_slides = len(slides_xml)
    sld_id_lst_xml = "".join([f'<p:sldId id="{256 + i}" r:id="rId{i+1}"/>' for i in range(total_slides)])
    pres_rels_xml = "".join([f'<Relationship Id="rId{i+1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide{i+1}.xml"/>' for i in range(total_slides)])
    pres_rels_xml += f'<Relationship Id="rId{total_slides+1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="slideMasters/slideMaster1.xml"/>'

    content_types_slides = "".join([f'<Override PartName="/ppt/slides/slide{i+1}.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>' for i in range(total_slides)])

    content_types_xml = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>
  <Override PartName="/ppt/slideMasters/slideMaster1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml"/>
  <Override PartName="/ppt/slideLayouts/slideLayout1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml"/>
  <Override PartName="/ppt/theme/theme1.xml" ContentType="application/vnd.openxmlformats-officedocument.theme+xml"/>
  {content_types_slides}
</Types>'''

    root_rels_xml = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/>
</Relationships>'''

    presentation_xml = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:presentation xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
                xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
                xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:sldMasterIdLst>
    <p:sldMasterId id="2147483648" r:id="rId{total_slides+1}"/>
  </p:sldMasterIdLst>
  <p:sldIdLst>
    {sld_id_lst_xml}
  </p:sldIdLst>
  <p:sldSz cx="12192000" cy="6858000" type="screen16x9"/>
  <p:notesSz cx="6858000" cy="9144000"/>
</p:presentation>'''

    slide_master_xml = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sldMaster xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
             xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
             xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:cSld>
    <p:bg><p:bgPr><a:solidClr><a:srgbClr val="080C14"/></a:solidClr></p:bgPr></p:bg>
    <p:spTree>
      <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
      <p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="12192000" cy="6858000"/></a:xfrm></p:grpSpPr>
    </p:spTree>
  </p:cSld>
  <p:clrMap bg1="dk1" tx1="lt1" bg2="dk2" tx2="lt2" accent1="accent1" accent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/>
  <p:sldLayoutIdLst>
    <p:sldLayoutId id="2147483649" r:id="rId1"/>
  </p:sldLayoutIdLst>
</p:sldMaster>'''

    slide_master_rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="../theme/theme1.xml"/>
</Relationships>'''

    slide_layout_xml = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sldLayout xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
             xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
             xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" type="blank">
  <p:cSld>
    <p:spTree>
      <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
      <p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="12192000" cy="6858000"/></a:xfrm></p:grpSpPr>
    </p:spTree>
  </p:cSld>
  <p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr>
</p:sldLayout>'''

    slide_layout_rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="../slideMasters/slideMaster1.xml"/>
</Relationships>'''

    theme_xml = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" name="VulnFlow Obsidian">
  <a:themeElements>
    <a:clrScheme name="VulnFlow">
      <a:dk1><a:srgbClr val="080C14"/></a:dk1>
      <a:lt1><a:srgbClr val="F8FAFC"/></a:lt1>
      <a:dk2><a:srgbClr val="0F172A"/></a:dk2>
      <a:lt2><a:srgbClr val="94A3B8"/></a:lt2>
      <a:accent1><a:srgbClr val="10B981"/></a:accent1>
      <a:accent2><a:srgbClr val="06B6D4"/></a:accent2>
      <a:accent3><a:srgbClr val="8B5CF6"/></a:accent3>
      <a:accent4><a:srgbClr val="F59E0B"/></a:accent4>
      <a:accent5><a:srgbClr val="F43F5E"/></a:accent5>
      <a:accent6><a:srgbClr val="3B82F6"/></a:accent6>
      <a:hlink><a:srgbClr val="38BDF8"/></a:hlink>
      <a:folHlink><a:srgbClr val="818CF8"/></a:folHlink>
    </a:clrScheme>
    <a:fontScheme name="Modern">
      <a:majorFont><a:latin typeface="Helvetica Neue"/></a:majorFont>
      <a:minorFont><a:latin typeface="Helvetica Neue"/></a:minorFont>
    </a:fontScheme>
    <a:fmtScheme name="Office">
      <a:fillStyleLst><a:solidClr><a:srgbClr val="0F172A"/></a:solidClr></a:fillStyleLst>
      <a:lnStyleLst><a:ln w="12700"><a:solidClr><a:srgbClr val="334155"/></a:solidClr></a:ln></a:lnStyleLst>
      <a:effectStyleLst><a:effectStyle><a:effectLst/></a:effectStyle></a:effectStyleLst>
      <a:bgFillStyleLst><a:solidClr><a:srgbClr val="080C14"/></a:solidClr></a:bgFillStyleLst>
    </a:fmtScheme>
  </a:themeElements>
</a:theme>'''

    slide_rels_xml = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/>
</Relationships>'''

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types_xml)
        zf.writestr("_rels/.rels", root_rels_xml)
        zf.writestr("ppt/presentation.xml", presentation_xml)
        zf.writestr("ppt/_rels/presentation.xml.rels", pres_rels_xml)
        zf.writestr("ppt/slideMasters/slideMaster1.xml", slide_master_xml)
        zf.writestr("ppt/slideMasters/_rels/slideMaster1.xml.rels", slide_master_rels)
        zf.writestr("ppt/slideLayouts/slideLayout1.xml", slide_layout_xml)
        zf.writestr("ppt/slideLayouts/_rels/slideLayout1.xml.rels", slide_layout_rels)
        zf.writestr("ppt/theme/theme1.xml", theme_xml)
        for i, sld_xml in enumerate(slides_xml):
            zf.writestr(f"ppt/slides/slide{i+1}.xml", sld_xml)
            zf.writestr(f"ppt/slides/_rels/slide{i+1}.xml.rels", slide_rels_xml)

    print(f"Successfully generated {total_slides}-slide PPTX presentation at: {output_path}")

if __name__ == "__main__":
    out = "demo_assets/VulnFlow_Architecture_Briefing.pptx"
    build_presentation_pptx(out)
