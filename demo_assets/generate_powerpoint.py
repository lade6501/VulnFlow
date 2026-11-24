#!/usr/bin/env python3
"""
generate_powerpoint.py
Generates an enterprise-grade 16:9 widescreen PowerPoint presentation (.pptx)
for VulnFlow AI using pure Python standard library (zipfile + XML).
Zero external pip dependencies required.
"""

import os
import zipfile

def create_shape(sp_id, name, x, y, cx, cy, fill_color=None, border_color=None, border_w=19050):
    """Generates OpenXML shape property XML."""
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
    """
    paragraphs: list of list of runs.
    Each run: (text, font_size_pt_x100, is_bold, color_hex, is_mono)
    """
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
        <a:ln><a:noFill/></a:ln>
      </p:spPr>
      <p:txBody>
        <a:bodyPr vert="horz" lIns="91440" tIns="91440" rIns="91440" bIns="91440" wrap="square"/>
        <a:lstStyle/>
        {all_p}
      </p:txBody>
    </p:sp>'''

def generate_slide_xml(slide_num, title, tagline, subtitle, shapes_xml):
    """Builds a complete slide XML with dark background, header, and shapes."""
    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
       xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
       xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:cSld>
    <p:spTree>
      <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
      <p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>
      
      <!-- Slide Background (Deep Obsidian) -->
      <p:sp>
        <p:nvSpPr><p:cNvPr id="2" name="SlideBg"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr>
          <a:xfrm><a:off x="0" y="0"/><a:ext cx="12192000" cy="6858000"/></a:xfrm>
          <a:prstGeom prst="rect"><a:avLst/></a:prstGeom>
          <a:solidClr><a:srgbClr val="080C14"/></a:solidClr>
        </p:spPr>
      </p:sp>

      <!-- Top Accent Bar (Emerald Glow) -->
      <p:sp>
        <p:nvSpPr><p:cNvPr id="3" name="TopAccent"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
        <p:spPr>
          <a:xfrm><a:off x="600000" y="300000"/><a:ext cx="10992000" cy="30000"/></a:xfrm>
          <a:prstGeom prst="rect"><a:avLst/></a:prstGeom>
          <a:solidClr><a:srgbClr val="10B981"/></a:solidClr>
        </p:spPr>
      </p:sp>

      <!-- Header: Tagline, Title, Subtitle -->
      {create_textbox(4, "Header", 600000, 450000, 10992000, 1100000, [
          [ (f"🛡️ {tagline.upper()}", 1100, True, "10B981", False) ],
          [ (title, 2500, True, "F8FAFC", False) ],
          [ (subtitle, 1250, False, "94A3B8", False) ]
      ])}

      <!-- Custom Slide Content Shapes -->
      {shapes_xml}

      <!-- Footer Bar -->
      {create_textbox(99, "Footer", 600000, 6350000, 10992000, 300000, [
          [
              ("VULNFLOW AI • AUTONOMOUS VULNERABILITY REMEDIATION", 1000, False, "64748B", False),
              (f"                                                                                                                    SLIDE {slide_num:02d} / 10", 1000, True, "10B981", True)
          ]
      ])}

    </p:spTree>
  </p:cSld>
  <p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr>
</p:sld>'''

def build_presentation(output_path):
    print(f"Building Enterprise PowerPoint presentation: {output_path}...")

    slides_xml = []

    # ==========================================
    # SLIDE 1: Title & Hero
    # ==========================================
    s1_shapes = f"""
    <!-- Card 1 -->
    {create_shape(10, "C1", 600000, 2000000, 3400000, 2800000, fill_color="0F172A", border_color="10B981")}
    {create_textbox(11, "T1", 800000, 2200000, 3000000, 2400000, [
        [("🛡️ Closed-Loop Remediation", 1800, True, "10B981", False)],
        [("", 800, False, "000000", False)],
        [("• LLM proposes safe version patches.", 1300, False, "E2E8F0", False)],
        [("• Deterministic tools execute manifest updates.", 1300, False, "E2E8F0", False)],
        [("• Security scanners verify residual CVEs.", 1300, False, "E2E8F0", False)],
        [("• Invariant: Failed scan is NEVER reported as success.", 1300, True, "34D399", False)]
    ])}

    <!-- Card 2 -->
    {create_shape(20, "C2", 4400000, 2000000, 3400000, 2800000, fill_color="0F172A", border_color="06B6D4")}
    {create_textbox(21, "T2", 4600000, 2200000, 3000000, 2400000, [
        [("🤖 10-Node State Machine", 1800, True, "06B6D4", False)],
        [("", 800, False, "000000", False)],
        [("• LangGraph interruptible state machine.", 1300, False, "E2E8F0", False)],
        [("• Neo4j graph root-cause grouping.", 1300, False, "E2E8F0", False)],
        [("• Ephemeral Docker sandbox test execution.", 1300, False, "E2E8F0", False)],
        [("• Self-correcting retry rollback loops.", 1300, True, "38BDF8", False)]
    ])}

    <!-- Card 3 -->
    {create_shape(30, "C3", 8200000, 2000000, 3400000, 2800000, fill_color="0F172A", border_color="8B5CF6")}
    {create_textbox(31, "T3", 8400000, 2200000, 3000000, 2400000, [
        [("📐 Deterministic Governance", 1800, True, "8B5CF6", False)],
        [("", 800, False, "000000", False)],
        [("• Pure-code policy engine (no hallucinations).", 1300, False, "E2E8F0", False)],
        [("• Whitelist, SemVer, and license constraints.", 1300, False, "E2E8F0", False)],
        [("• Human-in-the-loop review gate (Exit Code 10).", 1300, False, "E2E8F0", False)],
        [("• Secrets redacted at edge ingestion.", 1300, True, "C084FC", False)]
    ])}

    <!-- Bottom Banner -->
    {create_shape(40, "Banner", 600000, 5100000, 11000000, 900000, fill_color="111827", border_color="334155")}
    {create_textbox(41, "BT", 800000, 5250000, 10600000, 600000, [
        [
            ("ENTERPRISE STACK: ", 1200, True, "10B981", False),
            ("FastMCP JSON-RPC Protocol • Multi-LLM (NVIDIA, Anthropic, OpenAI, Ollama) • OpenTelemetry Tracing", 1200, False, "94A3B8", False)
        ]
    ])}
    """
    slides_xml.append(generate_slide_xml(
        1, "VulnFlow AI: Autonomous Remediation Platform",
        "Enterprise Architecture Briefing",
        "Turning raw security scanner noise into verified, policy-compliant pull requests without developer toil.",
        s1_shapes
    ))

    # ==========================================
    # SLIDE 2: The Developer Productivity Trap
    # ==========================================
    s2_shapes = f"""
    <!-- Pain 1 -->
    {create_shape(10, "P1", 600000, 2000000, 2550000, 2300000, fill_color="0F172A", border_color="EF4444")}
    {create_textbox(11, "PT1", 750000, 2150000, 2250000, 2000000, [
        [("🔍 Multi-Scanner Noise", 1400, True, "F87171", False)],
        [("Alert Duplication", 1000, True, "94A3B8", False)],
        [("", 400, False, "000000", False)],
        [("Trivy, Grype, and Snyk output fragmented reports. Engineers waste sprint hours manually correlating CVE IDs.", 1150, False, "CBD5E1", False)]
    ])}

    <!-- Pain 2 -->
    {create_shape(20, "P2", 3410000, 2000000, 2550000, 2300000, fill_color="0F172A", border_color="F59E0B")}
    {create_textbox(21, "PT2", 3560000, 2150000, 2250000, 2000000, [
        [("🌳 Transitive Explosion", 1400, True, "FBBF24", False)],
        [("Dependency Chaos", 1000, True, "94A3B8", False)],
        [("", 400, False, "000000", False)],
        [("A single deep transitive vulnerability triggers alerts across dozens of packages. Tracing root causes is manual toil.", 1150, False, "CBD5E1", False)]
    ])}

    <!-- Pain 3 -->
    {create_shape(30, "P3", 6220000, 2000000, 2550000, 2300000, fill_color="0F172A", border_color="8B5CF6")}
    {create_textbox(31, "PT3", 6370000, 2150000, 2250000, 2000000, [
        [("💥 Blind Upgrade Breaks", 1400, True, "C084FC", False)],
        [("Broken CI Pipelines", 1000, True, "94A3B8", False)],
        [("", 400, False, "000000", False)],
        [("Traditional bots bump versions blindly. Breaking API changes trigger compiler errors and broken CI/CD builds.", 1150, False, "CBD5E1", False)]
    ])}

    <!-- Pain 4 -->
    {create_shape(40, "P4", 9030000, 2000000, 2550000, 2300000, fill_color="0F172A", border_color="06B6D4")}
    {create_textbox(41, "PT4", 9180000, 2150000, 2250000, 2000000, [
        [("⚖️ Policy & License Risk", 1400, True, "38BDF8", False)],
        [("Governance Friction", 1000, True, "94A3B8", False)],
        [("", 400, False, "000000", False)],
        [("Upgrades risk introducing unapproved libraries or restrictive copyleft licenses (GPL/AGPL) violating corporate policy.", 1150, False, "CBD5E1", False)]
    ])}

    <!-- Bottom Dilemma Card -->
    {create_shape(50, "Dilemma", 600000, 4600000, 10980000, 1400000, fill_color="111827", border_color="EF4444")}
    {create_textbox(51, "DT", 900000, 4750000, 10380000, 1100000, [
        [("🚨 The Core Enterprise Dilemma: Detection is Solved. Remediation is Broken.", 1400, True, "F87171", False)],
        [("", 300, False, "000000", False)],
        [("Security scanners give visibility, but engineering teams carry the operational burden. DevSecOps needs an autonomous, trustworthy layer that safely formulates, sandbox-tests, and verifies code fixes before opening PRs.", 1200, False, "E2E8F0", False)]
    ])}
    """
    slides_xml.append(generate_slide_xml(
        2, "The Developer Productivity Trap: Remediation Toil",
        "The Engineering Bottleneck",
        "Modern security scanning creates visibility, but product engineers bear the crushing operational burden of manual remediation.",
        s2_shapes
    ))

    # ==========================================
    # SLIDE 3: Market Comparison & Differentiation
    # ==========================================
    s3_shapes = f"""
    <!-- Category 1: Scanners -->
    {create_shape(10, "C1", 600000, 2000000, 2600000, 3200000, fill_color="0F172A", border_color="475569")}
    {create_textbox(11, "CT1", 750000, 2150000, 2300000, 2900000, [
        [("Static Scanners", 1400, True, "94A3B8", False)],
        [("Trivy, Snyk, Grype", 1000, True, "64748B", False)],
        [("", 400, False, "000000", False)],
        [("• Detection only (no code fixes).", 1150, False, "CBD5E1", False)],
        [("• No transitive root-cause grouping.", 1150, False, "CBD5E1", False)],
        [("• Dumps raw CVE lists on backlogs.", 1150, False, "CBD5E1", False)],
        [("• Leaves 100% toil to developers.", 1150, False, "CBD5E1", False)]
    ])}

    <!-- Category 2: Dependency Bots -->
    {create_shape(20, "C2", 3400000, 2000000, 2600000, 3200000, fill_color="0F172A", border_color="F59E0B")}
    {create_textbox(21, "CT2", 3550000, 2150000, 2300000, 2900000, [
        [("Dependency Bots", 1400, True, "FBBF24", False)],
        [("Dependabot, Renovate", 1000, True, "64748B", False)],
        [("", 400, False, "000000", False)],
        [("• Blind version bumping.", 1150, False, "CBD5E1", False)],
        [("• No pre-PR sandbox testing.", 1150, False, "CBD5E1", False)],
        [("• Frequent broken builds in CI.", 1150, False, "CBD5E1", False)],
        [("• Ignores corporate whitelists.", 1150, False, "CBD5E1", False)]
    ])}

    <!-- Category 3: Generic AI -->
    {create_shape(30, "C3", 6200000, 2000000, 2600000, 3200000, fill_color="0F172A", border_color="8B5CF6")}
    {create_textbox(31, "CT3", 6350000, 2150000, 2300000, 2900000, [
        [("Generic LLM Tools", 1400, True, "C084FC", False)],
        [("Copilot, ChatGPT Prompts", 1000, True, "64748B", False)],
        [("", 400, False, "000000", False)],
        [("• Hallucinates fake package versions.", 1150, False, "CBD5E1", False)],
        [("• Plaintext secrets leak into prompts.", 1150, False, "CBD5E1", False)],
        [("• No deterministic policy enforcement.", 1150, False, "CBD5E1", False)],
        [("• Unconstrained, unverified edits.", 1150, False, "CBD5E1", False)]
    ])}

    <!-- Category 4: VulnFlow AI -->
    {create_shape(40, "C4", 9000000, 2000000, 2600000, 3200000, fill_color="081C15", border_color="10B981")}
    {create_textbox(41, "CT4", 9150000, 2150000, 2300000, 2900000, [
        [("🛡️ VulnFlow AI", 1500, True, "34D399", False)],
        [("Autonomous Verifiable Layer", 1000, True, "10B981", False)],
        [("", 400, False, "000000", False)],
        [("• Neo4j graph root-cause collapse.", 1150, True, "E2E8F0", False)],
        [("• Deterministic policy whitelisting.", 1150, True, "E2E8F0", False)],
        [("• Ephemeral sandbox self-correction.", 1150, True, "E2E8F0", False)],
        [("• Invariant rescan diff verification.", 1150, True, "10B981", False)]
    ])}

    <!-- Golden Rule Callout -->
    {create_shape(50, "Rule", 600000, 5400000, 11000000, 650000, fill_color="0B0F19", border_color="06B6D4")}
    {create_textbox(51, "RuleT", 800000, 5520000, 10600000, 450000, [
        [
            ("THE ARCHITECTURAL DIFFERENCE: ", 1250, True, "06B6D4", False),
            ('"LLMs propose remediation candidates. Deterministic tools execute changes. Scanners verify ground truth."', 1250, False, "F8FAFC", False)
        ]
    ])}
    """
    slides_xml.append(generate_slide_xml(
        3, "How VulnFlow Compares to Existing Market Solutions",
        "Market Differentiation",
        "A fundamental paradigm shift from passive scanning and blind version bumps to closed-loop verifiable remediation.",
        s3_shapes
    ))

    # ==========================================
    # SLIDE 4: 4-Tier Architecture
    # ==========================================
    s4_shapes = f"""
    <!-- Tier 1 -->
    {create_shape(10, "T1", 600000, 2000000, 2600000, 3900000, fill_color="0F172A", border_color="06B6D4")}
    {create_textbox(11, "TT1", 750000, 2150000, 2300000, 3600000, [
        [("TIER 1", 1100, True, "06B6D4", True)],
        [("Scanner Ingest & Redaction", 1500, True, "F8FAFC", False)],
        [("", 600, False, "000000", False)],
        [("• Ingests Trivy, Grype, Gitleaks, Snyk (SARIF / JSON).", 1200, False, "CBD5E1", False)],
        [("", 400, False, "000000", False)],
        [("• Edge Redaction: Strips API keys, JWTs, and passwords before prompt construction.", 1200, False, "CBD5E1", False)],
        [("", 400, False, "000000", False)],
        [("• Deduplication engine eliminates duplicate scanner reports.", 1200, False, "CBD5E1", False)]
    ])}

    <!-- Tier 2 -->
    {create_shape(20, "T2", 3400000, 2000000, 2600000, 3900000, fill_color="0F172A", border_color="10B981")}
    {create_textbox(21, "TT2", 3550000, 2150000, 2300000, 3600000, [
        [("TIER 2", 1100, True, "10B981", True)],
        [("LangGraph & Multi-Agent", 1500, True, "F8FAFC", False)],
        [("", 600, False, "000000", False)],
        [("• 10-node state machine with checkpointing.", 1200, False, "CBD5E1", False)],
        [("", 400, False, "000000", False)],
        [("• Specialized agents: Triage, Root-Cause, Planner, Fixer, Verifier.", 1200, False, "CBD5E1", False)],
        [("", 400, False, "000000", False)],
        [("• Human review gate on risky upgrades (Exit Code 10).", 1200, False, "CBD5E1", False)]
    ])}

    <!-- Tier 3 -->
    {create_shape(30, "T3", 6200000, 2000000, 2600000, 3900000, fill_color="0F172A", border_color="F59E0B")}
    {create_textbox(31, "TT3", 6350000, 2150000, 2300000, 3600000, [
        [("TIER 3", 1100, True, "F59E0B", True)],
        [("FastMCP Tool Servers", 1500, True, "F8FAFC", False)],
        [("", 600, False, "000000", False)],
        [("• Zero-dependency Anthropic Model Context Protocol stdio servers.", 1200, False, "CBD5E1", False)],
        [("", 400, False, "000000", False)],
        [("• git_server, build_server, scan_server, policy_server.", 1200, False, "CBD5E1", False)],
        [("", 400, False, "000000", False)],
        [("• Strict side-effect isolation.", 1200, False, "CBD5E1", False)]
    ])}

    <!-- Tier 4 -->
    {create_shape(40, "T4", 9000000, 2000000, 2600000, 3900000, fill_color="0F172A", border_color="8B5CF6")}
    {create_textbox(41, "TT4", 9150000, 2150000, 2300000, 3600000, [
        [("TIER 4", 1100, True, "8B5CF6", True)],
        [("Sandbox & Knowledge RAG", 1500, True, "F8FAFC", False)],
        [("", 600, False, "000000", False)],
        [("• Ephemeral Docker container sandbox builds & tests patches.", 1200, False, "CBD5E1", False)],
        [("", 400, False, "000000", False)],
        [("• Neo4j Graph RAG: blast radius & dependency paths.", 1200, False, "CBD5E1", False)],
        [("", 400, False, "000000", False)],
        [("• Vector RAG: security advisories & breaking change playbooks.", 1200, False, "CBD5E1", False)]
    ])}
    """
    slides_xml.append(generate_slide_xml(
        4, "4-Tier Modular Enterprise Architecture",
        "Technical Architecture",
        "Strict boundary isolation between generative intelligence, deterministic policy, and sandboxed execution.",
        s4_shapes
    ))

    # ==========================================
    # SLIDE 5: 10-Node State Machine
    # ==========================================
    s5_shapes = f"""
    <!-- Stage 1-5 Row -->
    {create_shape(10, "Row1", 600000, 2000000, 11000000, 1500000, fill_color="0F172A", border_color="334155")}
    {create_textbox(11, "R1T", 800000, 2150000, 10600000, 1200000, [
        [("PHASE 1: INGESTION & POLICY TRIAGE", 1200, True, "06B6D4", True)],
        [("", 400, False, "000000", False)],
        [("[01 Ingest] ➔ [02 Dedupe] ➔ [03 Root-Cause Grouping] ➔ [04 Policy Check] ➔ [05 Plan Node]", 1400, True, "F8FAFC", True)],
        [("", 400, False, "000000", False)],
        [("Parses scanner JSON/SARIF ➔ Collapses transitive tree in Neo4j ➔ Validates approved whitelist & SemVer constraints.", 1200, False, "94A3B8", False)]
    ])}

    <!-- Stage 6 Approval Box -->
    {create_shape(20, "Gate", 600000, 3700000, 3500000, 2200000, fill_color="1C1917", border_color="F59E0B")}
    {create_textbox(21, "GT", 800000, 3850000, 3100000, 1900000, [
        [("[06 Approval Gate]", 1400, True, "F59E0B", True)],
        [("Human Authorization Checkpoint", 1300, True, "F8FAFC", False)],
        [("", 400, False, "000000", False)],
        [("• Pauses on REVIEW tier (major bumps, unknown pkg).", 1150, False, "CBD5E1", False)],
        [("• Emits Exit Code 10 and stores pending_state.json.", 1150, False, "CBD5E1", False)],
        [("• Resumed via vulnflow approve CLI or Web UI.", 1150, True, "FCD34D", False)]
    ])}

    <!-- Stage 7 Sandbox -->
    {create_shape(30, "Sand", 4350000, 3700000, 3500000, 2200000, fill_color="0F172A", border_color="10B981")}
    {create_textbox(31, "ST", 4550000, 3850000, 3100000, 1900000, [
        [("[07 Sandbox Test Loop]", 1400, True, "10B981", True)],
        [("Self-Correcting Test Runner", 1300, True, "F8FAFC", False)],
        [("", 400, False, "000000", False)],
        [("• Patches manifest in isolated container.", 1150, False, "CBD5E1", False)],
        [("• Executes build & full unit test suite.", 1150, False, "CBD5E1", False)],
        [("• On test failure: analyzes error & retries conservative version.", 1150, True, "34D399", False)]
    ])}

    <!-- Stage 8-10 Delivery -->
    {create_shape(40, "Deliv", 8100000, 3700000, 3500000, 2200000, fill_color="0F172A", border_color="8B5CF6")}
    {create_textbox(41, "DT", 8300000, 3850000, 3100000, 1900000, [
        [("[08 PR] ➔ [09 Verify] ➔ [10 Audit]", 1400, True, "8B5CF6", True)],
        [("Verified Delivery & Invariants", 1300, True, "F8FAFC", False)],
        [("", 400, False, "000000", False)],
        [("• Opens GitHub PR with cited advisory evidence.", 1150, False, "CBD5E1", False)],
        [("• Runs rescan diff to verify 0 residual CVEs.", 1150, False, "CBD5E1", False)],
        [("• Appends to audit log & emits OpenTelemetry traces.", 1150, True, "C084FC", False)]
    ])}
    """
    slides_xml.append(generate_slide_xml(
        5, "The 10-Node Remediation State Machine",
        "Operational State Machine",
        "Deterministic LangGraph workflow coordinating root-cause analysis, sandboxed self-correction, and PR verification.",
        s5_shapes
    ))

    # ==========================================
    # SLIDE 6: Agentic AI Capabilities
    # ==========================================
    s6_shapes = f"""
    <!-- Agent 1 -->
    {create_shape(10, "A1", 600000, 2000000, 3400000, 2500000, fill_color="0F172A", border_color="06B6D4")}
    {create_textbox(11, "AT1", 800000, 2150000, 3000000, 2200000, [
        [("🌳 Root-Cause Agent", 1500, True, "06B6D4", False)],
        [("Graph RAG Traversal", 1100, True, "94A3B8", False)],
        [("", 400, False, "000000", False)],
        [("• Traverses Neo4j dependency trees to trace transitive CVEs to direct parent manifests.", 1200, False, "CBD5E1", False)],
        [("• Invariant: Cannot override graph facts.", 1150, True, "38BDF8", False)]
    ])}

    <!-- Agent 2 -->
    {create_shape(20, "A2", 4400000, 2000000, 3400000, 2500000, fill_color="0F172A", border_color="10B981")}
    {create_textbox(21, "AT2", 4600000, 2150000, 3000000, 2200000, [
        [("🔁 Self-Correcting Fixer", 1500, True, "10B981", False)],
        [("Sandbox Test Recovery Loop", 1100, True, "94A3B8", False)],
        [("", 400, False, "000000", False)],
        [("• When build or tests fail in sandbox, analyzes compiler errors & breaking API diffs.", 1200, False, "CBD5E1", False)],
        [("• Automatically rolls back & tests safe fallbacks.", 1150, True, "34D399", False)]
    ])}

    <!-- Agent 3 -->
    {create_shape(30, "A3", 8200000, 2000000, 3400000, 2500000, fill_color="0F172A", border_color="8B5CF6")}
    {create_textbox(31, "AT3", 8400000, 2150000, 3000000, 2200000, [
        [("🔒 Secrets & Expiry Agents", 1500, True, "8B5CF6", False)],
        [("Proactive Threat Remediation", 1100, True, "94A3B8", False)],
        [("", 400, False, "000000", False)],
        [("• Generates rotation checklists for leaked secrets.", 1200, False, "CBD5E1", False)],
        [("• Predicts TLS certificate and artifact expirations before scanners flag downtime.", 1200, False, "CBD5E1", False)]
    ])}

    <!-- Self-Correction Step-by-Step Flow -->
    {create_shape(40, "LoopBox", 600000, 4800000, 11000000, 1200000, fill_color="080C14", border_color="10B981")}
    {create_textbox(41, "LoopT", 800000, 4950000, 10600000, 900000, [
        [("AUTONOMOUS SELF-CORRECTION IN ACTION:", 1200, True, "10B981", True)],
        [("1. Patch manifest (Django 4.2 ➔ 5.2)  ➔  2. Run sandbox tests (FAIL: Breaking API)  ➔  3. Agent analyzes compiler logs & falls back to Django 5.0.12  ➔  4. Tests pass (0 errors)  ➔  5. Open PR", 1250, False, "F8FAFC", True)]
    ])}
    """
    slides_xml.append(generate_slide_xml(
        6, "Agentic AI Capabilities & Self-Correction",
        "Agentic Intelligence",
        "Goal-driven autonomous agents with bounded roles, multi-step reasoning, and closed-loop error recovery.",
        s6_shapes
    ))

    # ==========================================
    # SLIDE 7: Enterprise Governance & Safety
    # ==========================================
    s7_shapes = f"""
    <!-- Policy -->
    {create_shape(10, "P1", 600000, 2000000, 3400000, 2700000, fill_color="0F172A", border_color="10B981")}
    {create_textbox(11, "PT1", 800000, 2150000, 3000000, 2400000, [
        [("📜 Code-First Policy", 1600, True, "10B981", False)],
        [("Zero-Hallucination Guarantees", 1100, True, "94A3B8", False)],
        [("", 400, False, "000000", False)],
        [("• Evaluates allowed packages, SemVer ranges, and licenses (e.g. GPL-3.0 restrictions) in deterministic code.", 1250, False, "CBD5E1", False)],
        [("", 400, False, "000000", False)],
        [("• Loads from YAML, Artifactory, Nexus, or OPA.", 1250, False, "CBD5E1", False)],
        [("• Decisions never rely on LLM judgment.", 1200, True, "34D399", False)]
    ])}

    <!-- Risk Tiers -->
    {create_shape(20, "P2", 4400000, 2000000, 3400000, 2700000, fill_color="0F172A", border_color="F59E0B")}
    {create_textbox(21, "PT2", 4600000, 2150000, 3000000, 2400000, [
        [("🚦 3-Tier Risk Model", 1600, True, "F59E0B", False)],
        [("Predictable Enforcement", 1100, True, "94A3B8", False)],
        [("", 400, False, "000000", False)],
        [("• AUTO: Minor bumps with passing sandbox tests ➔ Immediate PR creation.", 1200, False, "CBD5E1", False)],
        [("", 300, False, "000000", False)],
        [("• REVIEW: Major upgrades, unknown packages ➔ Pauses run (Exit Code 10).", 1200, False, "CBD5E1", False)],
        [("", 300, False, "000000", False)],
        [("• BLOCKED: Banned packages ➔ Opens Jira exception ticket (Exit Code 20).", 1200, False, "CBD5E1", False)]
    ])}

    <!-- Redaction -->
    {create_shape(30, "P3", 8200000, 2000000, 3400000, 2700000, fill_color="0F172A", border_color="06B6D4")}
    {create_textbox(31, "PT3", 8400000, 2150000, 3000000, 2400000, [
        [("🔐 Edge Secret Stripping", 1600, True, "06B6D4", False)],
        [("Zero-Knowledge Security", 1100, True, "94A3B8", False)],
        [("", 400, False, "000000", False)],
        [("• Secrets, private keys, and bearer tokens are redacted at the ingestion boundary.", 1250, False, "CBD5E1", False)],
        [("", 400, False, "000000", False)],
        [("• Only fingerprints and line numbers travel to LLM prompts, traces, or logs.", 1250, False, "CBD5E1", False)],
        [("• Absolute confidentiality guarantee.", 1200, True, "38BDF8", False)]
    ])}

    <!-- Reviewer Command Box -->
    {create_shape(40, "RevBox", 600000, 5000000, 11000000, 1000000, fill_color="18181B", border_color="F59E0B")}
    {create_textbox(41, "RevT", 800000, 5150000, 10600000, 700000, [
        [("SECURITY LEAD APPROVAL & RESUME COMMAND (EXIT CODE 10):", 1100, True, "F59E0B", True)],
        [("vulnflow approve --plan-id PLAN-ebaaef6720e2 --reviewer \"sec-lead@corp.com\" --resume", 1300, True, "F8FAFC", True)]
    ])}
    """
    slides_xml.append(generate_slide_xml(
        7, "Deterministic Policy & Human-in-the-Loop Gates",
        "Safety, Trust & Governance",
        "Giving enterprise security leaders total control with verifiable risk boundaries and zero model hallucinations.",
        s7_shapes
    ))

    # ==========================================
    # SLIDE 8: FastMCP & Ecosystem
    # ==========================================
    s8_shapes = f"""
    <!-- MCP -->
    {create_shape(10, "E1", 600000, 2000000, 3400000, 2700000, fill_color="0F172A", border_color="06B6D4")}
    {create_textbox(11, "ET1", 800000, 2150000, 3000000, 2400000, [
        [("⚡ FastMCP Protocol Suite", 1600, True, "06B6D4", False)],
        [("Standardized Tool Architecture", 1100, True, "94A3B8", False)],
        [("", 400, False, "000000", False)],
        [("• Built on Anthropic's Model Context Protocol (FastMCP JSON-RPC).", 1250, False, "CBD5E1", False)],
        [("• Zero pip dependencies for standalone stdio servers.", 1250, False, "CBD5E1", False)],
        [("• Plugs natively into Cursor, Claude Desktop, or custom orchestrators.", 1250, False, "CBD5E1", False)]
    ])}

    <!-- CI/CD -->
    {create_shape(20, "E2", 4400000, 2000000, 3400000, 2700000, fill_color="0F172A", border_color="10B981")}
    {create_textbox(21, "ET2", 4600000, 2150000, 3000000, 2400000, [
        [("🚢 Universal CI/CD Container", 1600, True, "10B981", False)],
        [("Single Docker Container Step", 1100, True, "94A3B8", False)],
        [("", 400, False, "000000", False)],
        [("• Drop-in container step for GitHub Actions, GitLab CI, and Jenkins.", 1250, False, "CBD5E1", False)],
        [("• Standard exit codes: 0 (Success), 10 (Approval Required), 20 (Exception).", 1250, False, "CBD5E1", False)],
        [("• Universal launcher: ./run.sh scan --mode pr", 1250, True, "34D399", True)]
    ])}

    <!-- Multi LLM -->
    {create_shape(30, "E3", 8200000, 2000000, 3400000, 2700000, fill_color="0F172A", border_color="8B5CF6")}
    {create_textbox(31, "ET3", 8400000, 2150000, 3000000, 2400000, [
        [("🔀 Multi-LLM Provider Layer", 1600, True, "8B5CF6", False)],
        [("Role-Based Model Factory", 1100, True, "94A3B8", False)],
        [("", 400, False, "000000", False)],
        [("• Swappable backend: NVIDIA NIM, Anthropic Claude, OpenAI, Bedrock, or Ollama.", 1250, False, "CBD5E1", False)],
        [("• Role routing: Fast models for triage, high-reasoning for planning.", 1250, False, "CBD5E1", False)],
        [("• Offline fallback when no LLM key is configured.", 1250, False, "CBD5E1", False)]
    ])}

    <!-- Web Dashboard Banner -->
    {create_shape(40, "Dash", 600000, 5000000, 11000000, 1000000, fill_color="111827", border_color="334155")}
    {create_textbox(41, "DashT", 800000, 5150000, 10600000, 700000, [
        [("🖥️ CONTROL PLANE: WEB DASHBOARD & REST API (vulnflow serve)", 1200, True, "F8FAFC", False)],
        [("Real-time React control plane to inspect active runs, approval queues, dependency blast radius, and audit logs.", 1200, False, "94A3B8", False)]
    ])}
    """
    slides_xml.append(generate_slide_xml(
        8, "FastMCP Protocol & Universal CI/CD Integration",
        "Integrations & Extensibility",
        "Zero vendor lock-in. Modular FastMCP servers, single-container CI/CD execution, and swappable LLMs.",
        s8_shapes
    ))

    # ==========================================
    # SLIDE 9: Live Execution Walkthrough
    # ==========================================
    s9_shapes = f"""
    <!-- Terminal Background Box -->
    {create_shape(10, "TermBox", 600000, 2000000, 11000000, 4000000, fill_color="050811", border_color="334155")}
    {create_textbox(11, "TermText", 900000, 2200000, 10400000, 3600000, [
        [("user@devsecops:~$ vulnflow scan --repo fake-vuln-repo --mode pr", 1300, True, "38BDF8", True)],
        [("", 300, False, "000000", False)],
        [("[00:01] 🔍 [Ingest] Ingesting Trivy report (38 findings detected across repo)...", 1200, False, "94A3B8", True)],
        [("[00:02] 🧹 [Dedupe] Fingerprinting findings: collapsed 38 reports ➔ 6 distinct CVEs.", 1200, False, "94A3B8", True)],
        [("[00:03] 🌳 [RootCause] Neo4j graph traversal identified direct parent: axios@0.21.1", 1200, True, "C084FC", True)],
        [("[00:04] ⚖️ [Policy] Corporate policy check: axios ➔ target allowed (>=1.7.4)", 1200, True, "34D399", True)],
        [("[00:05] 📝 [Plan] Formulating RemediationPlan [PLAN-SEC-8f3a]: bump axios 0.21.1 ➔ 1.7.4", 1200, False, "F8FAFC", True)],
        [("[00:06] 🚦 [RiskTier] Calculated tier: AUTO (patch verified within SemVer bounds)", 1200, True, "FBBF24", True)],
        [("[00:07] 🧪 [Sandbox] Spawning ephemeral Docker container; running npm test & build...", 1200, False, "94A3B8", True)],
        [("[00:10] ✅ [Sandbox] Build & 42 unit tests passed cleanly (0 errors).", 1200, True, "34D399", True)],
        [("[00:11] 🚀 [PR] Created branch vulnflow/fix-axios-cve; opened GitHub PR #42", 1200, True, "38BDF8", True)],
        [("[00:13] 🔍 [Verify] Triggering rescan diff: 0 remaining CVEs. VERIFICATION_SUCCESS!", 1200, True, "34D399", True)],
        [("====================================================================", 1200, False, "64748B", True)],
        [("🛡️  VulnFlow Execution Summary: RUN-8a4e19b SUCCESS (Exit Code: 0)", 1300, True, "10B981", True)]
    ])}
    """
    slides_xml.append(generate_slide_xml(
        9, "End-to-End Live Execution Walkthrough",
        "Live Execution Demo",
        "Real-world execution showing root-cause correlation, sandbox testing, and verified PR generation.",
        s9_shapes
    ))

    # ==========================================
    # SLIDE 10: Developer Productivity Impact
    # ==========================================
    s10_shapes = f"""
    <!-- Dividend 1 -->
    {create_shape(10, "B1", 600000, 2000000, 2550000, 2300000, fill_color="0F172A", border_color="10B981")}
    {create_textbox(11, "BT1", 750000, 2150000, 2250000, 2000000, [
        [("🧹 Zero Triage Toil", 1400, True, "34D399", False)],
        [("Root-Cause Collapse", 1000, True, "94A3B8", False)],
        [("", 400, False, "000000", False)],
        [("Neo4j graph RAG collapses dozens of cascading transitive CVE alerts into one direct parent fix. Review 1 PR instead of 30 tickets.", 1150, False, "CBD5E1", False)]
    ])}

    <!-- Dividend 2 -->
    {create_shape(20, "B2", 3410000, 2000000, 2550000, 2300000, fill_color="0F172A", border_color="06B6D4")}
    {create_textbox(21, "BT2", 3560000, 2150000, 2250000, 2000000, [
        [("🛡️ Zero Broken CI Builds", 1400, True, "38BDF8", False)],
        [("Pre-Tested Sandboxing", 1000, True, "94A3B8", False)],
        [("", 400, False, "000000", False)],
        [("Every patch is pre-compiled and tested against your unit test suite in an isolated ephemeral container before PR creation.", 1150, False, "CBD5E1", False)]
    ])}

    <!-- Dividend 3 -->
    {create_shape(30, "B3", 6220000, 2000000, 2550000, 2300000, fill_color="0F172A", border_color="8B5CF6")}
    {create_textbox(31, "BT3", 6370000, 2150000, 2250000, 2000000, [
        [("🔄 Self-Healing Fixes", 1400, True, "C084FC", False)],
        [("Autonomous Recovery", 1000, True, "94A3B8", False)],
        [("", 400, False, "000000", False)],
        [("When an update breaks compiler or unit tests, the agent analyzes error logs, rolls back, and retries conservative versions.", 1150, False, "CBD5E1", False)]
    ])}

    <!-- Dividend 4 -->
    {create_shape(40, "B4", 9030000, 2000000, 2550000, 2300000, fill_color="0F172A", border_color="F59E0B")}
    {create_textbox(41, "BT4", 9180000, 2150000, 2250000, 2000000, [
        [("⚖️ 100% Policy Guardrails", 1400, True, "FBBF24", False)],
        [("Deterministic Compliance", 1000, True, "94A3B8", False)],
        [("", 400, False, "000000", False)],
        [("Whitelists, SemVer bounds, and software licenses are enforced by deterministic Python code—eliminating model hallucinations.", 1150, False, "CBD5E1", False)]
    ])}

    <!-- Final Call to Action Card -->
    {create_shape(50, "Cta", 600000, 4600000, 10980000, 1400000, fill_color="0B0F19", border_color="10B981")}
    {create_textbox(51, "CtaT", 900000, 4750000, 10380000, 1100000, [
        [("The Core Takeaway for Product & Security Leaders:", 1400, True, "10B981", False)],
        [("", 300, False, "000000", False)],
        [("Developers are hired to ship revenue-generating features, not debug dependency locks. VulnFlow AI offloads remediation toil: vulnflow scan --repo . --mode pr", 1200, False, "F8FAFC", False)]
    ])}
    """
    slides_xml.append(generate_slide_xml(
        10, "Reclaiming Engineering Velocity from Remediation Toil",
        "Developer Productivity Impact",
        "Transforming security from an engineering bottleneck into an automated, verified pipeline advantage.",
        s10_shapes
    ))

    # ==========================================
    # Package everything into OpenXML PPTX Zip
    # ==========================================
    with zipfile.ZipFile(output_path, 'w', compression=zipfile.ZIP_DEFLATED) as z:
        # 1. [Content_Types].xml
        ct_overrides = ""
        for i in range(1, 11):
            ct_overrides += f'<Override PartName="/ppt/slides/slide{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>\n'

        z.writestr('[Content_Types].xml', f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>
  <Override PartName="/ppt/slideMasters/slideMaster1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml"/>
  <Override PartName="/ppt/slideLayouts/slideLayout1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml"/>
  <Override PartName="/ppt/theme/theme1.xml" ContentType="application/vnd.openxmlformats-officedocument.theme+xml"/>
  {ct_overrides}
</Types>''')

        # 2. _rels/.rels
        z.writestr('_rels/.rels', '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/>
</Relationships>''')

        # 3. ppt/_rels/presentation.xml.rels
        pres_rels = '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="slideMasters/slideMaster1.xml"/>\n'
        for i in range(1, 11):
            pres_rels += f'<Relationship Id="rId{i+1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide{i}.xml"/>\n'
        pres_rels += '<Relationship Id="rId12" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="theme/theme1.xml"/>\n'

        z.writestr('ppt/_rels/presentation.xml.rels', f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  {pres_rels}
</Relationships>''')

        # 4. ppt/presentation.xml
        sld_ids = ""
        for i in range(1, 11):
            sld_ids += f'<p:sldId id="{255+i}" r:id="rId{i+1}"/>\n'

        z.writestr('ppt/presentation.xml', f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:presentation xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
                xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
                xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:sldMasterIdLst>
    <p:sldMasterId id="2147483648" r:id="rId1"/>
  </p:sldMasterIdLst>
  <p:sldIdLst>
    {sld_ids}
  </p:sldIdLst>
  <p:sldSz cx="12192000" cy="6858000" type="screen16x9"/>
  <p:notesSz cx="6858000" cy="9144000"/>
</p:presentation>''')

        # 5. ppt/theme/theme1.xml
        z.writestr('ppt/theme/theme1.xml', '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" name="EnterpriseDark">
  <a:themeElements>
    <a:clrScheme name="Enterprise">
      <a:dk1><a:srgbClr val="080C14"/></a:dk1>
      <a:lt1><a:srgbClr val="F8FAFC"/></a:lt1>
      <a:dk2><a:srgbClr val="0F172A"/></a:dk2>
      <a:lt2><a:srgbClr val="E2E8F0"/></a:lt2>
      <a:accent1><a:srgbClr val="10B981"/></a:accent1>
      <a:accent2><a:srgbClr val="06B6D4"/></a:accent2>
      <a:accent3><a:srgbClr val="3B82F6"/></a:accent3>
      <a:accent4><a:srgbClr val="F59E0B"/></a:accent4>
      <a:accent5><a:srgbClr val="8B5CF6"/></a:accent5>
      <a:accent6><a:srgbClr val="EF4444"/></a:accent6>
      <a:hlink><a:srgbClr val="38BDF8"/></a:hlink>
      <a:folHlink><a:srgbClr val="818CF8"/></a:folHlink>
    </a:clrScheme>
    <a:fontScheme name="Modern">
      <a:majorFont><a:latin typeface="Helvetica Neue"/></a:majorFont>
      <a:minorFont><a:latin typeface="Helvetica"/></a:minorFont>
    </a:fontScheme>
    <a:fmtScheme name="Office">
      <a:fillStyleLst><a:solidClr><a:schemeClr val="phClr"/></a:solidClr><a:solidClr><a:schemeClr val="phClr"/></a:solidClr><a:solidClr><a:schemeClr val="phClr"/></a:solidClr></a:fillStyleLst>
      <a:lnStyleLst><a:ln w="9525"><a:solidClr><a:schemeClr val="phClr"/></a:solidClr></a:ln><a:ln w="19050"><a:solidClr><a:schemeClr val="phClr"/></a:solidClr></a:ln><a:ln w="28575"><a:solidClr><a:schemeClr val="phClr"/></a:solidClr></a:ln></a:lnStyleLst>
      <a:effectStyleLst><a:effectStyle><a:effectLst/></a:effectStyle><a:effectStyle><a:effectLst/></a:effectStyle><a:effectStyle><a:effectLst/></a:effectStyle></a:effectStyleLst>
      <a:bgFillStyleLst><a:solidClr><a:schemeClr val="phClr"/></a:solidClr><a:solidClr><a:schemeClr val="phClr"/></a:solidClr><a:solidClr><a:schemeClr val="phClr"/></a:solidClr></a:bgFillStyleLst>
    </a:fmtScheme>
  </a:themeElements>
</a:theme>''')

        # 6. ppt/slideMasters/_rels/slideMaster1.xml.rels
        z.writestr('ppt/slideMasters/_rels/slideMaster1.xml.rels', '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="../theme/theme1.xml"/>
</Relationships>''')

        # 7. ppt/slideMasters/slideMaster1.xml
        z.writestr('ppt/slideMasters/slideMaster1.xml', '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sldMaster xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
             xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
             xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:cSld>
    <p:spTree>
      <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
      <p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>
    </p:spTree>
  </p:cSld>
  <p:clrMap bg1="dk1" tx1="lt1" bg2="dk2" tx2="lt2" accent1="accent1" accent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/>
  <p:sldLayoutIdLst>
    <p:sldLayoutId id="2147483649" r:id="rId1"/>
  </p:sldLayoutIdLst>
</p:sldMaster>''')

        # 8. ppt/slideLayouts/_rels/slideLayout1.xml.rels
        z.writestr('ppt/slideLayouts/_rels/slideLayout1.xml.rels', '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="../slideMasters/slideMaster1.xml"/>
</Relationships>''')

        # 9. ppt/slideLayouts/slideLayout1.xml
        z.writestr('ppt/slideLayouts/slideLayout1.xml', '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sldLayout xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
             xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
             xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" type="blank">
  <p:cSld name="Blank">
    <p:spTree>
      <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
      <p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>
    </p:spTree>
  </p:cSld>
</p:sldLayout>''')

        # 10. Write each slide and its rels
        for idx, s_xml in enumerate(slides_xml, start=1):
            z.writestr(f'ppt/slides/slide{idx}.xml', s_xml)
            z.writestr(f'ppt/slides/_rels/slide{idx}.xml.rels', '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/>
</Relationships>''')

    print(f"✅ Successfully created 10-slide enterprise presentation: {output_path}")

if __name__ == "__main__":
    out1 = "/Users/vishal/Documents/VulnFlow/VulnFlow_Enterprise_Presentation.pptx"
    out2 = "/Users/vishal/Documents/VulnFlow/demo_assets/VulnFlow_Enterprise_Presentation.pptx"
    build_presentation(out1)
    build_presentation(out2)
