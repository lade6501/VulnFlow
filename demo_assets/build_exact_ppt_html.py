#!/usr/bin/env python3
"""
build_exact_ppt_html.py
Generates demo_assets/vulnflow_architecture_briefing.html with the EXACT layout
from the uploaded PowerPoint (media_1795518551708_364e1e52.pptx), including:
- Exact 13-slide geometry, titles, subtitles, and bottom-right slide numbers.
- Exact embedded base64 icons extracted from the PPT slides.
- Dual theme engine: Dark Obsidian (default) and Light Titanium.
- Perfect audio & visual synchronization:
  * A slide NEVER advances until ALL content builds have been fully revealed
    AND audio speech has completed, followed by a comfortable 2.5s reading pause.
  * Spreads builds dynamically across speech duration so each point pops in on cue.
  * Row-by-row builds for Slide 10 task table.
- Web Audio API sound engine (synthesized whooshes, clicks, and pops).
- Speech synthesis voiceover with auto-play video demo mode.
- Speaker notes drawer, full-screen mode, and keyboard shortcuts.
"""

import base64
import glob
import os

# 1. Load and base64-encode all extracted PPT icons
icons_dir = "demo_assets/ppt_icons"
icons_b64 = {}
for p in sorted(glob.glob(f"{icons_dir}/*.png")):
    name = os.path.splitext(os.path.basename(p))[0]
    with open(p, "rb") as f:
        b64 = base64.b64encode(f.read()).decode("utf-8")
        icons_b64[name] = f"data:image/png;base64,{b64}"

print(f"Loaded {len(icons_b64)} icons into memory.")

def icon_img(name, css_class="ppt-icon-img", style=""):
    src = icons_b64.get(name, "")
    return f'<img src="{src}" class="{css_class}" alt="{name}" style="{style}">'

# 2. Build the complete HTML document
html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VulnFlow AI — Enterprise Architecture Briefing</title>
  <style>
    /* =========================================================
       EXECUTIVE DUAL-THEME ENGINE (OBSIDIAN & TITANIUM)
       Matching the exact colors from PPT theme1.xml:
       dk1: 0F172A, lt1: FFFFFF, dk2: 334155, lt2: F1F5F9,
       accent1: 0F766E, accent2: 6D5BD0, accent3: B45309,
       accent4: 64748B, accent5: B91C1C, accent6: 0369A1
       ========================================================= */
    :root {{
      /* Dark Theme (Default: Obsidian Cyber) */
      --bg-dark: #080C14;
      --bg-surface: #0F172A;
      --bg-card: rgba(15, 23, 42, 0.78);
      --bg-card-hover: rgba(30, 41, 59, 0.9);
      --border-subtle: rgba(255, 255, 255, 0.08);
      --border-accent: rgba(16, 185, 129, 0.4);
      --text-main: #F8FAFC;
      --text-muted: #94A3B8;
      --text-dim: #64748B;
      --emerald: #10B981;
      --emerald-glow: rgba(16, 185, 129, 0.25);
      --teal: #0F766E;
      --cyan: #06B6D4;
      --blue: #3B82F6;
      --amber: #F59E0B;
      --rose: #F43F5E;
      --purple: #8B5CF6;
      --card-shadow: 0 20px 45px rgba(0, 0, 0, 0.55), inset 0 1px 0 rgba(255, 255, 255, 0.06);
      --header-bg: rgba(8, 12, 20, 0.88);
      --narration-bg: rgba(11, 15, 25, 0.95);
      --terminal-bg: #050811;
      --terminal-header: #0f172a;
      --terminal-text: #cbd5e1;
      --grid-line: rgba(255, 255, 255, 0.025);
      --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      --icon-filter: brightness(0) invert(1);
    }}

    body.light-theme {{
      /* Executive Light Titanium Theme */
      --bg-dark: #F1F5F9;
      --bg-surface: #FFFFFF;
      --bg-card: rgba(255, 255, 255, 0.94);
      --bg-card-hover: rgba(248, 250, 252, 0.98);
      --border-subtle: rgba(203, 213, 225, 0.85);
      --border-accent: rgba(15, 118, 110, 0.5);
      --text-main: #0F172A;
      --text-muted: #334155;
      --text-dim: #64748B;
      --emerald: #059669;
      --emerald-glow: rgba(5, 150, 105, 0.2);
      --teal: #0F766E;
      --cyan: #0284C7;
      --blue: #2563EB;
      --amber: #D97706;
      --rose: #E11D48;
      --purple: #7C3AED;
      --card-shadow: 0 18px 40px rgba(15, 23, 42, 0.08), inset 0 1px 0 rgba(255, 255, 255, 0.95);
      --header-bg: rgba(255, 255, 255, 0.88);
      --narration-bg: rgba(255, 255, 255, 0.95);
      --terminal-bg: #0F172A;
      --terminal-header: #1E293B;
      --terminal-text: #F1F5F9;
      --grid-line: rgba(15, 23, 42, 0.035);
      --icon-filter: brightness(0) invert(0.18);
    }}

    * {{ box-sizing: border-box; margin: 0; padding: 0; }}

    body {{
      background-color: var(--bg-dark);
      color: var(--text-main);
      font-family: var(--font-sans);
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      overflow-x: hidden;
      user-select: none;
      -webkit-font-smoothing: antialiased;
      transition: background-color 0.4s ease, color 0.4s ease;
      background-image: 
        linear-gradient(var(--grid-line) 1px, transparent 1px),
        linear-gradient(90deg, var(--grid-line) 1px, transparent 1px);
      background-size: 40px 40px;
    }}

    /* =========================================================
       EXECUTIVE TOP BAR
       ========================================================= */
    header {{
      background: var(--header-bg);
      backdrop-filter: blur(14px);
      border-bottom: 1px solid var(--border-subtle);
      padding: 10px 28px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      position: sticky;
      top: 0;
      z-index: 100;
    }}

    .header-left {{
      display: flex;
      align-items: center;
      gap: 14px;
    }}

    .logo-container {{
      display: flex;
      align-items: center;
      gap: 9px;
      text-decoration: none;
      color: var(--text-main);
    }}

    .logo-icon {{
      width: 28px;
      height: 28px;
      border-radius: 7px;
      background: linear-gradient(135deg, #059669, #0284c7);
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 0 12px var(--emerald-glow);
    }}

    .logo-icon svg {{
      width: 17px;
      height: 17px;
      fill: #fff;
    }}

    .brand-title {{
      font-weight: 800;
      font-size: 16px;
      letter-spacing: -0.4px;
    }}

    .briefing-tag {{
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.8px;
      background: rgba(16, 185, 129, 0.12);
      border: 1px solid var(--emerald);
      color: var(--emerald);
      padding: 3px 8px;
      border-radius: 5px;
    }}

    .header-controls {{
      display: flex;
      align-items: center;
      gap: 8px;
    }}

    .btn {{
      padding: 6px 12px;
      border-radius: 7px;
      font-size: 12.5px;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      transition: background 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease;
      border: 1px solid var(--border-subtle);
      background: var(--bg-card);
      color: var(--text-main);
      box-shadow: 0 2px 6px rgba(0, 0, 0, 0.05);
    }}

    .btn:hover {{
      background: var(--bg-card-hover);
      border-color: var(--cyan);
    }}

    .btn-primary {{
      background: linear-gradient(135deg, #059669, #0d9488);
      border: 1px solid #10b981;
      color: #fff;
      box-shadow: 0 4px 14px var(--emerald-glow);
    }}

    .btn-primary:hover {{
      background: linear-gradient(135deg, #10b981, #14b8a6);
      box-shadow: 0 0 14px var(--emerald-glow);
    }}

    .btn-video-active {{
      background: linear-gradient(135deg, #7c3aed, #4f46e5);
      border-color: #a855f7;
      color: #fff;
      animation: pulse-video-border 2s infinite;
    }}

    @keyframes pulse-video-border {{
      0%, 100% {{ box-shadow: 0 0 10px rgba(168, 85, 247, 0.4); }}
      50% {{ box-shadow: 0 0 22px rgba(168, 85, 247, 0.8); }}
    }}

    /* =========================================================
       PRESENTATION VIEWPORT
       16:9 widescreen canvas matching PPT slides
       ========================================================= */
    main {{
      flex: 1;
      position: relative;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 16px 28px;
      z-index: 10;
      overflow: hidden;
    }}

    .slide-viewport {{
      width: 100%;
      max-width: 1360px;
      height: 100%;
      max-height: 765px;
      aspect-ratio: 16 / 9;
      position: relative;
      cursor: pointer;
    }}

    .slide {{
      position: absolute;
      inset: 0;
      opacity: 0;
      pointer-events: none;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      background: var(--bg-card);
      backdrop-filter: blur(20px);
      border: 1px solid var(--border-subtle);
      border-radius: 14px;
      padding: 30px 42px 22px;
      box-shadow: var(--card-shadow);
      overflow-y: auto;
      will-change: transform, opacity;
      transition: transform 0.45s cubic-bezier(0.16, 1, 0.3, 1), opacity 0.38s ease;
      transform: scale(0.97) translateY(12px);
    }}

    .slide.active {{
      opacity: 1;
      pointer-events: auto;
      transform: scale(1) translateY(0);
      z-index: 2;
    }}

    .slide.exit-left {{
      transform: scale(0.97) translateX(-40px);
      opacity: 0;
    }}

    .slide.exit-right {{
      transform: scale(0.97) translateX(40px);
      opacity: 0;
    }}

    /* Exact PPT Slide Header */
    .slide-header {{
      margin-bottom: 20px;
    }}

    .slide-title {{
      font-size: 27px;
      font-weight: 800;
      letter-spacing: -0.5px;
      color: var(--text-main);
      line-height: 1.2;
      margin-bottom: 5px;
    }}

    .slide-subtitle {{
      font-size: 14px;
      color: var(--text-muted);
      font-weight: 500;
      line-height: 1.45;
    }}

    .slide-body {{
      flex: 1;
      display: flex;
      flex-direction: column;
      justify-content: center;
      position: relative;
    }}

    /* Bottom Slide Footer with exact clean slide number */
    .slide-footer {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      font-size: 12px;
      color: var(--text-dim);
      border-top: 1px solid var(--border-subtle);
      padding-top: 10px;
      margin-top: 14px;
    }}

    .slide-num {{
      font-size: 14px;
      font-weight: 700;
      color: var(--text-dim);
      margin-left: auto;
    }}

    /* =========================================================
       PPT-STYLE STEP-BY-STEP BUILDS
       ========================================================= */
    .ppt-item {{
      opacity: 0;
      transform: translateY(12px);
      transition: opacity 0.36s cubic-bezier(0.16, 1, 0.3, 1), transform 0.36s cubic-bezier(0.16, 1, 0.3, 1);
      pointer-events: none;
    }}

    .ppt-item.revealed {{
      opacity: 1;
      transform: translateY(0);
      pointer-events: auto;
    }}

    /* Special smooth reveal for table rows */
    tr.ppt-item {{
      opacity: 0;
      transition: opacity 0.35s ease;
    }}

    tr.ppt-item.revealed {{
      opacity: 1;
      pointer-events: auto;
    }}

    tr.ppt-item td {{
      transform: translateY(6px);
      transition: transform 0.35s cubic-bezier(0.16, 1, 0.3, 1);
    }}

    tr.ppt-item.revealed td {{
      transform: translateY(0);
    }}

    /* When builds are toggled OFF via 'B' key, all items are revealed instantly */
    body.builds-disabled .ppt-item {{
      opacity: 1 !important;
      transform: none !important;
      pointer-events: auto !important;
      transition: none !important;
    }}

    /* =========================================================
       ICON STYLING (matching original PPT 256x256 PNGs)
       ========================================================= */
    .ppt-icon-img {{
      width: 32px;
      height: 32px;
      object-fit: contain;
      filter: var(--icon-filter);
      transition: filter 0.3s ease;
      display: block;
    }}

    .ppt-icon-box {{
      width: 44px;
      height: 44px;
      display: flex;
      align-items: center;
      justify-content: center;
      border-radius: 9px;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid var(--border-subtle);
      flex-shrink: 0;
    }}

    /* =========================================================
       COMMON LAYOUT COMPONENTS (EXACT MATCH TO PPT)
       ========================================================= */
    .card {{
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: 10px;
      padding: 18px 20px;
      box-shadow: 0 4px 16px rgba(0, 0, 0, 0.12);
      transition: border-color 0.25s ease, background 0.25s ease;
    }}

    .card:hover {{
      border-color: var(--cyan);
    }}

    .grid-3 {{
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 18px;
    }}

    .grid-2 {{
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 20px;
    }}

    .badge {{
      display: inline-flex;
      align-items: center;
      padding: 4px 10px;
      border-radius: 5px;
      font-size: 11.5px;
      font-weight: 700;
      letter-spacing: 0.4px;
      text-transform: uppercase;
    }}

    .badge-emerald {{ background: rgba(16, 185, 129, 0.15); color: var(--emerald); border: 1px solid var(--emerald); }}
    .badge-amber {{ background: rgba(245, 158, 11, 0.15); color: var(--amber); border: 1px solid var(--amber); }}
    .badge-rose {{ background: rgba(244, 63, 94, 0.15); color: var(--rose); border: 1px solid var(--rose); }}
    .badge-purple {{ background: rgba(139, 92, 246, 0.15); color: var(--purple); border: 1px solid var(--purple); }}
    .badge-cyan {{ background: rgba(6, 182, 212, 0.15); color: var(--cyan); border: 1px solid var(--cyan); }}

    /* =========================================================
       NARRATION TOAST & BOTTOM CONTROLS
       ========================================================= */
    .narration-toast {{
      position: fixed;
      bottom: 20px;
      left: 50%;
      transform: translateX(-50%);
      background: var(--narration-bg);
      backdrop-filter: blur(16px);
      border: 1px solid var(--border-accent);
      border-radius: 10px;
      padding: 10px 22px;
      display: flex;
      align-items: center;
      gap: 14px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.4);
      z-index: 100;
      max-width: 820px;
      width: 90%;
      font-size: 13px;
      color: var(--text-main);
      line-height: 1.45;
      pointer-events: none;
    }}

    .speaker-wave {{
      display: flex;
      align-items: center;
      gap: 3px;
      height: 18px;
    }}

    .speaker-bar {{
      width: 3px;
      background: var(--emerald);
      border-radius: 2px;
      animation: sound-bounce 1.2s infinite ease-in-out;
    }}
    .speaker-bar:nth-child(1) {{ height: 8px; animation-delay: 0.1s; }}
    .speaker-bar:nth-child(2) {{ height: 16px; animation-delay: 0.2s; }}
    .speaker-bar:nth-child(3) {{ height: 11px; animation-delay: 0.3s; }}
    .speaker-bar:nth-child(4) {{ height: 14px; animation-delay: 0.4s; }}

    .speaker-wave.paused .speaker-bar {{
      animation-play-state: paused;
      height: 4px !important;
    }}

    @keyframes sound-bounce {{
      0%, 100% {{ transform: scaleY(0.4); }}
      50% {{ transform: scaleY(1); }}
    }}

    /* Notes Drawer */
    .notes-drawer {{
      position: fixed;
      top: 0;
      right: -420px;
      width: 400px;
      height: 100vh;
      background: var(--bg-surface);
      border-left: 1px solid var(--border-subtle);
      box-shadow: -10px 0 30px rgba(0,0,0,0.5);
      z-index: 200;
      padding: 24px;
      display: flex;
      flex-direction: column;
      gap: 16px;
      transition: right 0.35s cubic-bezier(0.16, 1, 0.3, 1);
      pointer-events: none;
    }}

    .notes-drawer.open {{
      right: 0;
      pointer-events: auto;
    }}

    .notes-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--border-subtle);
      padding-bottom: 12px;
    }}

    .notes-content {{
      flex: 1;
      overflow-y: auto;
      font-size: 13.5px;
      line-height: 1.6;
      color: var(--text-muted);
    }}
  </style>
</head>
<body>

  <!-- =========================================================
       EXECUTIVE HEADER CONTROLS
       ========================================================= */ -->
  <header>
    <div class="header-left">
      <div class="logo-container">
        <div class="logo-icon">
          <svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 16l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z"/></svg>
        </div>
        <span class="brand-title">VulnFlow AI</span>
      </div>
      <span class="briefing-tag">Architecture Briefing</span>
    </div>

    <div class="header-controls">
      <!-- Prev & Next Buttons -->
      <button id="btn-prev" class="btn" title="Previous Slide (← / P)">
        <svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor"><path d="M15.41 7.41L14 6l-6 6 6 6 1.41-1.41L10.83 12z"/></svg>
        <span>Prev</span>
      </button>

      <button id="btn-next" class="btn btn-primary" title="Next Build or Slide (Space / → / N)">
        <span>Next</span>
        <svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor"><path d="M10 6L8.59 7.41 13.17 12l-4.58 4.59L10 18l6-6z"/></svg>
      </button>

      <!-- Slide Selector -->
      <select id="slide-select" class="btn" style="padding: 5px 8px; font-weight: 600;">
        <option value="0">01 • Title Briefing</option>
        <option value="1">02 • Problem Statement</option>
        <option value="2">03 • Detection is Mature</option>
        <option value="3">04 • How VulnFlow Differs</option>
        <option value="4">05 • Four Tiers Boundaries</option>
        <option value="5">06 • 10-Node Workflow</option>
        <option value="6">07 • Agentic AI Roles</option>
        <option value="7">08 • Self-Correction Loop</option>
        <option value="8">09 • Governance & Policy</option>
        <option value="9">10 • Developer Productivity</option>
        <option value="10">11 • End-to-End Real Run</option>
        <option value="11">12 • Measurable Roadmap</option>
        <option value="12">13 • Agents Propose</option>
        <option value="13">14 • Thank You</option>
      </select>

      <!-- Step Counter / Status -->
      <span id="step-counter" class="btn" style="cursor: default; font-family: var(--font-mono); font-size: 11.5px; color: var(--emerald);">
        Build: 1 / 4
      </span>

      <!-- Auto Demo Button -->
      <button id="btn-video" class="btn btn-primary" title="Toggle Auto Video Demo Mode (V)">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z"/></svg>
        <span id="btn-video-text">Auto Demo</span>
      </button>

      <!-- Voiceover Play/Pause -->
      <button id="btn-audio" class="btn" title="Toggle Voiceover (M)">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M3 9v6h4l5 5V4L7 9H3zm13.5 3c0-1.77-1.02-3.29-2.5-4.03v8.05c1.48-.73 2.5-2.25 2.5-4.02zM14 3.23v2.06c2.89.86 5 3.54 5 6.71s-2.11 5.85-5 6.71v2.06c4.01-.91 7-4.49 7-8.77s-2.99-7.86-7-8.77z"/></svg>
        <span id="btn-audio-text">Voice: ON</span>
      </button>

      <!-- Theme Toggle -->
      <button id="btn-theme" class="btn" title="Toggle Light/Dark Theme (T)">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M12 3c-4.97 0-9 4.03-9 9s4.03 9 9 9 9-4.03 9-9c0-.46-.04-.92-.1-1.36-.98 1.37-2.58 2.26-4.4 2.26-2.98 0-5.4-2.42-5.4-5.4 0-1.81.89-3.42 2.26-4.4-.44-.06-.9-.1-1.36-.1z"/></svg>
        <span id="btn-theme-text">Dark</span>
      </button>

      <!-- Notes Drawer Toggle -->
      <button id="btn-notes" class="btn" title="Toggle Speaker Notes (S)">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M14 2H6c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></svg>
        <span>Notes</span>
      </button>

      <!-- Fullscreen Toggle -->
      <button id="btn-fullscreen" class="btn" title="Fullscreen (F)">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><path d="M7 14H5v5h5v-2H7v-3zm-2-4h2V7h3V5H5v5zm12 7h-3v2h5v-5h-2v3zM14 5v2h3v3h2V5h-5z"/></svg>
      </button>
    </div>
  </header>

  <!-- =========================================================
       PRESENTATION VIEWPORT
       ========================================================= -->
  <main>
    <div class="slide-viewport" id="viewport">

      <!-- =========================================================
           SLIDE 1: TITLE / HERO BRIEFING
           ========================================================= -->
      <section class="slide active" id="slide-1" data-duration="17"
               data-narration="Welcome to the VulnFlow AI Enterprise Architecture Briefing: agentic vulnerability remediation that bridges the gap from scanner noise to verified pull requests. LLM agents propose, deterministic code executes, and scanners verify.">
        <div style="flex: 1; display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center; max-width: 900px; margin: 0 auto;">
          <div style="font-size: 13.5px; font-weight: 800; letter-spacing: 2px; color: var(--emerald); text-transform: uppercase; margin-bottom: 12px;">
            ENTERPRISE ARCHITECTURE BRIEFING
          </div>
          <h1 style="font-size: 56px; font-weight: 800; letter-spacing: -1.2px; line-height: 1.1; margin-bottom: 14px; background: linear-gradient(135deg, #fff 40%, var(--emerald)); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
            VulnFlow AI
          </h1>
          <p style="font-size: 20px; color: var(--text-muted); font-weight: 500; line-height: 1.5; margin-bottom: 40px; max-width: 760px;">
            Agentic vulnerability remediation: from scanner noise to verified pull requests
          </p>

          <!-- 3 Pillars Connected by Arrows (Exact Match to PPT Slide 1) -->
          <div style="display: flex; align-items: center; gap: 14px; width: 100%; justify-content: center; margin-bottom: 24px;">
            <div style="display: flex; align-items: center; gap: 14px;">
              <div style="background: var(--bg-surface); border: 1px solid var(--border-subtle); padding: 14px 22px; border-radius: 9px; font-weight: 700; font-size: 15px; color: var(--text-main); box-shadow: 0 4px 14px rgba(0,0,0,0.2);">
                LLM agents propose
              </div>
              <div style="color: var(--text-dim); font-size: 20px;">➔</div>
            </div>
            <div style="display: flex; align-items: center; gap: 14px;">
              <div style="background: var(--bg-surface); border: 1px solid var(--border-subtle); padding: 14px 22px; border-radius: 9px; font-weight: 700; font-size: 15px; color: var(--text-main); box-shadow: 0 4px 14px rgba(0,0,0,0.2);">
                Deterministic code executes
              </div>
              <div style="color: var(--text-dim); font-size: 20px;">➔</div>
            </div>
            <div style="display: flex; align-items: center;">
              <div style="background: var(--bg-surface); border: 1px solid var(--emerald); padding: 14px 22px; border-radius: 9px; font-weight: 700; font-size: 15px; color: var(--emerald); box-shadow: 0 0 16px var(--emerald-glow);">
                Scanners verify
              </div>
            </div>
          </div>
        </div>

        <div class="slide-footer">
          <span>VulnFlow AI • Executive Briefing</span>
          <span class="slide-num">1</span>
        </div>
      </section>

      <!-- =========================================================
           SLIDE 2: PROBLEM STATEMENT (EXACT PPT LAYOUT)
           ========================================================= -->
      <section class="slide" id="slide-2" data-duration="22"
               data-narration="The gap VulnFlow is built to close: scanners tell teams what is vulnerable, but turning findings into safe, policy-compliant, verified fixes is still manual, slow, and risky at scale. Here is who feels the pain, why existing tools fall short, and what an enterprise solution must do.">
        <div class="slide-header">
          <h2 class="slide-title">Problem statement</h2>
          <p class="slide-subtitle">The gap VulnFlow is built to close.</p>
        </div>

        <div class="slide-body">
          <!-- Top Card: THE PROBLEM (Exact match) -->
          <div class="card ppt-item" style="background: rgba(244, 63, 94, 0.08); border: 1px solid rgba(244, 63, 94, 0.4); margin-bottom: 22px; padding: 16px 24px;">
            <div style="font-weight: 800; font-size: 14px; letter-spacing: 0.5px; color: var(--rose); margin-bottom: 6px;">
              THE PROBLEM
            </div>
            <div style="font-size: 15px; line-height: 1.5; color: var(--text-main); font-weight: 500;">
              Scanners tell teams what is vulnerable, but turning findings into safe, policy-compliant, verified fixes is still manual, slow and risky at scale.
            </div>
          </div>

          <!-- 3 Columns with Exact PPT Icons and Headers -->
          <div class="grid-3" style="gap: 18px;">
            <!-- Column 1: Who feels it -->
            <div class="card ppt-item">
              <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
                <div class="ppt-icon-box" style="background: rgba(255, 255, 255, 0.06);">
                  {icon_img("image-2-1")}
                </div>
                <div style="font-weight: 700; font-size: 17px; color: var(--text-main);">Who feels it</div>
              </div>
              <ul style="list-style: none; font-size: 13.5px; line-height: 1.65; color: var(--text-muted);">
                <li>• Developers lose time to triage and upgrades</li>
                <li>• Security cannot see which findings share a fix</li>
                <li>• Leaders see backlogs, not closure</li>
              </ul>
            </div>

            <!-- Column 2: Why current tools fall short -->
            <div class="card ppt-item">
              <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
                <div class="ppt-icon-box" style="background: rgba(245, 158, 11, 0.1); border-color: rgba(245, 158, 11, 0.3);">
                  {icon_img("image-2-2")}
                </div>
                <div style="font-weight: 700; font-size: 17px; color: var(--text-main);">Why current tools fall short</div>
              </div>
              <ul style="list-style: none; font-size: 13.5px; line-height: 1.65; color: var(--text-muted);">
                <li>• Scanners stop at detection</li>
                <li>• Bump bots lack root-cause and policy context</li>
                <li>• Fixes are rarely tested and rescanned first</li>
              </ul>
            </div>

            <!-- Column 3: What a solution must do -->
            <div class="card ppt-item">
              <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
                <div class="ppt-icon-box" style="background: rgba(16, 185, 129, 0.1); border-color: rgba(16, 185, 129, 0.3);">
                  {icon_img("image-2-3")}
                </div>
                <div style="font-weight: 700; font-size: 17px; color: var(--text-main);">What a solution must do</div>
              </div>
              <ul style="list-style: none; font-size: 13.5px; line-height: 1.65; color: var(--text-muted);">
                <li>• Group findings by root cause</li>
                <li>• Enforce policy in code</li>
                <li>• Test in a sandbox, verify by rescan</li>
                <li>• Keep humans on risky changes</li>
              </ul>
            </div>
          </div>
        </div>

        <div class="slide-footer">
          <span>Problem statement</span>
          <span class="slide-num">2</span>
        </div>
      </section>

      <!-- =========================================================
           SLIDE 3: DETECTION IS MATURE (EXACT PPT LAYOUT)
           ========================================================= -->
      <section class="slide" id="slide-3" data-duration="20"
               data-narration="Detection is mature, but remediation is still manual. Where the gap shows up: alert noise from duplicated scanner reports, deep transitive dependencies that share a single root cause, and the engineering toil of manual triage. In one real repository scan, four hundred twenty-six findings collapsed into forty-three direct root causes.">
        <div class="slide-header">
          <h2 class="slide-title">Detection is mature. Remediation is still manual</h2>
          <p class="slide-subtitle">Where the gap shows up: three pain points and one real data point.</p>
        </div>

        <div class="slide-body">
          <!-- 3 Columns with Large Top Icons matching PPT -->
          <div class="grid-3" style="gap: 18px; margin-bottom: 22px;">
            <!-- Column 1: Alert noise -->
            <div class="card ppt-item" style="padding: 22px 20px;">
              <div class="ppt-icon-box" style="margin-bottom: 14px;">
                {icon_img("image-3-1")}
              </div>
              <div style="font-weight: 700; font-size: 18px; color: var(--text-main); margin-bottom: 8px;">
                Alert noise
              </div>
              <div style="font-size: 13.5px; line-height: 1.55; color: var(--text-muted);">
                Every scanner reports every CVE in every location. Backlogs outgrow triage.
              </div>
            </div>

            <!-- Column 2: Duplicate root causes -->
            <div class="card ppt-item" style="padding: 22px 20px;">
              <div class="ppt-icon-box" style="margin-bottom: 14px;">
                {icon_img("image-3-2")}
              </div>
              <div style="font-weight: 700; font-size: 18px; color: var(--text-main); margin-bottom: 8px;">
                Duplicate root causes
              </div>
              <div style="font-size: 13.5px; line-height: 1.55; color: var(--text-muted);">
                One outdated direct dependency fans out into many findings that share a single fix.
              </div>
            </div>

            <!-- Column 3: Toil and risk -->
            <div class="card ppt-item" style="padding: 22px 20px;">
              <div class="ppt-icon-box" style="margin-bottom: 14px;">
                {icon_img("image-3-3")}
              </div>
              <div style="font-weight: 700; font-size: 18px; color: var(--text-main); margin-bottom: 8px;">
                Toil and risk
              </div>
              <div style="font-size: 13.5px; line-height: 1.55; color: var(--text-muted);">
                Triage, policy checks, testing and PR writing are manual, and blind bot upgrades can break builds.
              </div>
            </div>
          </div>

          <!-- Bottom Highlight Banner: 426 -> 43 (Exact match to PPT) -->
          <div class="card ppt-item" style="background: var(--bg-surface); border: 1px solid var(--emerald); display: flex; align-items: center; gap: 24px; padding: 18px 28px;">
            <div style="display: flex; align-items: baseline; gap: 12px; font-weight: 800; font-size: 38px; color: var(--emerald); letter-spacing: -1px;">
              <span>426</span>
              <span style="font-size: 24px; color: var(--text-dim); font-weight: 400;">➔</span>
              <span>43</span>
            </div>
            <div style="flex: 1; border-left: 1px solid var(--border-subtle); padding-left: 20px;">
              <div style="font-weight: 700; font-size: 16px; color: var(--text-main); margin-bottom: 2px;">
                findings became root causes in one real scan
              </div>
              <div style="font-size: 13px; color: var(--text-dim);">
                Single test repository, shown for illustration. Not an average.
              </div>
            </div>
          </div>
        </div>

        <div class="slide-footer">
          <span>Detection is mature</span>
          <span class="slide-num">3</span>
        </div>
      </section>

      <!-- =========================================================
           SLIDE 4: HOW VULNFLOW DIFFERS (EXACT TABLE)
           ========================================================= -->
      <section class="slide" id="slide-4" data-duration="22"
               data-narration="How VulnFlow differs from existing tools: detection scanners stop at alerts, bump bots lack dependency context, and vendor autofix features only address single ecosystems. VulnFlow closes the loop with multi-scanner ingestion, root-cause grouping, policy in code, and sandboxed rescan verification.">
        <div class="slide-header">
          <h2 class="slide-title">How VulnFlow differs from existing tools</h2>
          <p class="slide-subtitle">Detection, bump bots and vendor autofix each cover part of the loop. VulnFlow closes it.</p>
        </div>

        <div class="slide-body">
          <div class="card ppt-item" style="padding: 0; overflow: hidden; border: 1px solid var(--border-subtle); margin-bottom: 12px;">
            <table style="width: 100%; border-collapse: collapse; font-size: 13px; text-align: left;">
              <thead>
                <tr style="background: rgba(255, 255, 255, 0.04); border-bottom: 1px solid var(--border-subtle);">
                  <th style="padding: 12px 18px; font-weight: 800; color: var(--text-dim); width: 34%;">Capability</th>
                  <th style="padding: 12px 14px; font-weight: 700; color: var(--text-dim); width: 16%;">Scanners</th>
                  <th style="padding: 12px 14px; font-weight: 700; color: var(--text-dim); width: 16%;">Bump bots</th>
                  <th style="padding: 12px 14px; font-weight: 700; color: var(--text-dim); width: 17%;">Vendor autofix</th>
                  <th style="padding: 12px 16px; font-weight: 800; color: var(--emerald); background: rgba(16, 185, 129, 0.08); width: 17%;">VulnFlow</th>
                </tr>
              </thead>
              <tbody>
                <tr style="border-bottom: 1px solid var(--border-subtle);">
                  <td style="padding: 10px 18px; font-weight: 600; color: var(--text-main);">Ingests findings from many scanners</td>
                  <td style="padding: 10px 14px; color: var(--text-dim);">Not a focus</td>
                  <td style="padding: 10px 14px; color: var(--text-dim);">Not a focus</td>
                  <td style="padding: 10px 14px; color: var(--amber);">Partial</td>
                  <td style="padding: 10px 16px; font-weight: 700; color: var(--emerald); background: rgba(16, 185, 129, 0.05);">Built in</td>
                </tr>
                <tr style="border-bottom: 1px solid var(--border-subtle);">
                  <td style="padding: 10px 18px; font-weight: 600; color: var(--text-main);">Groups findings into root causes</td>
                  <td style="padding: 10px 14px; color: var(--amber);">Partial</td>
                  <td style="padding: 10px 14px; color: var(--text-dim);">Not a focus</td>
                  <td style="padding: 10px 14px; color: var(--amber);">Partial</td>
                  <td style="padding: 10px 16px; font-weight: 700; color: var(--emerald); background: rgba(16, 185, 129, 0.05);">Built in</td>
                </tr>
                <tr style="border-bottom: 1px solid var(--border-subtle);">
                  <td style="padding: 10px 18px; font-weight: 600; color: var(--text-main);">Enforces org policy as code</td>
                  <td style="padding: 10px 14px; color: var(--amber);">Partial</td>
                  <td style="padding: 10px 14px; color: var(--amber);">Partial</td>
                  <td style="padding: 10px 14px; color: var(--amber);">Partial</td>
                  <td style="padding: 10px 16px; font-weight: 700; color: var(--emerald); background: rgba(16, 185, 129, 0.05);">Built in</td>
                </tr>
                <tr style="border-bottom: 1px solid var(--border-subtle);">
                  <td style="padding: 10px 18px; font-weight: 600; color: var(--text-main);">Tests the fix in a sandbox before the PR</td>
                  <td style="padding: 10px 14px; color: var(--text-dim);">Not a focus</td>
                  <td style="padding: 10px 14px; color: var(--amber);">Partial</td>
                  <td style="padding: 10px 14px; color: var(--amber);">Partial</td>
                  <td style="padding: 10px 16px; font-weight: 700; color: var(--emerald); background: rgba(16, 185, 129, 0.05);">Built in</td>
                </tr>
                <tr style="border-bottom: 1px solid var(--border-subtle);">
                  <td style="padding: 10px 18px; font-weight: 600; color: var(--text-main);">Rescans to prove the fix worked</td>
                  <td style="padding: 10px 14px; color: var(--amber);">Partial</td>
                  <td style="padding: 10px 14px; color: var(--text-dim);">Not a focus</td>
                  <td style="padding: 10px 14px; color: var(--amber);">Partial</td>
                  <td style="padding: 10px 16px; font-weight: 700; color: var(--emerald); background: rgba(16, 185, 129, 0.05);">Built in</td>
                </tr>
                <tr style="border-bottom: 1px solid var(--border-subtle);">
                  <td style="padding: 10px 18px; font-weight: 600; color: var(--text-main);">Gated approvals with an audit trail</td>
                  <td style="padding: 10px 14px; color: var(--text-dim);">Not a focus</td>
                  <td style="padding: 10px 14px; color: var(--amber);">Partial</td>
                  <td style="padding: 10px 14px; color: var(--amber);">Partial</td>
                  <td style="padding: 10px 16px; font-weight: 700; color: var(--emerald); background: rgba(16, 185, 129, 0.05);">Built in</td>
                </tr>
                <tr>
                  <td style="padding: 10px 18px; font-weight: 600; color: var(--text-main);">Agent retries when a fix fails</td>
                  <td style="padding: 10px 14px; color: var(--text-dim);">Not a focus</td>
                  <td style="padding: 10px 14px; color: var(--text-dim);">Not a focus</td>
                  <td style="padding: 10px 14px; color: var(--amber);">Partial</td>
                  <td style="padding: 10px 16px; font-weight: 700; color: var(--emerald); background: rgba(16, 185, 129, 0.05);">Built in</td>
                </tr>
              </tbody>
            </table>
          </div>

          <div class="ppt-item" style="font-size: 11.5px; color: var(--text-dim); line-height: 1.45;">
            Category-level view; capabilities vary by product. Bump bots: Dependabot or Renovate style. Vendor autofix: remediation features of a scanner vendor.
          </div>
        </div>

        <div class="slide-footer">
          <span>How VulnFlow differs</span>
          <span class="slide-num">4</span>
        </div>
      </section>

      <!-- =========================================================
           SLIDE 5: FOUR TIERS WITH HARD BOUNDARIES (EXACT MATCH)
           ========================================================= -->
      <section class="slide" id="slide-5" data-duration="24"
               data-narration="VulnFlow's architecture enforces four tiers with hard boundaries. Tier 1 handles ingest and edge redaction. Tier 2 orchestrates LangGraph agents. Tier 3 provides isolated FastMCP tools. Tier 4 runs Docker sandboxes and knowledge graphs. Only Tier 2 calls an LLM, while all code edits, policy checks, and rescans remain strictly deterministic.">
        <div class="slide-header">
          <h2 class="slide-title">Four tiers with hard boundaries</h2>
          <p class="slide-subtitle">Only Tier 2 calls an LLM. Everything that touches code, policy or scans is deterministic.</p>
        </div>

        <div class="slide-body">
          <!-- 4 Horizontal Tiers -->
          <div style="display: flex; flex-direction: column; gap: 10px; margin-bottom: 18px;">
            <!-- Tier 1 -->
            <div class="card ppt-item" style="display: flex; align-items: center; gap: 16px; padding: 11px 18px;">
              <span class="badge" style="background: rgba(255, 255, 255, 0.08); color: var(--text-main); font-size: 14px; width: 28px; height: 28px; justify-content: center; padding: 0;">1</span>
              <div style="width: 200px; font-weight: 700; font-size: 15px; color: var(--text-main);">Ingest and redaction</div>
              <div style="flex: 1; font-size: 13px; color: var(--text-muted);">
                Reads Trivy, Grype, Gitleaks and Snyk • Redacts secrets at the edge • Fingerprints and dedupes
              </div>
            </div>

            <!-- Tier 2 (Highlighted) -->
            <div class="card ppt-item" style="display: flex; align-items: center; gap: 16px; padding: 11px 18px; border-color: var(--emerald); background: rgba(16, 185, 129, 0.06);">
              <span class="badge badge-emerald" style="font-size: 14px; width: 28px; height: 28px; justify-content: center; padding: 0;">2</span>
              <div style="width: 200px; font-weight: 700; font-size: 15px; color: var(--emerald);">Agent orchestration</div>
              <div style="flex: 1; font-size: 13px; color: var(--text-main);">
                LangGraph, 10 checkpointed nodes • Triage, root-cause, planner, fixer, verifier agents • Human approval gate
              </div>
            </div>

            <!-- Tier 3 -->
            <div class="card ppt-item" style="display: flex; align-items: center; gap: 16px; padding: 11px 18px;">
              <span class="badge" style="background: rgba(255, 255, 255, 0.08); color: var(--text-main); font-size: 14px; width: 28px; height: 28px; justify-content: center; padding: 0;">3</span>
              <div style="width: 200px; font-weight: 700; font-size: 15px; color: var(--text-main);">FastMCP tool servers</div>
              <div style="flex: 1; font-size: 13px; color: var(--text-muted);">
                Stdio servers, no pip dependencies • git, build, scan, policy tools • All side effects live here
              </div>
            </div>

            <!-- Tier 4 -->
            <div class="card ppt-item" style="display: flex; align-items: center; gap: 16px; padding: 11px 18px;">
              <span class="badge" style="background: rgba(255, 255, 255, 0.08); color: var(--text-main); font-size: 14px; width: 28px; height: 28px; justify-content: center; padding: 0;">4</span>
              <div style="width: 200px; font-weight: 700; font-size: 15px; color: var(--text-main);">Sandbox and knowledge</div>
              <div style="flex: 1; font-size: 13px; color: var(--text-muted);">
                Docker sandbox runs build and tests • Neo4j: dependency paths, blast radius • Vector RAG: advisories, playbooks
              </div>
            </div>
          </div>

          <!-- Bottom Row of 4 Cards -->
          <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px;">
            <div class="card ppt-item" style="padding: 12px 14px;">
              <div style="font-weight: 700; font-size: 13px; color: var(--text-main); margin-bottom: 4px;">Outputs</div>
              <div style="font-size: 11.5px; color: var(--text-muted); line-height: 1.4;">PR with cited evidence, Jira exception ticket, audit log, OpenTelemetry traces</div>
            </div>
            <div class="card ppt-item" style="padding: 12px 14px;">
              <div style="font-weight: 700; font-size: 13px; color: var(--text-main); margin-bottom: 4px;">CI-native</div>
              <div style="font-size: 11.5px; color: var(--text-muted); line-height: 1.4;">One container step for GitHub Actions, GitLab CI and Jenkins</div>
            </div>
            <div class="card ppt-item" style="padding: 12px 14px;">
              <div style="font-weight: 700; font-size: 13px; color: var(--text-main); margin-bottom: 4px;">Model-agnostic</div>
              <div style="font-size: 11.5px; color: var(--text-muted); line-height: 1.4;">NVIDIA NIM, Claude, OpenAI, Bedrock or Ollama, with role-based routing</div>
            </div>
            <div class="card ppt-item" style="padding: 12px 14px;">
              <div style="font-weight: 700; font-size: 13px; color: var(--text-main); margin-bottom: 4px;">Control plane</div>
              <div style="font-size: 11.5px; color: var(--text-muted); line-height: 1.4;">React dashboard and REST API; approvals persisted in Supabase</div>
            </div>
          </div>
        </div>

        <div class="slide-footer">
          <span>Four tiers with hard boundaries</span>
          <span class="slide-num">5</span>
        </div>
      </section>

      <!-- =========================================================
           SLIDE 6: 10-NODE WORKFLOW (EXACT MATCH)
           ========================================================= -->
      <section class="slide" id="slide-6" data-duration="24"
               data-narration="The ten-node remediation workflow is a checkpointed LangGraph state machine. It begins with deterministic ingestion, secret redaction, and deduplication, moves to agentic root-cause analysis and planning, enforces human approval on risky changes, and executes sandboxed test-repair loops before opening evidence-backed pull requests and auditing telemetry.">
        <div class="slide-header">
          <h2 class="slide-title">The 10-node remediation workflow</h2>
          <p class="slide-subtitle">A checkpointed LangGraph state machine. Each node is an agent, deterministic code, or a human.</p>
        </div>

        <div class="slide-body">
          <!-- Row 1: Nodes 01-05 -->
          <div style="display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 14px;">
            <div class="card ppt-item" style="border-top: 3px solid var(--blue); padding: 14px 12px;">
              <div style="font-weight: 800; font-size: 13px; color: var(--text-main); margin-bottom: 4px;">01 Ingest</div>
              <div style="font-size: 11.5px; color: var(--text-muted); line-height: 1.35;">Reads Trivy, Grype, Gitleaks, Snyk; redacts secrets</div>
            </div>
            <div class="card ppt-item" style="border-top: 3px solid var(--blue); padding: 14px 12px;">
              <div style="font-weight: 800; font-size: 13px; color: var(--text-main); margin-bottom: 4px;">02 Dedupe</div>
              <div style="font-size: 11.5px; color: var(--text-muted); line-height: 1.35;">Fingerprints and merges duplicate reports</div>
            </div>
            <div class="card ppt-item" style="border-top: 3px solid var(--purple); padding: 14px 12px;">
              <div style="font-weight: 800; font-size: 13px; color: var(--purple); margin-bottom: 4px;">03 Root cause</div>
              <div style="font-size: 11.5px; color: var(--text-muted); line-height: 1.35;">Agent traces transitive CVEs to the direct parent</div>
            </div>
            <div class="card ppt-item" style="border-top: 3px solid var(--blue); padding: 14px 12px;">
              <div style="font-weight: 800; font-size: 13px; color: var(--text-main); margin-bottom: 4px;">04 Policy check</div>
              <div style="font-size: 11.5px; color: var(--text-muted); line-height: 1.35;">Whitelist, SemVer and license rules in code</div>
            </div>
            <div class="card ppt-item" style="border-top: 3px solid var(--purple); padding: 14px 12px;">
              <div style="font-weight: 800; font-size: 13px; color: var(--purple); margin-bottom: 4px;">05 Plan</div>
              <div style="font-size: 11.5px; color: var(--text-muted); line-height: 1.35;">Agent proposes a target version and cites advisories</div>
            </div>
          </div>

          <!-- Row 2: Nodes 06-10 -->
          <div style="display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 20px;">
            <div class="card ppt-item" style="border-top: 3px solid var(--rose); padding: 14px 12px;">
              <div style="font-weight: 800; font-size: 13px; color: var(--rose); margin-bottom: 4px;">06 Approval gate</div>
              <div style="font-size: 11.5px; color: var(--text-muted); line-height: 1.35;">Pauses on risky changes. Exit code 10</div>
            </div>
            <div class="card ppt-item" style="border-top: 3px solid var(--purple); padding: 14px 12px;">
              <div style="font-weight: 800; font-size: 13px; color: var(--purple); margin-bottom: 4px;">07 Sandbox loop</div>
              <div style="font-size: 11.5px; color: var(--text-muted); line-height: 1.35;">Runs build and tests; agent picks a safer retry</div>
            </div>
            <div class="card ppt-item" style="border-top: 3px solid var(--blue); padding: 14px 12px;">
              <div style="font-weight: 800; font-size: 13px; color: var(--text-main); margin-bottom: 4px;">08 Pull request</div>
              <div style="font-size: 11.5px; color: var(--text-muted); line-height: 1.35;">Opens a PR with advisory evidence</div>
            </div>
            <div class="card ppt-item" style="border-top: 3px solid var(--blue); padding: 14px 12px;">
              <div style="font-weight: 800; font-size: 13px; color: var(--text-main); margin-bottom: 4px;">09 Verify</div>
              <div style="font-size: 11.5px; color: var(--text-muted); line-height: 1.35;">Rescans. A failed scan is never reported as success</div>
            </div>
            <div class="card ppt-item" style="border-top: 3px solid var(--blue); padding: 14px 12px;">
              <div style="font-weight: 800; font-size: 13px; color: var(--text-main); margin-bottom: 4px;">10 Audit</div>
              <div style="font-size: 11.5px; color: var(--text-muted); line-height: 1.35;">Audit log and OpenTelemetry traces</div>
            </div>
          </div>

          <!-- Bottom Legend (Exact Match) -->
          <div class="ppt-item" style="display: flex; gap: 24px; font-size: 12.5px; color: var(--text-muted);">
            <div style="display: flex; align-items: center; gap: 7px;">
              <span style="width: 10px; height: 10px; border-radius: 50%; background: var(--purple);"></span>
              <span>Agent: LLM reasoning</span>
            </div>
            <div style="display: flex; align-items: center; gap: 7px;">
              <span style="width: 10px; height: 10px; border-radius: 50%; background: var(--blue);"></span>
              <span>Deterministic code</span>
            </div>
            <div style="display: flex; align-items: center; gap: 7px;">
              <span style="width: 10px; height: 10px; border-radius: 50%; background: var(--rose);"></span>
              <span>Human decision</span>
            </div>
          </div>
        </div>

        <div class="slide-footer">
          <span>The 10-node remediation workflow</span>
          <span class="slide-num">6</span>
        </div>
      </section>

      <!-- =========================================================
           SLIDE 7: AGENTIC AI (EXACT 3x2 GRID + PNG ICONS)
           ========================================================= -->
      <section class="slide" id="slide-7" data-duration="24"
               data-narration="Agentic AI in VulnFlow uses specialized agents with bounded roles: triage, root-cause, planner, self-correcting fixer, verifier, and secrets and expiry agents. Each agent has a single responsibility and isolated tools, operating under strict policy limits with zero hallucinated authority.">
        <div class="slide-header">
          <h2 class="slide-title">Agentic AI: specialized agents, bounded roles</h2>
          <p class="slide-subtitle">Each agent has one job, its own tools, and a hard limit on what it can decide.</p>
        </div>

        <div class="slide-body">
          <div class="grid-3" style="gap: 16px; margin-bottom: 18px;">
            <!-- Agent 1: Triage agent -->
            <div class="card ppt-item">
              <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
                <div class="ppt-icon-box">
                  {icon_img("image-7-1")}
                </div>
                <div style="font-weight: 700; font-size: 16px; color: var(--text-main);">Triage agent</div>
              </div>
              <div style="font-size: 12.5px; color: var(--text-muted); line-height: 1.45; margin-bottom: 8px;">
                Sorts deduplicated findings so the right ones reach planning.
              </div>
              <div style="font-size: 11.5px; color: var(--text-dim); background: rgba(255,255,255,0.04); padding: 5px 8px; border-radius: 4px;">
                Fast model here; a stronger one plans.
              </div>
            </div>

            <!-- Agent 2: Root-cause agent -->
            <div class="card ppt-item">
              <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
                <div class="ppt-icon-box">
                  {icon_img("image-7-2")}
                </div>
                <div style="font-weight: 700; font-size: 16px; color: var(--text-main);">Root-cause agent</div>
              </div>
              <div style="font-size: 12.5px; color: var(--text-muted); line-height: 1.45; margin-bottom: 8px;">
                Traces transitive CVEs to the direct parent using the Neo4j graph.
              </div>
              <div style="font-size: 11.5px; color: var(--text-dim); background: rgba(255,255,255,0.04); padding: 5px 8px; border-radius: 4px;">
                Cannot override graph facts.
              </div>
            </div>

            <!-- Agent 3: Planner agent -->
            <div class="card ppt-item">
              <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
                <div class="ppt-icon-box">
                  {icon_img("image-7-3")}
                </div>
                <div style="font-weight: 700; font-size: 16px; color: var(--text-main);">Planner agent</div>
              </div>
              <div style="font-size: 12.5px; color: var(--text-muted); line-height: 1.45; margin-bottom: 8px;">
                Proposes a target version and cites the advisories behind it.
              </div>
              <div style="font-size: 11.5px; color: var(--text-dim); background: rgba(255,255,255,0.04); padding: 5px 8px; border-radius: 4px;">
                The policy engine can reject the plan.
              </div>
            </div>

            <!-- Agent 4: Self-correcting fixer -->
            <div class="card ppt-item">
              <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
                <div class="ppt-icon-box">
                  {icon_img("image-7-4")}
                </div>
                <div style="font-weight: 700; font-size: 16px; color: var(--text-main);">Self-correcting fixer</div>
              </div>
              <div style="font-size: 12.5px; color: var(--text-muted); line-height: 1.45; margin-bottom: 8px;">
                Reads build and test failures, rolls back and tries a safer version.
              </div>
              <div style="font-size: 11.5px; color: var(--text-dim); background: rgba(255,255,255,0.04); padding: 5px 8px; border-radius: 4px;">
                Works only inside the sandbox.
              </div>
            </div>

            <!-- Agent 5: Verifier agent -->
            <div class="card ppt-item">
              <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
                <div class="ppt-icon-box">
                  {icon_img("image-7-5")}
                </div>
                <div style="font-weight: 700; font-size: 16px; color: var(--text-main);">Verifier agent</div>
              </div>
              <div style="font-size: 12.5px; color: var(--text-muted); line-height: 1.45; margin-bottom: 8px;">
                Rescans and compares before and after.
              </div>
              <div style="font-size: 11.5px; color: var(--text-dim); background: rgba(255,255,255,0.04); padding: 5px 8px; border-radius: 4px;">
                Never reports a failed scan as success.
              </div>
            </div>

            <!-- Agent 6: Secrets and expiry agents -->
            <div class="card ppt-item">
              <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
                <div class="ppt-icon-box">
                  {icon_img("image-7-6")}
                </div>
                <div style="font-weight: 700; font-size: 16px; color: var(--text-main);">Secrets & expiry agents</div>
              </div>
              <div style="font-size: 12.5px; color: var(--text-muted); line-height: 1.45; margin-bottom: 8px;">
                Draft rotation checklists for leaked secrets and flag expiring certs.
              </div>
              <div style="font-size: 11.5px; color: var(--text-dim); background: rgba(255,255,255,0.04); padding: 5px 8px; border-radius: 4px;">
                Sees fingerprints and line numbers, never secret values.
              </div>
            </div>
          </div>

          <!-- Bottom Pill Banner (Exact Match) -->
          <div class="card ppt-item" style="text-align: center; padding: 10px; font-size: 12.5px; font-weight: 600; color: var(--text-muted); letter-spacing: 0.5px;">
            Goal-driven  •  Tool-using via MCP  •  Stateful and resumable  •  Self-correcting  •  Bounded autonomy
          </div>
        </div>

        <div class="slide-footer">
          <span>Agentic AI: specialized agents</span>
          <span class="slide-num">7</span>
        </div>
      </section>

      <!-- =========================================================
           SLIDE 8: SELF-CORRECTION LOOP (EXACT PIPELINE + GUARANTEES)
           ========================================================= -->
      <section class="slide" id="slide-8" data-duration="22"
               data-narration="Self-correction is the loop that removes broken pull requests. When a dependency patch causes unit test failures in the Docker sandbox, the fixer agent analyzes the compiler logs, identifies breaking API changes, rolls back, and tests a safer version before any pull request is opened.">
        <div class="slide-header" style="display: flex; justify-content: space-between; align-items: flex-start;">
          <div>
            <h2 class="slide-title">Self-correction: the loop that removes broken PRs</h2>
            <p class="slide-subtitle">When tests fail, the agent reads the evidence and retries before any PR opens.</p>
          </div>
          <span class="badge" style="background: rgba(255, 255, 255, 0.08); color: var(--text-muted);">Illustrative scenario</span>
        </div>

        <div class="slide-body">
          <!-- Flow Pipeline (5 Stages with FAIL loop) -->
          <div class="ppt-item" style="position: relative; margin-bottom: 30px;">
            <div style="display: flex; align-items: stretch; gap: 12px; width: 100%;">
              <!-- Step 1 -->
              <div class="card" style="flex: 1; padding: 14px 12px; text-align: center;">
                <div style="font-weight: 700; font-size: 13.5px; color: var(--text-main); margin-bottom: 4px;">Patch manifest</div>
                <div style="font-size: 12px; color: var(--text-muted); font-family: var(--font-mono);">Django 4.2 → 5.2</div>
              </div>
              <div style="display: flex; align-items: center; color: var(--text-dim);">➔</div>

              <!-- Step 2 -->
              <div class="card" style="flex: 1.2; padding: 14px 12px; text-align: center; border-color: rgba(244, 63, 94, 0.4); position: relative;">
                <div style="position: absolute; top: -11px; left: 50%; transform: translateX(-50%);">
                  <span class="badge badge-rose" style="font-size: 10px; padding: 1px 7px;">FAIL</span>
                </div>
                <div style="font-weight: 700; font-size: 13.5px; color: var(--text-main); margin-bottom: 4px;">Run sandbox tests</div>
                <div style="font-size: 12px; color: var(--text-muted);">Build and unit tests in Docker</div>
              </div>
              <div style="display: flex; align-items: center; color: var(--text-dim);">➔</div>

              <!-- Step 3 -->
              <div class="card" style="flex: 1.3; padding: 14px 12px; text-align: center; border-color: var(--purple);">
                <div style="font-weight: 700; font-size: 13.5px; color: var(--purple); margin-bottom: 4px;">Agent reads the logs</div>
                <div style="font-size: 12px; color: var(--text-muted);">Finds breaking API; picks Django 5.0.12</div>
              </div>
              <div style="display: flex; align-items: center; color: var(--text-dim);">➔</div>

              <!-- Step 4 -->
              <div class="card" style="flex: 1; padding: 14px 12px; text-align: center; border-color: rgba(16, 185, 129, 0.4); position: relative;">
                <div style="position: absolute; top: -11px; left: 50%; transform: translateX(-50%);">
                  <span class="badge badge-emerald" style="font-size: 10px; padding: 1px 7px;">PASS</span>
                </div>
                <div style="font-weight: 700; font-size: 13.5px; color: var(--text-main); margin-bottom: 4px;">Re-test</div>
                <div style="font-size: 12px; color: var(--emerald); font-weight: 600;">Tests pass with 0 errors</div>
              </div>
              <div style="display: flex; align-items: center; color: var(--text-dim);">➔</div>

              <!-- Step 5 -->
              <div class="card" style="flex: 1.2; padding: 14px 12px; text-align: center; border-color: var(--emerald); background: rgba(16, 185, 129, 0.05);">
                <div style="font-weight: 700; font-size: 13.5px; color: var(--emerald); margin-bottom: 4px;">Open PR</div>
                <div style="font-size: 12px; color: var(--text-main);">Cites advisories & verified version</div>
              </div>
            </div>

            <!-- Loopback Arrow Label -->
            <div style="margin-top: 10px; text-align: center; font-size: 12px; color: var(--amber); font-weight: 600;">
              ⟲ Roll back, then retry the tests
            </div>
          </div>

          <!-- Bottom 3 Guarantee Cards (Exact Match) -->
          <div class="grid-3" style="gap: 16px;">
            <div class="card ppt-item">
              <div style="font-weight: 700; font-size: 15px; color: var(--text-main); margin-bottom: 6px;">No broken PRs</div>
              <div style="font-size: 12.5px; color: var(--text-muted); line-height: 1.5;">Developers receive a PR that already passed build and tests.</div>
            </div>
            <div class="card ppt-item">
              <div style="font-weight: 700; font-size: 15px; color: var(--text-main); margin-bottom: 6px;">Safe by construction</div>
              <div style="font-size: 12.5px; color: var(--text-muted); line-height: 1.5;">Patches run in an ephemeral container, never on main or a laptop.</div>
            </div>
            <div class="card ppt-item">
              <div style="font-weight: 700; font-size: 15px; color: var(--text-main); margin-bottom: 6px;">Evidence travels with the fix</div>
              <div style="font-size: 12.5px; color: var(--text-muted); line-height: 1.5;">The PR cites the advisories behind the chosen version.</div>
            </div>
          </div>
        </div>

        <div class="slide-footer">
          <span>Self-correction: the loop</span>
          <span class="slide-num">8</span>
        </div>
      </section>

      <!-- =========================================================
           SLIDE 9: GOVERNANCE & POLICY (EXACT MATCH)
           ========================================================= -->
      <section class="slide" id="slide-9" data-duration="22"
               data-narration="Governance in VulnFlow enforces policy strictly in code, keeping humans at the critical gates. Safe minor bumps auto-merge if sandbox tests pass, while major upgrades pause for review. Approval states are persisted durably in Supabase across runs, with enterprise SSO and quorum routing on the roadmap.">
        <div class="slide-header">
          <h2 class="slide-title">Governance: policy in code, humans at the gates</h2>
          <p class="slide-subtitle">Rules load from YAML, Artifactory, Nexus or OPA. The model never makes the call.</p>
        </div>

        <div class="slide-body">
          <div class="grid-2" style="gap: 22px;">
            <!-- Left Column: Risk model enforced in code -->
            <div>
              <div style="font-weight: 700; font-size: 16px; color: var(--text-main); margin-bottom: 12px;">
                Risk model enforced in code
              </div>
              <div style="display: flex; flex-direction: column; gap: 12px;">
                <div class="card ppt-item" style="display: flex; align-items: center; gap: 14px; padding: 14px 18px;">
                  <span class="badge badge-emerald" style="width: 72px; justify-content: center;">AUTO</span>
                  <div style="font-size: 13px; color: var(--text-muted);">Minor and patch bumps that pass sandbox tests open a PR.</div>
                </div>
                <div class="card ppt-item" style="display: flex; align-items: center; gap: 14px; padding: 14px 18px;">
                  <span class="badge badge-amber" style="width: 72px; justify-content: center;">REVIEW</span>
                  <div style="font-size: 13px; color: var(--text-muted);">Major upgrades and unknown packages pause the run (exit 10).</div>
                </div>
                <div class="card ppt-item" style="display: flex; align-items: center; gap: 14px; padding: 14px 18px;">
                  <span class="badge badge-rose" style="width: 72px; justify-content: center;">BLOCKED</span>
                  <div style="font-size: 13px; color: var(--text-muted);">Banned packages open a Jira exception ticket (exit 20).</div>
                </div>
              </div>
            </div>

            <!-- Right Column: Approval workflow (Supabase + Roadmap) -->
            <div class="card ppt-item" style="display: flex; flex-direction: column; justify-content: space-between; padding: 20px;">
              <div>
                <div style="font-weight: 700; font-size: 16px; color: var(--text-main); margin-bottom: 14px;">
                  Approval workflow
                </div>
                <!-- Built: Supabase -->
                <div style="display: flex; align-items: flex-start; gap: 12px; margin-bottom: 16px;">
                  <span class="badge badge-emerald" style="margin-top: 2px;">BUILT</span>
                  <div style="font-size: 13px; color: var(--text-main); font-weight: 500;">
                    Approval state persisted in Supabase, so decisions survive across runs
                  </div>
                </div>
                <!-- Roadmap: Enterprise controls -->
                <div style="display: flex; align-items: flex-start; gap: 12px; margin-bottom: 10px;">
                  <span class="badge badge-cyan" style="margin-top: 2px;">ROADMAP</span>
                  <div style="font-weight: 700; font-size: 13px; color: var(--text-main);">Next: enterprise controls</div>
                </div>
                <ul style="list-style: none; font-size: 12.5px; line-height: 1.6; color: var(--text-muted); padding-left: 68px;">
                  <li>• SSO identity and group membership</li>
                  <li>• Per-risk routing with sequential or quorum steps</li>
                  <li>• Separation of duties, append-only audit trail</li>
                  <li>• Expiry, escalation and delegation</li>
                </ul>
              </div>
            </div>
          </div>
        </div>

        <div class="slide-footer">
          <span>Governance: policy in code</span>
          <span class="slide-num">9</span>
        </div>
      </section>

      <!-- =========================================================
           SLIDE 10: DEVELOPER PRODUCTIVITY (EXACT 3-COL TABLE WITH ICONS)
           ========================================================= -->
      <section class="slide" id="slide-10" data-duration="24"
               data-narration="Developer productivity shifts from mechanical remediation toil to reviewing verified results. Instead of sorting raw alerts, tracing deep lockfiles, and fighting broken builds, engineers receive an evidence-backed pull request that has already passed automated sandbox tests and rescan validation.">
        <div class="slide-header">
          <h2 class="slide-title">Developer productivity: from toil to review</h2>
          <p class="slide-subtitle">Developer time shifts from doing remediation work to reviewing a verified result.</p>
        </div>

        <div class="slide-body">
          <div class="card" style="padding: 0; overflow: hidden; border: 1px solid var(--border-subtle);">
            <table style="width: 100%; border-collapse: collapse; font-size: 13px; text-align: left;">
              <thead>
                <tr style="background: rgba(255, 255, 255, 0.04); border-bottom: 1px solid var(--border-subtle);">
                  <th style="padding: 10px 18px; font-weight: 800; color: var(--text-dim); width: 28%;">TASK</th>
                  <th style="padding: 10px 16px; font-weight: 700; color: var(--rose); width: 34%;">TODAY: MANUAL</th>
                  <th style="padding: 10px 18px; font-weight: 800; color: var(--emerald); background: rgba(16, 185, 129, 0.08); width: 38%;">WITH VULNFLOW</th>
                </tr>
              </thead>
              <tbody>
                <!-- Row 1: Triage alerts -->
                <tr class="ppt-item" style="border-bottom: 1px solid var(--border-subtle);">
                  <td style="padding: 9px 18px; font-weight: 600; color: var(--text-main); display: flex; align-items: center; gap: 10px;">
                    {icon_img("image-10-1", "ppt-icon-img", "width:22px; height:22px;")}
                    <span>Triage alerts</span>
                  </td>
                  <td style="padding: 9px 16px; color: var(--text-muted);">Sort raw alerts by hand</td>
                  <td style="padding: 9px 18px; font-weight: 600; color: var(--emerald); background: rgba(16, 185, 129, 0.04);">Agent groups findings into root causes</td>
                </tr>
                <!-- Row 2: Find the cause -->
                <tr class="ppt-item" style="border-bottom: 1px solid var(--border-subtle);">
                  <td style="padding: 9px 18px; font-weight: 600; color: var(--text-main); display: flex; align-items: center; gap: 10px;">
                    {icon_img("image-10-2", "ppt-icon-img", "width:22px; height:22px;")}
                    <span>Find the cause</span>
                  </td>
                  <td style="padding: 9px 16px; color: var(--text-muted);">Trace deep dependency locks manually</td>
                  <td style="padding: 9px 18px; font-weight: 600; color: var(--emerald); background: rgba(16, 185, 129, 0.04);">Graph traversal names the direct parent</td>
                </tr>
                <!-- Row 3: Check policy -->
                <tr class="ppt-item" style="border-bottom: 1px solid var(--border-subtle);">
                  <td style="padding: 9px 18px; font-weight: 600; color: var(--text-main); display: flex; align-items: center; gap: 10px;">
                    {icon_img("image-10-3", "ppt-icon-img", "width:22px; height:22px;")}
                    <span>Check policy</span>
                  </td>
                  <td style="padding: 9px 16px; color: var(--text-muted);">Cross-reference wikis and spreadsheets</td>
                  <td style="padding: 9px 18px; font-weight: 600; color: var(--emerald); background: rgba(16, 185, 129, 0.04);">Policy engine checks the rules in code</td>
                </tr>
                <!-- Row 4: Test the upgrade -->
                <tr class="ppt-item" style="border-bottom: 1px solid var(--border-subtle);">
                  <td style="padding: 9px 18px; font-weight: 600; color: var(--text-main); display: flex; align-items: center; gap: 10px;">
                    {icon_img("image-10-4", "ppt-icon-img", "width:22px; height:22px;")}
                    <span>Test the upgrade</span>
                  </td>
                  <td style="padding: 9px 16px; color: var(--text-muted);">Upgrade, build, test, find breakage</td>
                  <td style="padding: 9px 18px; font-weight: 600; color: var(--emerald); background: rgba(16, 185, 129, 0.04);">Sandbox tests first; agent retries</td>
                </tr>
                <!-- Row 5: Write the PR -->
                <tr class="ppt-item" style="border-bottom: 1px solid var(--border-subtle);">
                  <td style="padding: 9px 18px; font-weight: 600; color: var(--text-main); display: flex; align-items: center; gap: 10px;">
                    {icon_img("image-10-5", "ppt-icon-img", "width:22px; height:22px;")}
                    <span>Write the PR</span>
                  </td>
                  <td style="padding: 9px 16px; color: var(--text-muted);">Draft the PR, hunt for advisory links</td>
                  <td style="padding: 9px 18px; font-weight: 600; color: var(--emerald); background: rgba(16, 185, 129, 0.04);">PR opens with cited advisory evidence</td>
                </tr>
                <!-- Row 6: Prove it is fixed -->
                <tr class="ppt-item">
                  <td style="padding: 9px 18px; font-weight: 600; color: var(--text-main); display: flex; align-items: center; gap: 10px;">
                    {icon_img("image-10-6", "ppt-icon-img", "width:22px; height:22px;")}
                    <span>Prove it is fixed</span>
                  </td>
                  <td style="padding: 9px 16px; color: var(--text-muted);">Merge on green CI and rescan later</td>
                  <td style="padding: 9px 18px; font-weight: 600; color: var(--emerald); background: rgba(16, 185, 129, 0.04);">Rescan diff verifies the result</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <div class="slide-footer">
          <span>Developer productivity</span>
          <span class="slide-num">10</span>
        </div>
      </section>

      <!-- =========================================================
           SLIDE 11: A REAL RUN, END TO END (EXACT MATCH)
           ========================================================= -->
      <section class="slide" id="slide-11" data-duration="24"
               data-narration="Here is an end-to-end execution on a real test repository. Four hundred twenty-six scanner findings were analyzed, collapsing into forty-three direct root causes. Three safe fixes were applied and consolidated into a single pull request, while major upgrades were held for human approval.">
        <div class="slide-header" style="display: flex; justify-content: space-between; align-items: flex-start;">
          <div>
            <h2 class="slide-title">A real run, end to end</h2>
            <p class="slide-subtitle">Output of one VulnFlow run in PR mode on a test repository.</p>
          </div>
          <span class="badge" style="background: rgba(255, 255, 255, 0.08); color: var(--text-muted);">Illustrative, not an average</span>
        </div>

        <div class="slide-body">
          <!-- 4 Stat Numbers Across Top (Exact Match to PPT) -->
          <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 20px;">
            <div class="card ppt-item" style="text-align: center; padding: 14px;">
              <div style="font-size: 38px; font-weight: 800; color: var(--text-main); line-height: 1;">426</div>
              <div style="font-size: 12.5px; color: var(--text-muted); margin-top: 4px;">findings analyzed</div>
            </div>
            <div class="card ppt-item" style="text-align: center; padding: 14px;">
              <div style="font-size: 38px; font-weight: 800; color: var(--cyan); line-height: 1;">43</div>
              <div style="font-size: 12.5px; color: var(--text-muted); margin-top: 4px;">root causes</div>
            </div>
            <div class="card ppt-item" style="text-align: center; padding: 14px;">
              <div style="font-size: 38px; font-weight: 800; color: var(--emerald); line-height: 1;">3</div>
              <div style="font-size: 12.5px; color: var(--text-muted); margin-top: 4px;">fixes applied</div>
            </div>
            <div class="card ppt-item" style="text-align: center; padding: 14px;">
              <div style="font-size: 38px; font-weight: 800; color: var(--purple); line-height: 1;">1</div>
              <div style="font-size: 12.5px; color: var(--text-muted); margin-top: 4px;">pull request opened</div>
            </div>
          </div>

          <!-- Bottom: Code Diff on Left + 3 Cards on Right -->
          <div class="grid-2" style="gap: 20px;">
            <!-- Left: Code Diff Box -->
            <div class="card ppt-item" style="padding: 16px; background: var(--terminal-bg); font-family: var(--font-mono); font-size: 12.5px; line-height: 1.6; border: 1px solid var(--border-subtle);">
              <div style="color: var(--text-dim); margin-bottom: 4px; font-weight: 700;">package.json</div>
              <div style="color: #FCA5A5;">- "lodash": "4.17.4"</div>
              <div style="color: #86EFAC;">+ "lodash": "4.18.0"</div>
              <div style="color: var(--text-dim); margin: 8px 0 4px; font-weight: 700;">requirements.txt</div>
              <div style="color: #FCA5A5;">- requests==2.6.0</div>
              <div style="color: #86EFAC;">+ requests==2.33.0</div>
              <div style="margin-top: 14px; font-size: 11px; color: var(--text-dim); font-family: var(--font-sans);">
                2 of 3 applied fixes shown
              </div>
            </div>

            <!-- Right: 3 Stacked Cards -->
            <div style="display: flex; flex-direction: column; gap: 10px;">
              <div class="card ppt-item" style="padding: 12px 16px;">
                <div style="font-weight: 700; font-size: 14px; color: var(--emerald); margin-bottom: 2px;">Applied</div>
                <div style="font-size: 12.5px; color: var(--text-muted);">Safe bumps were written to manifests and opened as one PR.</div>
              </div>
              <div class="card ppt-item" style="padding: 12px 16px;">
                <div style="font-weight: 700; font-size: 14px; color: var(--amber); margin-bottom: 2px;">Held for approval</div>
                <div style="font-size: 12.5px; color: var(--text-muted);">Major upgrades and unapproved packages waited for a human decision.</div>
              </div>
              <div class="card ppt-item" style="padding: 12px 16px;">
                <div style="font-weight: 700; font-size: 14px; color: var(--cyan); margin-bottom: 2px;">Next gate</div>
                <div style="font-size: 12.5px; color: var(--text-muted);">Rescan was not run in this execution. Verified closure is the next step.</div>
              </div>
            </div>
          </div>
        </div>

        <div class="slide-footer">
          <span>A real run, end to end</span>
          <span class="slide-num">11</span>
        </div>
      </section>

      <!-- =========================================================
           SLIDE 12: ROADMAP & METRICS (EXACT MATCH)
           ========================================================= -->
      <section class="slide" id="slide-12" data-duration="22"
               data-narration="Our roadmap focuses on enterprise trust and measurable impact. We will instrument key pilot metrics: time from scan to pull request, developer review time, and rescan-verified closures, rather than publishing unverified projections.">
        <div class="slide-header">
          <h2 class="slide-title">Roadmap and how we will prove the impact</h2>
          <p class="slide-subtitle">We report measured results from a pilot. We do not publish projections.</p>
        </div>

        <div class="slide-body">
          <div class="grid-2" style="gap: 24px;">
            <!-- Left: Roadmap -->
            <div>
              <div style="font-weight: 700; font-size: 16px; color: var(--text-main); margin-bottom: 12px;">Roadmap</div>
              <div style="display: flex; flex-direction: column; gap: 12px;">
                <div class="card ppt-item" style="display: flex; align-items: flex-start; gap: 14px; padding: 14px 16px;">
                  <span class="badge badge-emerald" style="width: 65px; justify-content: center;">Next</span>
                  <div style="font-size: 13px; color: var(--text-muted); line-height: 1.45;">
                    SSO-based multi-approver workflow with routing, audit trail and escalation
                  </div>
                </div>
                <div class="card ppt-item" style="display: flex; align-items: flex-start; gap: 14px; padding: 14px 16px;">
                  <span class="badge badge-cyan" style="width: 65px; justify-content: center;">Then</span>
                  <div style="font-size: 13px; color: var(--text-muted); line-height: 1.45;">
                    Org-wide remediation campaigns and a multi-repo portfolio view
                  </div>
                </div>
                <div class="card ppt-item" style="display: flex; align-items: flex-start; gap: 14px; padding: 14px 16px;">
                  <span class="badge badge-purple" style="width: 65px; justify-content: center;">Always</span>
                  <div style="font-size: 13px; color: var(--text-muted); line-height: 1.45;">
                    Stable-release target versions, and rescan verification on every run
                  </div>
                </div>
              </div>
            </div>

            <!-- Right: Pilot Metrics (2x3 Grid) -->
            <div>
              <div style="font-weight: 700; font-size: 16px; color: var(--text-main); margin-bottom: 12px;">
                Pilot metrics we will instrument
              </div>
              <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px;">
                <div class="card ppt-item" style="padding: 14px 16px; display: flex; align-items: center; justify-content: center; text-align: center; font-weight: 600; font-size: 13px; color: var(--text-main);">
                  Time from scan to PR
                </div>
                <div class="card ppt-item" style="padding: 14px 16px; display: flex; align-items: center; justify-content: center; text-align: center; font-weight: 600; font-size: 13px; color: var(--text-main);">
                  Developer review time per PR
                </div>
                <div class="card ppt-item" style="padding: 14px 16px; display: flex; align-items: center; justify-content: center; text-align: center; font-weight: 600; font-size: 13px; color: var(--text-main);">
                  PRs merged without edits
                </div>
                <div class="card ppt-item" style="padding: 14px 16px; display: flex; align-items: center; justify-content: center; text-align: center; font-weight: 600; font-size: 13px; color: var(--text-main);">
                  First-attempt build pass rate
                </div>
                <div class="card ppt-item" style="padding: 14px 16px; display: flex; align-items: center; justify-content: center; text-align: center; font-weight: 600; font-size: 13px; color: var(--text-main);">
                  Findings per root cause
                </div>
                <div class="card ppt-item" style="padding: 14px 16px; display: flex; align-items: center; justify-content: center; text-align: center; font-weight: 600; font-size: 13px; color: var(--text-main);">
                  Rescan-verified closures
                </div>
              </div>
            </div>
          </div>
        </div>

        <div class="slide-footer">
          <span>Roadmap and pilot metrics</span>
          <span class="slide-num">12</span>
        </div>
      </section>

      <!-- =========================================================
           SLIDE 13: CONCLUSION & NEXT STEPS (EXACT MATCH)
           ========================================================= -->
      <section class="slide" id="slide-13" data-duration="20"
               data-narration="In conclusion: agents propose, code decides, scanners verify. VulnFlow AI delivers an evidence-backed architecture that eliminates security backlog toil. Our proposed next step is a pilot deployment on two or three repositories to instrument and prove these velocity gains.">
        <div class="slide-header" style="text-align: center; margin-bottom: 24px;">
          <h2 class="slide-title" style="font-size: 36px; font-weight: 800; letter-spacing: -0.8px;">
            Agents propose. Code decides. Scanners verify.
          </h2>
        </div>

        <div class="slide-body">
          <!-- 3 Columns with Large PNG Icons on Top -->
          <div class="grid-3" style="gap: 20px; margin-bottom: 28px;">
            <!-- Column 1: Architecture -->
            <div class="card ppt-item" style="text-align: center; padding: 24px 20px;">
              <div class="ppt-icon-box" style="margin: 0 auto 16px;">
                {icon_img("image-13-1")}
              </div>
              <div style="font-weight: 800; font-size: 18px; color: var(--text-main); margin-bottom: 8px;">Architecture</div>
              <div style="font-size: 13px; line-height: 1.55; color: var(--text-muted);">
                Four tiers with hard boundaries: only agents use an LLM, and nothing the model proposes is applied without code and tests.
              </div>
            </div>

            <!-- Column 2: Agentic AI -->
            <div class="card ppt-item" style="text-align: center; padding: 24px 20px;">
              <div class="ppt-icon-box" style="margin: 0 auto 16px;">
                {icon_img("image-13-2")}
              </div>
              <div style="font-weight: 800; font-size: 18px; color: var(--text-main); margin-bottom: 8px;">Agentic AI</div>
              <div style="font-size: 13px; line-height: 1.55; color: var(--text-muted);">
                Specialized, bounded agents, a self-correcting fixer, and human gates where risk is high.
              </div>
            </div>

            <!-- Column 3: Developers -->
            <div class="card ppt-item" style="text-align: center; padding: 24px 20px;">
              <div class="ppt-icon-box" style="margin: 0 auto 16px;">
                {icon_img("image-13-3")}
              </div>
              <div style="font-weight: 800; font-size: 18px; color: var(--text-main); margin-bottom: 8px;">Developers</div>
              <div style="font-size: 13px; line-height: 1.55; color: var(--text-muted);">
                One evidence-backed PR per root cause instead of a long list of alerts to triage.
              </div>
            </div>
          </div>

          <!-- Bottom Next Step Banner with CLI command (Exact Match) -->
          <div class="card ppt-item" style="background: rgba(16, 185, 129, 0.08); border: 1px solid var(--emerald); padding: 16px 24px;">
            <div style="font-weight: 700; font-size: 14px; color: var(--text-main); margin-bottom: 8px;">
              Proposed next step: a pilot on two or three repositories, measured as on slide 12.
            </div>
            <div style="font-family: var(--font-mono); font-size: 13px; color: var(--emerald); font-weight: 700;">
              vulnflow scan --repo . --mode report &nbsp;&nbsp;&nbsp;&nbsp; vulnflow serve
            </div>
          </div>
        </div>

        <div class="slide-footer">
          <span>Agents propose. Code decides. Scanners verify.</span>
          <span class="slide-num">13</span>
        </div>
      </section>

      <!-- =========================================================
           SLIDE 14: THANK YOU / CONCLUSION & DISCUSSION
           ========================================================= -->
      <section class="slide" id="slide-14" data-duration="15"
               data-narration="Thank you for your time. VulnFlow AI bridges the gap between vulnerability detection and verified remediation. We look forward to answering your questions and kicking off your pilot deployment.">
        <div style="flex: 1; display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center; max-width: 960px; margin: 0 auto; width: 100%;">
          <div style="font-size: 13.5px; font-weight: 800; letter-spacing: 2px; color: var(--emerald); text-transform: uppercase; margin-bottom: 12px;">
            ENTERPRISE ARCHITECTURE BRIEFING
          </div>
          <h1 style="font-size: 58px; font-weight: 800; letter-spacing: -1.2px; line-height: 1.1; margin-bottom: 14px; background: linear-gradient(135deg, #fff 40%, var(--emerald)); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
            Thank You
          </h1>
          <p style="font-size: 19px; color: var(--text-muted); font-weight: 500; line-height: 1.5; margin-bottom: 34px; max-width: 780px;">
            Turning security scanner noise into safe, verified, policy-compliant pull requests.
          </p>

          <!-- 3 Info / Action Cards -->
          <div class="grid-3" style="width: 100%; gap: 18px; margin-bottom: 24px; text-align: left;">
            <div class="card ppt-item" style="padding: 18px 20px;">
              <div style="font-weight: 700; font-size: 15px; color: var(--emerald); margin-bottom: 6px;">
                🚀 Pilot Deployment
              </div>
              <div style="font-size: 12.5px; color: var(--text-muted); line-height: 1.5;">
                Deploy on 2–3 target repositories to instrument cycle-time reduction, pass rates, and verified closures.
              </div>
            </div>

            <div class="card ppt-item" style="padding: 18px 20px;">
              <div style="font-weight: 700; font-size: 15px; color: var(--cyan); margin-bottom: 6px;">
                ⚡ CLI & Dashboard
              </div>
              <div style="font-size: 12.5px; color: var(--text-muted); line-height: 1.5; margin-bottom: 6px;">
                Run report or PR mode natively in CI/CD:
              </div>
              <div style="font-family: var(--font-mono); font-size: 11.5px; color: var(--emerald); background: rgba(16, 185, 129, 0.08); padding: 4px 8px; border-radius: 5px;">
                vulnflow scan --repo . --mode pr
              </div>
            </div>

            <div class="card ppt-item" style="padding: 18px 20px;">
              <div style="font-weight: 700; font-size: 15px; color: var(--purple); margin-bottom: 6px;">
                💬 Q&A & Architecture
              </div>
              <div style="font-size: 12.5px; color: var(--text-muted); line-height: 1.5;">
                Open for discussion on agentic orchestration, FastMCP sandboxes, and Supabase persistent governance.
              </div>
            </div>
          </div>
        </div>

        <div class="slide-footer">
          <span>VulnFlow AI • Executive Briefing</span>
          <span class="slide-num">14</span>
        </div>
      </section>

    </div>
  </main>

  <!-- =========================================================
       NARRATION TOAST DOCK
       ========================================================= -->
  <div class="narration-toast" id="narration-toast">
    <div class="speaker-wave" id="speaker-wave">
      <div class="speaker-bar"></div>
      <div class="speaker-bar"></div>
      <div class="speaker-bar"></div>
      <div class="speaker-bar"></div>
    </div>
    <div id="narration-text" style="flex: 1;">
      Click anywhere or press Space / Enter to advance builds.
    </div>
  </div>

  <!-- =========================================================
       SPEAKER NOTES DRAWER (S KEY)
       ========================================================= -->
  <aside class="notes-drawer" id="notes-drawer">
    <div class="notes-header">
      <div style="font-weight: 800; font-size: 15px;">Speaker Talking Points</div>
      <button class="btn" id="close-notes-btn" style="padding: 4px 8px;">✕</button>
    </div>
    <div class="notes-content" id="notes-content">
      <!-- Injected by JS -->
    </div>
  </aside>

  <!-- =========================================================
       INTERACTIVE RUNTIME SCRIPT
       Synchronized Audio & Animated Builds Engine
       ========================================================= -->
  <script>
    // ==========================================
    // SOUND ENGINE (Web Audio API Synthesizer)
    // ==========================================
    class SoundEngine {{
      constructor() {{
        this.ctx = null;
        this.muted = false;
      }}

      init() {{
        if (this.ctx) return;
        try {{
          const AudioContext = window.AudioContext || window.webkitAudioContext;
          if (AudioContext) {{
            this.ctx = new AudioContext();
            this.ctx.resume();
          }}
        }} catch (e) {{
          console.warn("AudioContext init error:", e);
        }}
      }}

      playTransition() {{
        if (this.muted) return;
        this.init();
        if (!this.ctx) return;
        try {{
          const t = this.ctx.currentTime;
          const osc = this.ctx.createOscillator();
          const gain = this.ctx.createGain();
          osc.type = 'sine';
          osc.frequency.setValueAtTime(260, t);
          osc.frequency.exponentialRampToValueAtTime(740, t + 0.14);
          gain.gain.setValueAtTime(0.06, t);
          gain.gain.exponentialRampToValueAtTime(0.001, t + 0.18);
          osc.connect(gain);
          gain.connect(this.ctx.destination);
          osc.start(t);
          osc.stop(t + 0.18);
        }} catch (err) {{}}
      }}

      playContentEntry() {{
        if (this.muted) return;
        this.init();
        if (!this.ctx) return;
        try {{
          const t = this.ctx.currentTime;
          const osc = this.ctx.createOscillator();
          const gain = this.ctx.createGain();
          osc.type = 'sine';
          osc.frequency.setValueAtTime(520, t);
          osc.frequency.exponentialRampToValueAtTime(840, t + 0.07);
          gain.gain.setValueAtTime(0.035, t);
          gain.gain.exponentialRampToValueAtTime(0.001, t + 0.09);
          osc.connect(gain);
          gain.connect(this.ctx.destination);
          osc.start(t);
          osc.stop(t + 0.09);
        }} catch (err) {{}}
      }}
    }}

    // ==========================================
    // VOICEOVER ENGINE (SpeechSynthesis)
    // ==========================================
    class VoiceoverEngine {{
      constructor() {{
        this.synth = window.speechSynthesis;
        this.voice = null;
        this.enabled = true;
        this.isSpeaking = false;
        this.initVoices();
      }}

      initVoices() {{
        if (!this.synth) return;
        const update = () => {{
          const voices = this.synth.getVoices();
          this.voice = voices.find(v => v.lang.startsWith('en') && (v.name.includes('Natural') || v.name.includes('Siri') || v.name.includes('Daniel') || v.name.includes('Alex'))) ||
                       voices.find(v => v.lang.startsWith('en')) || null;
        }};
        update();
        if (this.synth.onvoiceschanged !== undefined) {{
          this.synth.onvoiceschanged = update;
        }}
      }}

      speak(text, onEnd) {{
        if (!this.synth || !this.enabled) {{
          if (onEnd) onEnd();
          return;
        }}
        this.stop();
        const utter = new SpeechSynthesisUtterance(text);
        if (this.voice) utter.voice = this.voice;
        utter.rate = 1.0;
        utter.pitch = 1.0;
        this.isSpeaking = true;
        document.getElementById('speaker-wave').classList.remove('paused');

        utter.onend = () => {{
          this.isSpeaking = false;
          document.getElementById('speaker-wave').classList.add('paused');
          if (onEnd) onEnd();
        }};
        utter.onerror = () => {{
          this.isSpeaking = false;
          document.getElementById('speaker-wave').classList.add('paused');
          if (onEnd) onEnd();
        }};

        this.synth.speak(utter);
      }}

      stop() {{
        if (this.synth) {{
          this.synth.cancel();
          this.isSpeaking = false;
          document.getElementById('speaker-wave').classList.add('paused');
        }}
      }}
    }}

    // ==========================================
    // PRESENTATION CONTROLLER
    // Synchronized Speech & Content Builds
    // ==========================================
    class PresentationController {{
      constructor() {{
        this.slides = Array.from(document.querySelectorAll('.slide'));
        this.currentIndex = 0;
        this.currentBuildIndex = 0;
        this.sound = new SoundEngine();
        this.voiceover = new VoiceoverEngine();
        this.isVideoMode = false;
        this.buildsEnabled = true;

        // Synchronization state flags
        this.activeTimers = [];
        this.speechFinished = false;
        this.allBuildsRevealed = false;
        this.isAdvancing = false;

        this.initDOM();
        this.initEvents();
        this.goToSlide(0);
      }}

      initDOM() {{
        this.slideSelect = document.getElementById('slide-select');
        this.stepCounter = document.getElementById('step-counter');
        this.narrationText = document.getElementById('narration-text');
        this.notesContent = document.getElementById('notes-content');
        this.notesDrawer = document.getElementById('notes-drawer');
        this.btnPrev = document.getElementById('btn-prev');
        this.btnNext = document.getElementById('btn-next');
        this.btnVideo = document.getElementById('btn-video');
        this.btnAudio = document.getElementById('btn-audio');
        this.btnAudioText = document.getElementById('btn-audio-text');
        this.btnTheme = document.getElementById('btn-theme');
        this.btnThemeText = document.getElementById('btn-theme-text');
      }}

      initEvents() {{
        // Keyboard navigation
        document.addEventListener('keydown', (e) => {{
          if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT') return;

          switch (e.key) {{
            case ' ':
            case 'Enter':
              e.preventDefault();
              this.advanceBuildOrNextSlide();
              break;
            case 'ArrowRight':
            case 'n':
            case 'N':
              e.preventDefault();
              this.nextSlide();
              break;
            case 'ArrowLeft':
            case 'p':
            case 'P':
              e.preventDefault();
              this.prevSlide();
              break;
            case 't':
            case 'T':
              this.toggleTheme();
              break;
            case 'v':
            case 'V':
              this.toggleVideoMode();
              break;
            case 'm':
            case 'M':
              this.toggleAudio();
              break;
            case 's':
            case 'S':
              this.toggleNotes();
              break;
            case 'f':
            case 'F':
              this.toggleFullscreen();
              break;
            case 'b':
            case 'B':
              this.toggleBuilds();
              break;
          }}
        }});

        // Click anywhere on slide viewport or main to advance build or next slide
        const advanceOnClick = (e) => {{
          if (e.target.closest('button') || e.target.closest('select') || e.target.closest('a') || e.target.closest('.notes-drawer')) return;
          this.advanceBuildOrNextSlide();
        }};
        const viewportEl = document.getElementById('viewport');
        if (viewportEl) viewportEl.addEventListener('click', advanceOnClick);
        const mainEl = document.querySelector('main');
        if (mainEl) mainEl.addEventListener('click', advanceOnClick);

        // Prev & Next Buttons
        if (this.btnPrev) this.btnPrev.addEventListener('click', (e) => {{
          e.stopPropagation();
          this.prevSlide();
        }});
        if (this.btnNext) this.btnNext.addEventListener('click', (e) => {{
          e.stopPropagation();
          this.advanceBuildOrNextSlide();
        }});

        // Slide Selector Dropdown
        this.slideSelect.addEventListener('change', (e) => {{
          this.goToSlide(parseInt(e.target.value));
        }});

        // Header Buttons
        this.btnVideo.addEventListener('click', () => this.toggleVideoMode());
        this.btnAudio.addEventListener('click', () => this.toggleAudio());
        this.btnTheme.addEventListener('click', () => this.toggleTheme());
        document.getElementById('btn-notes').addEventListener('click', () => this.toggleNotes());
        document.getElementById('close-notes-btn').addEventListener('click', () => this.toggleNotes());
        document.getElementById('btn-fullscreen').addEventListener('click', () => this.toggleFullscreen());
      }}

      clearAllTimers() {{
        this.activeTimers.forEach(id => clearTimeout(id));
        this.activeTimers = [];
      }}

      getCurrentSlide() {{
        return this.slides[this.currentIndex];
      }}

      getSlideBuildItems(slide) {{
        return Array.from(slide.querySelectorAll('.ppt-item'));
      }}

      goToSlide(index, direction = 'next') {{
        if (index < 0 || index >= this.slides.length) return;
        
        // Stop current audio and clear all pending timeouts
        this.voiceover.stop();
        this.clearAllTimers();

        const currentSlide = this.getCurrentSlide();
        const nextSlide = this.slides[index];

        if (currentSlide && currentSlide !== nextSlide) {{
          currentSlide.classList.remove('active');
          currentSlide.classList.add(direction === 'next' ? 'exit-left' : 'exit-right');
          const exitTimer = setTimeout(() => {{
            currentSlide.classList.remove('exit-left', 'exit-right');
          }}, 500);
          this.activeTimers.push(exitTimer);
        }}

        this.currentIndex = index;
        this.currentBuildIndex = 0;
        this.slideSelect.value = index;

        // Reset synchronization state
        this.speechFinished = false;
        this.allBuildsRevealed = false;
        this.isAdvancing = false;

        // Reset and prepare build items for new slide
        const buildItems = this.getSlideBuildItems(nextSlide);
        buildItems.forEach(item => item.classList.remove('revealed'));

        nextSlide.classList.add('active');
        this.sound.playTransition();

        // Update speaker notes and subtitle toast
        const narration = nextSlide.getAttribute('data-narration') || '';
        this.narrationText.textContent = narration;
        this.notesContent.innerHTML = `
          <div style="font-weight:700; color:var(--text-main); margin-bottom:6px;">Slide ${{index + 1}} Talking Points:</div>
          <p style="margin-bottom:12px;">${{narration}}</p>
          <div style="font-size:12px; color:var(--text-dim); border-top:1px solid var(--border-subtle); padding-top:10px;">
            Target Duration: ${{nextSlide.getAttribute('data-duration') || '20'}}s • ${{buildItems.length}} Interactive Builds
          </div>
        `;

        // Always reveal the first build immediately on entry
        if (buildItems.length > 0) {{
          this.revealBuild(0);
          if (buildItems.length === 1) {{
            this.allBuildsRevealed = true;
          }}
        }} else {{
          this.allBuildsRevealed = true;
          this.updateBuildCounter(0, 0);
        }}

        // Speak narration
        this.voiceover.speak(narration, () => {{
          // Voice narration completed
          this.speechFinished = true;
          this.checkReadyToAdvance();
        }});

        // In Auto Demo Mode, schedule progressive build reveals
        if (this.isVideoMode && buildItems.length > 1) {{
          this.scheduleVideoBuilds(buildItems, narration);
        }}
      }}

      scheduleVideoBuilds(buildItems, narration) {{
        // Estimate speaking duration: ~135 words per minute = 2.25 words/sec
        const words = narration.trim().split(' ').filter(Boolean).length;
        const estSpeechSec = Math.max(7, words / 2.2);

        const count = buildItems.length;
        const remaining = count - 1;

        // Space remaining builds across the available speech time
        // Clamp interval between 1100ms and 2400ms so items appear at a readable pace
        let intervalMs = Math.round(((estSpeechSec - 1.0) * 1000) / remaining);
        if (intervalMs < 1100) intervalMs = 1100;
        if (intervalMs > 2400) intervalMs = 2400;

        for (let i = 1; i < count; i++) {{
          const delay = intervalMs * i;
          const timer = setTimeout(() => {{
            if (this.isVideoMode && this.currentIndex === this.slides.indexOf(buildItems[0].closest('.slide'))) {{
              this.revealBuild(i);
              if (i === count - 1) {{
                // All build items for this slide have now been revealed!
                this.allBuildsRevealed = true;
                this.checkReadyToAdvance();
              }}
            }}
          }}, delay);
          this.activeTimers.push(timer);
        }}
      }}

      checkReadyToAdvance() {{
        if (!this.isVideoMode) return;
        if (this.isAdvancing) return;

        // CRITICAL: Slide advances ONLY when BOTH speech has finished AND all content builds are shown!
        if (this.speechFinished && this.allBuildsRevealed) {{
          this.isAdvancing = true;
          this.stepCounter.textContent = `All shown • Holding 2.5s`;
          // Comfort hold pause so viewer can absorb the complete slide
          const advanceTimer = setTimeout(() => {{
            if (this.isVideoMode) {{
              if (this.currentIndex < this.slides.length - 1) {{
                this.nextSlide();
              }} else {{
                // Reached the end of the presentation
                this.toggleVideoMode(false);
              }}
            }}
          }}, 2500);
          this.activeTimers.push(advanceTimer);
        }} else if (this.speechFinished && !this.allBuildsRevealed) {{
          // Audio finished early, but some builds are still pending!
          // We do NOT advance! We let the scheduled builds reveal smoothly.
          this.stepCounter.textContent = `Speaking done • Showing content...`;
        }} else if (!this.speechFinished && this.allBuildsRevealed) {{
          // Content is fully revealed, but audio is still speaking!
          // We let the voice finish speaking naturally.
          this.stepCounter.textContent = `Content ready • Speaking...`;
        }}
      }}

      advanceBuildOrNextSlide() {{
        const slide = this.getCurrentSlide();
        const buildItems = this.getSlideBuildItems(slide);

        if (this.currentBuildIndex < buildItems.length) {{
          this.revealBuild(this.currentBuildIndex);
          if (this.currentBuildIndex >= buildItems.length) {{
            this.allBuildsRevealed = true;
            this.checkReadyToAdvance();
          }}
        }} else {{
          this.nextSlide();
        }}
      }}

      revealBuild(index) {{
        const slide = this.getCurrentSlide();
        const buildItems = this.getSlideBuildItems(slide);

        if (index >= 0 && index < buildItems.length) {{
          buildItems[index].classList.add('revealed');
          this.sound.playContentEntry();
          this.currentBuildIndex = index + 1;
          this.updateBuildCounter(this.currentBuildIndex, buildItems.length);
          if (this.currentBuildIndex >= buildItems.length) {{
            this.allBuildsRevealed = true;
          }}
        }}
      }}

      updateBuildCounter(curr, total) {{
        if (total === 0) {{
          this.stepCounter.textContent = 'Slide ' + (this.currentIndex + 1);
        }} else {{
          this.stepCounter.textContent = `Build: ${{curr}} / ${{total}}`;
        }}
      }}

      nextSlide() {{
        if (this.currentIndex < this.slides.length - 1) {{
          this.goToSlide(this.currentIndex + 1, 'next');
        }}
      }}

      prevSlide() {{
        if (this.currentIndex > 0) {{
          this.goToSlide(this.currentIndex - 1, 'prev');
        }}
      }}

      toggleTheme() {{
        const isLight = document.body.classList.toggle('light-theme');
        this.btnThemeText.textContent = isLight ? 'Light' : 'Dark';
        this.sound.playContentEntry();
      }}

      toggleAudio() {{
        this.voiceover.enabled = !this.voiceover.enabled;
        this.btnAudioText.textContent = this.voiceover.enabled ? 'Voice: ON' : 'Voice: OFF';
        if (!this.voiceover.enabled) {{
          this.voiceover.stop();
          this.speechFinished = true;
          this.checkReadyToAdvance();
        }} else {{
          this.voiceover.speak(this.getCurrentSlide().getAttribute('data-narration') || '', () => {{
            this.speechFinished = true;
            this.checkReadyToAdvance();
          }});
        }}
      }}

      toggleNotes() {{
        this.notesDrawer.classList.toggle('open');
      }}

      toggleFullscreen() {{
        if (!document.fullscreenElement) {{
          document.documentElement.requestFullscreen().catch(() => {{}});
        }} else {{
          document.exitFullscreen().catch(() => {{}});
        }}
      }}

      toggleBuilds() {{
        this.buildsEnabled = !this.buildsEnabled;
        document.body.classList.toggle('builds-disabled', !this.buildsEnabled);
        if (!this.buildsEnabled) {{
          this.allBuildsRevealed = true;
          this.checkReadyToAdvance();
        }}
      }}

      toggleVideoMode(force) {{
        this.isVideoMode = force !== undefined ? force : !this.isVideoMode;
        if (this.isVideoMode) {{
          this.btnVideo.classList.add('btn-video-active');
          document.getElementById('btn-video-text').textContent = 'Stop Demo';
          this.voiceover.enabled = true;
          this.btnAudioText.textContent = 'Voice: ON';
          this.goToSlide(this.currentIndex);
        }} else {{
          this.btnVideo.classList.remove('btn-video-active');
          document.getElementById('btn-video-text').textContent = 'Auto Demo';
          this.clearAllTimers();
          this.voiceover.stop();
          this.isAdvancing = false;
        }}
      }}
    }}

    // Launch Controller on load
    window.addEventListener('DOMContentLoaded', () => {{
      window.presentation = new PresentationController();
    }});
  </script>
</body>
</html>
"""

# 3. Write output file
out_path = "demo_assets/vulnflow_architecture_briefing.html"
with open(out_path, "w", encoding="utf-8") as f:
    f.write(html)

file_size_kb = os.path.getsize(out_path) / 1024
print(f"Successfully generated {out_path} ({file_size_kb:.1f} KB).")
