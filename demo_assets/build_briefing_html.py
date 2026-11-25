import json
import os

html_template = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VulnFlow AI — Enterprise Architecture Briefing</title>
  <style>
    /* =========================================================
       EXECUTIVE DUAL-THEME ENGINE (OBSIDIAN & TITANIUM)
       ========================================================= */
    :root {
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
      --cyan: #06B6D4;
      --cyan-glow: rgba(6, 182, 212, 0.25);
      --blue: #3B82F6;
      --amber: #F59E0B;
      --amber-glow: rgba(245, 158, 11, 0.25);
      --rose: #F43F5E;
      --purple: #8B5CF6;
      --purple-glow: rgba(139, 92, 246, 0.25);
      --card-shadow: 0 20px 45px rgba(0, 0, 0, 0.55), inset 0 1px 0 rgba(255, 255, 255, 0.06);
      --header-bg: rgba(8, 12, 20, 0.88);
      --narration-bg: rgba(11, 15, 25, 0.95);
      --terminal-bg: #050811;
      --terminal-header: #0f172a;
      --terminal-text: #cbd5e1;
      --grid-line: rgba(255, 255, 255, 0.025);
      --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }

    body.light-theme {
      /* Executive Light Titanium Theme */
      --bg-dark: #F1F5F9;
      --bg-surface: #FFFFFF;
      --bg-card: rgba(255, 255, 255, 0.92);
      --bg-card-hover: rgba(248, 250, 252, 0.98);
      --border-subtle: rgba(203, 213, 225, 0.85);
      --border-accent: rgba(5, 150, 105, 0.5);
      --text-main: #0F172A;
      --text-muted: #334155;
      --text-dim: #64748B;
      --emerald: #059669;
      --emerald-glow: rgba(5, 150, 105, 0.2);
      --cyan: #0284C7;
      --cyan-glow: rgba(2, 132, 199, 0.2);
      --blue: #2563EB;
      --amber: #D97706;
      --amber-glow: rgba(217, 119, 6, 0.2);
      --rose: #E11D48;
      --purple: #7C3AED;
      --purple-glow: rgba(124, 58, 237, 0.2);
      --card-shadow: 0 18px 40px rgba(15, 23, 42, 0.08), inset 0 1px 0 rgba(255, 255, 255, 0.95);
      --header-bg: rgba(255, 255, 255, 0.88);
      --narration-bg: rgba(255, 255, 255, 0.95);
      --terminal-bg: #0F172A;
      --terminal-header: #1E293B;
      --terminal-text: #F1F5F9;
      --grid-line: rgba(15, 23, 42, 0.035);
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      background-color: var(--bg-dark);
      color: var(--text-main);
      font-family: var(--font-sans);
      overflow: hidden;
      height: 100vh;
      display: flex;
      flex-direction: column;
      user-select: none;
      transition: background-color 0.4s ease, color 0.4s ease;
    }

    /* Ambient Subtle Canvas */
    #ambientCanvas {
      position: fixed;
      top: 0;
      left: 0;
      width: 100vw;
      height: 100vh;
      pointer-events: none;
      z-index: 0;
      opacity: 0.55;
    }

    /* Top Navigation Bar */
    header {
      height: 58px;
      padding: 0 28px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      border-bottom: 1px solid var(--border-subtle);
      background: var(--header-bg);
      backdrop-filter: blur(12px);
      z-index: 100;
    }

    .logo-container {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .logo-icon {
      width: 32px;
      height: 32px;
      border-radius: 8px;
      background: linear-gradient(135deg, var(--emerald), var(--cyan));
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 0 14px var(--emerald-glow);
      font-size: 15px;
    }

    .logo-text {
      font-size: 16px;
      font-weight: 800;
      letter-spacing: -0.3px;
      color: var(--text-main);
    }

    .logo-pill {
      font-size: 10.5px;
      padding: 2px 8px;
      border-radius: 9999px;
      background: var(--emerald-glow);
      color: var(--emerald);
      border: 1px solid var(--emerald);
      font-weight: 700;
      letter-spacing: 0.5px;
      text-transform: uppercase;
    }

    .header-controls {
      display: flex;
      align-items: center;
      gap: 9px;
    }

    .btn {
      padding: 6px 13px;
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
    }

    .btn:hover {
      background: var(--bg-card-hover);
      border-color: var(--cyan);
      box-shadow: 0 4px 10px rgba(6, 182, 212, 0.1);
    }

    .btn:active {
      transform: translateY(1px);
    }

    .btn-primary {
      background: linear-gradient(135deg, #059669, #0d9488);
      border: 1px solid #10b981;
      color: #fff;
      box-shadow: 0 4px 14px var(--emerald-glow);
    }

    .btn-primary:hover {
      background: linear-gradient(135deg, #10b981, #14b8a6);
      box-shadow: 0 0 14px var(--emerald-glow);
    }

    .btn-video-active {
      background: linear-gradient(135deg, #7c3aed, #4f46e5);
      border-color: #a855f7;
      color: #fff;
      animation: pulse-video-border 2s infinite;
    }

    @keyframes pulse-video-border {
      0%, 100% { box-shadow: 0 0 10px rgba(168, 85, 247, 0.4); }
      50% { box-shadow: 0 0 22px rgba(168, 85, 247, 0.8); }
    }

    /* =========================================================
       PRESENTATION VIEWPORT & POWERPOINT TRANSITIONS
       ========================================================= */
    main {
      flex: 1;
      position: relative;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 16px 36px;
      z-index: 10;
      overflow: hidden;
    }

    .slide-viewport {
      width: 100%;
      max-width: 1380px;
      height: 100%;
      max-height: 760px;
      position: relative;
      cursor: pointer; /* Clicking anywhere on slide advances build */
    }

    /* Slide Component */
    .slide {
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
      border-radius: 16px;
      padding: 34px 44px 24px;
      box-shadow: var(--card-shadow);
      overflow-y: auto;
      will-change: transform, opacity;
      transition: 
        transform 0.5s cubic-bezier(0.16, 1, 0.3, 1),
        opacity 0.42s ease,
        border-color 0.3s ease,
        background 0.3s ease;
    }

    /* Slide States for Transitions */
    .slide.active {
      opacity: 1;
      pointer-events: auto;
      transform: translate3d(0, 0, 0);
      z-index: 2;
    }

    .slide.exit-left {
      opacity: 0;
      transform: translate3d(-75px, 0, 0);
      z-index: 1;
    }

    .slide.exit-right {
      opacity: 0;
      transform: translate3d(75px, 0, 0);
      z-index: 1;
    }

    /* =========================================================
       POWERPOINT CONTENT ENTRANCE ANIMATIONS (.ppt-item)
       ========================================================= */
    .ppt-item {
      opacity: 0;
      transform: translateY(22px);
      transition: 
        opacity 0.45s cubic-bezier(0.16, 1, 0.3, 1), 
        transform 0.45s cubic-bezier(0.16, 1, 0.3, 1),
        border-color 0.35s ease,
        box-shadow 0.35s ease;
      will-change: transform, opacity;
      pointer-events: none;
    }

    .ppt-item.revealed {
      opacity: 1;
      transform: translateY(0);
      pointer-events: auto;
    }

    /* Highlight glow when a build item first appears */
    .ppt-item.just-revealed {
      border-color: var(--cyan) !important;
      box-shadow: 0 0 16px var(--cyan-glow), var(--card-shadow) !important;
    }

    /* When builds are disabled or printing */
    body.builds-disabled .ppt-item,
    @media print {
      .ppt-item {
        opacity: 1 !important;
        transform: none !important;
        pointer-events: auto !important;
        transition: none !important;
      }
    }

    /* Slide Header */
    .slide-tagline {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 1.4px;
      color: var(--emerald);
      margin-bottom: 7px;
    }

    .slide-title {
      font-size: 27px;
      font-weight: 800;
      letter-spacing: -0.6px;
      color: var(--text-main);
      margin-bottom: 5px;
    }

    .slide-subtitle {
      font-size: 14.5px;
      color: var(--text-muted);
      line-height: 1.5;
      max-width: 980px;
    }

    .slide-body {
      flex: 1;
      display: flex;
      flex-direction: column;
      justify-content: center;
      margin: 16px 0;
    }

    /* Layout Grids */
    .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
    .grid-3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 18px; }
    .grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; }
    .grid-6 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; }

    /* Cards */
    .card {
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      border-radius: 10px;
      padding: 18px 20px;
      box-shadow: var(--card-shadow);
      transition: border-color 0.25s ease, box-shadow 0.25s ease;
      position: relative;
      overflow: hidden;
    }

    .card:hover {
      border-color: var(--cyan);
      box-shadow: 0 4px 14px rgba(6, 182, 212, 0.1);
    }

    .card-accent-emerald { border-left: 4px solid var(--emerald); }
    .card-accent-cyan { border-left: 4px solid var(--cyan); }
    .card-accent-amber { border-left: 4px solid var(--amber); }
    .card-accent-purple { border-left: 4px solid var(--purple); }
    .card-accent-rose { border-left: 4px solid var(--rose); }

    .card-title {
      font-size: 15px;
      font-weight: 700;
      color: var(--text-main);
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 7px;
    }

    .card-desc {
      font-size: 12.8px;
      color: var(--text-muted);
      line-height: 1.55;
    }

    /* Badges */
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 3px 9px;
      border-radius: 6px;
      font-size: 10.5px;
      font-weight: 700;
      letter-spacing: 0.4px;
      font-family: var(--font-mono);
    }

    .badge-emerald { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.35); }
    .badge-cyan { background: rgba(6, 182, 212, 0.15); color: #38bdf8; border: 1px solid rgba(6, 182, 212, 0.35); }
    .badge-amber { background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.35); }
    .badge-rose { background: rgba(244, 63, 94, 0.15); color: #fb7185; border: 1px solid rgba(244, 63, 94, 0.35); }
    .badge-purple { background: rgba(139, 92, 246, 0.15); color: #c084fc; border: 1px solid rgba(139, 92, 246, 0.35); }

    body.light-theme .badge-emerald { background: rgba(5, 150, 105, 0.12); color: #047857; border-color: rgba(5, 150, 105, 0.3); }
    body.light-theme .badge-cyan { background: rgba(2, 132, 199, 0.12); color: #0369a1; border-color: rgba(2, 132, 199, 0.3); }
    body.light-theme .badge-amber { background: rgba(217, 119, 6, 0.12); color: #b45309; border-color: rgba(217, 119, 6, 0.3); }
    body.light-theme .badge-rose { background: rgba(225, 29, 72, 0.12); color: #be123c; border-color: rgba(225, 29, 72, 0.3); }
    body.light-theme .badge-purple { background: rgba(124, 58, 237, 0.12); color: #6d28d9; border-color: rgba(124, 58, 237, 0.3); }

    /* Comparison Table */
    .comp-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 12.5px;
      margin-top: 6px;
    }

    .comp-table th {
      text-align: left;
      padding: 10px 14px;
      background: var(--bg-surface);
      color: var(--text-muted);
      border-bottom: 2px solid var(--border-subtle);
      font-weight: 700;
    }

    .comp-table th:last-child {
      background: rgba(16, 185, 129, 0.12);
      color: var(--emerald);
      border-bottom-color: var(--emerald);
    }

    .comp-table td {
      padding: 9px 14px;
      border-bottom: 1px solid var(--border-subtle);
      color: var(--text-main);
    }

    .comp-table tr:hover td {
      background: rgba(255, 255, 255, 0.02);
    }

    .comp-table td:last-child {
      background: rgba(16, 185, 129, 0.04);
      font-weight: 700;
      color: var(--emerald);
    }

    /* State Machine Graphic */
    .state-machine-container {
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: 12px;
      padding: 16px;
      box-shadow: 0 10px 25px rgba(0,0,0,0.15);
    }

    .flow-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 7px;
      margin-bottom: 12px;
    }

    .node-box {
      flex: 1;
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      border-radius: 8px;
      padding: 9px 6px;
      text-align: center;
      cursor: pointer;
      transition: border-color 0.2s ease, box-shadow 0.2s ease;
      position: relative;
    }

    .node-box:hover, .node-box.active-node {
      border-color: var(--cyan);
      box-shadow: 0 0 14px var(--cyan-glow);
    }

    .node-box.active-node {
      border-color: var(--emerald);
      background: rgba(16, 185, 129, 0.08);
    }

    .node-num {
      font-family: var(--font-mono);
      font-size: 9.5px;
      color: var(--text-dim);
      margin-bottom: 3px;
    }

    .node-name {
      font-size: 11.5px;
      font-weight: 700;
      color: var(--text-main);
    }

    .flow-arrow {
      color: var(--text-dim);
      font-size: 13px;
    }

    .node-detail-panel {
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      border-radius: 8px;
      padding: 12px 16px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      min-height: 58px;
    }

    /* Terminal Window */
    .terminal-window {
      background: var(--terminal-bg);
      border: 1px solid var(--border-subtle);
      border-radius: 10px;
      overflow: hidden;
      font-family: var(--font-mono);
      box-shadow: 0 15px 35px rgba(0,0,0,0.4);
    }

    .terminal-header {
      background: var(--terminal-header);
      padding: 9px 14px;
      display: flex;
      align-items: center;
      gap: 7px;
      border-bottom: 1px solid var(--border-subtle);
    }

    .term-dot { width: 10px; height: 10px; border-radius: 50%; }
    .term-red { background: #ef4444; }
    .term-yellow { background: #f59e0b; }
    .term-green { background: #10b981; }

    .terminal-body {
      padding: 16px 20px;
      font-size: 12px;
      line-height: 1.65;
      color: var(--terminal-text);
      max-height: 290px;
      overflow-y: auto;
    }

    .term-prompt { color: var(--emerald); font-weight: 700; }
    .term-accent { color: var(--cyan); }
    .term-success { color: #34d399; }
    .term-warn { color: #fbbf24; }
    .term-diff-sub { color: #f87171; }
    .term-diff-add { color: #4ade80; }

    /* Bottom Control Bar */
    .narration-bar {
      height: 70px;
      padding: 0 28px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      background: var(--narration-bg);
      border-top: 1px solid var(--border-subtle);
      backdrop-filter: blur(12px);
      z-index: 100;
      gap: 20px;
    }

    .narrator-avatar {
      display: flex;
      align-items: center;
      gap: 12px;
      min-width: 220px;
    }

    .audio-waves {
      display: flex;
      align-items: center;
      gap: 3px;
      height: 24px;
      padding: 0 4px;
    }

    .wave-bar {
      width: 3.5px;
      height: 6px;
      background: var(--emerald);
      border-radius: 9999px;
      transition: height 0.15s ease;
    }

    .audio-waves.waves-active .wave-bar:nth-child(1) { animation: wavePulse 0.7s infinite alternate 0.1s; }
    .audio-waves.waves-active .wave-bar:nth-child(2) { animation: wavePulse 0.5s infinite alternate 0.25s; }
    .audio-waves.waves-active .wave-bar:nth-child(3) { animation: wavePulse 0.8s infinite alternate 0.15s; }
    .audio-waves.waves-active .wave-bar:nth-child(4) { animation: wavePulse 0.6s infinite alternate 0.3s; }
    .audio-waves.waves-active .wave-bar:nth-child(5) { animation: wavePulse 0.75s infinite alternate 0.05s; }

    @keyframes wavePulse {
      0% { height: 4px; opacity: 0.4; }
      100% { height: 22px; opacity: 1; background: var(--cyan); }
    }

    .narration-text {
      flex: 1;
      font-size: 13px;
      color: var(--text-muted);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      line-height: 1.4;
    }

    .narration-text span {
      color: var(--emerald);
      font-weight: 700;
      margin-right: 6px;
    }

    .progress-bar-container {
      width: 130px;
      height: 5px;
      background: var(--border-subtle);
      border-radius: 9999px;
      overflow: hidden;
    }

    .progress-bar-fill {
      height: 100%;
      width: 0%;
      background: linear-gradient(90deg, var(--emerald), var(--cyan));
      border-radius: 9999px;
      transition: width 0.25s linear;
    }

    /* Speaker Notes Drawer */
    #speakerNotesDrawer {
      position: fixed;
      bottom: 70px;
      right: 28px;
      width: 440px;
      max-height: 290px;
      background: var(--bg-surface);
      border: 1px solid var(--border-subtle);
      border-radius: 12px;
      padding: 18px;
      box-shadow: 0 20px 45px rgba(0,0,0,0.5);
      z-index: 99;
      display: none;
      overflow-y: auto;
      font-size: 12.5px;
      line-height: 1.6;
      color: var(--text-muted);
    }

    #speakerNotesDrawer.open { display: block; }

    /* Print / PDF Mode */
    @media print {
      body { overflow: visible !important; height: auto !important; }
      header, .narration-bar, #ambientCanvas, #speakerNotesDrawer { display: none !important; }
      main { padding: 0 !important; }
      .slide-viewport { max-width: 100% !important; max-height: none !important; height: auto !important; }
      .slide { position: relative !important; opacity: 1 !important; transform: none !important; page-break-after: always; margin-bottom: 24px; }
      .ppt-item { opacity: 1 !important; transform: none !important; }
    }
  </style>
</head>
<body>

  <!-- Ambient Network Canvas -->
  <canvas id="ambientCanvas"></canvas>

  <!-- Top Executive Header -->
  <header>
    <div class="logo-container">
      <div class="logo-icon">🛡️</div>
      <div class="logo-text">VulnFlow AI</div>
      <div class="logo-pill">Architecture Briefing</div>
    </div>

    <div class="header-controls">
      <button id="btnVideoMode" class="btn btn-primary" title="Play or Pause automated presentation video with voiceover (P)">
        <span id="videoPlayIcon">▶</span> <span id="videoBtnText">Auto-Play Video Demo</span>
      </button>

      <button id="btnSoundToggle" class="btn" title="Toggle Sound / Voiceover (M)">
        <span id="soundIcon">🔊</span> <span id="soundText">Voice On</span>
      </button>

      <button id="btnTestAudio" class="btn" title="Click to test audio & voiceover immediately">
        <span style="color: #38bdf8;">⚡</span> Test Sound
      </button>

      <button id="btnBuildToggle" class="btn" title="Toggle PowerPoint Content Animations / Builds (B)">
        <span id="buildIcon">✨</span> <span id="buildText">Builds: ON</span>
      </button>

      <button id="btnThemeToggle" class="btn" title="Switch between Light & Dark Mode (T)">
        <span id="themeIcon">☀️</span> <span id="themeText">Light Mode</span>
      </button>

      <button id="btnNotes" class="btn" title="Toggle Presenter Notes (S)">🎙️ Notes</button>
      <button id="btnPrint" class="btn" title="Print or Save as High-Res PDF Deck">📄 PDF</button>
      <button id="btnFullscreen" class="btn" title="Toggle Fullscreen (F)">⛶</button>
    </div>
  </header>

  <!-- Slide Viewport Stage -->
  <main id="mainContainer">
    <div class="slide-viewport" id="slideViewport">

      <!-- SLIDE 1: HERO / TITLE -->
      <section class="slide active" id="slide-1" data-duration="17" 
               data-narration="Welcome to the VulnFlow AI Enterprise Architecture Briefing: agentic vulnerability remediation that bridges the gap from scanner noise to verified pull requests.">
        <div>
          <div class="slide-tagline">🏛️ Enterprise Architecture Briefing</div>
          <h1 class="slide-title" style="font-size: 38px;">
            VulnFlow AI
          </h1>
          <p class="slide-subtitle" style="font-size: 17px;">
            Agentic vulnerability remediation: from scanner noise to verified pull requests
          </p>
        </div>

        <div class="slide-body">
          <div class="grid-3" style="margin-bottom: 24px;">
            <div class="card card-accent-cyan ppt-item">
              <div class="card-title">🤖 LLM Agents Propose</div>
              <p class="card-desc">Specialized AI agents inspect advisory vectors, traverse dependency trees, and formulate targeted remediation candidates.</p>
            </div>
            <div class="card card-accent-emerald ppt-item">
              <div class="card-title">⚙️ Deterministic Code Executes</div>
              <p class="card-desc">Hard policy enforcement, SemVer constraints, and package whitelists run strictly in deterministic code—never hallucinated by an LLM.</p>
            </div>
            <div class="card card-accent-purple ppt-item">
              <div class="card-title">🔍 Scanners Verify</div>
              <p class="card-desc">Patches are built and pre-tested in isolated ephemeral sandboxes, then rescanned to mathematically verify CVE elimination before opening PRs.</p>
            </div>
          </div>

          <div class="ppt-item" style="display: flex; gap: 12px; align-items: center; justify-content: center; background: var(--bg-surface); padding: 13px; border-radius: 9px; border: 1px solid var(--border-subtle);">
            <span class="badge badge-cyan">LangGraph State Machine</span>
            <span class="badge badge-emerald">FastMCP Tool Isolation</span>
            <span class="badge badge-amber">Supabase Durable Approvals</span>
            <span class="badge badge-purple">Neo4j Dependency Graph</span>
          </div>
        </div>

        <div style="display: flex; justify-content: space-between; align-items: center; font-size: 12px; color: var(--text-dim); border-top: 1px solid var(--border-subtle); padding-top: 14px;">
          <span>CONFIDENTIAL • VULNFLOW ARCHITECTURE WORKING GROUP</span>
          <span>SLIDE 01 / 13</span>
        </div>
      </section>

      <!-- SLIDE 2: PROBLEM STATEMENT -->
      <section class="slide" id="slide-2" data-duration="22"
               data-narration="The gap VulnFlow is built to close: scanners tell teams what is vulnerable, but turning findings into safe, policy-compliant, verified fixes is still manual, slow, and risky at scale.">
        <div>
          <div class="slide-tagline" style="color: var(--rose);">⚠️ The Gap VulnFlow is Built to Close</div>
          <h2 class="slide-title">Problem Statement</h2>
          <p class="slide-subtitle">Modern security scanning creates visibility, but product engineers bear the crushing operational burden of manual remediation.</p>
        </div>

        <div class="slide-body">
          <div class="card ppt-item" style="background: rgba(244, 63, 94, 0.08); border: 1px solid rgba(244, 63, 94, 0.35); margin-bottom: 20px; padding: 16px 22px;">
            <div style="font-weight: 800; font-size: 15.5px; color: var(--rose); margin-bottom: 4px;">THE PROBLEM:</div>
            <div style="font-size: 14px; color: var(--text-main); line-height: 1.5;">
              Scanners tell teams what is vulnerable, but turning findings into safe, policy-compliant, verified fixes is still manual, slow and risky at scale.
            </div>
          </div>

          <div class="grid-3" style="gap: 18px;">
            <div class="card card-accent-rose ppt-item">
              <div class="card-title" style="color: var(--rose);">👥 Who Feels It</div>
              <ul style="list-style: none; font-size: 12.5px; line-height: 1.65; color: var(--text-muted); margin-top: 6px;">
                <li>• <b>Developers:</b> Lose sprint hours to triage and manual lockfile upgrades.</li>
                <li>• <b>Security:</b> Cannot see which cascading findings share a single fix.</li>
                <li>• <b>Leaders:</b> See escalating CVE backlogs, not verified closure.</li>
              </ul>
            </div>

            <div class="card card-accent-amber ppt-item">
              <div class="card-title" style="color: var(--amber);">⚠️ Why Current Tools Fall Short</div>
              <ul style="list-style: none; font-size: 12.5px; line-height: 1.65; color: var(--text-muted); margin-top: 6px;">
                <li>• <b>Scanners:</b> Stop at detection, leaving 100% of the fix toil to engineers.</li>
                <li>• <b>Bump Bots:</b> Bump versions blindly without root-cause or policy context.</li>
                <li>• <b>Blind Fixes:</b> Rarely compiled, tested, or rescanned before PR creation.</li>
              </ul>
            </div>

            <div class="card card-accent-emerald ppt-item">
              <div class="card-title" style="color: var(--emerald);">🎯 What a Solution Must Do</div>
              <ul style="list-style: none; font-size: 12.5px; line-height: 1.65; color: var(--text-muted); margin-top: 6px;">
                <li>• <b>Group findings</b> by direct transitive root cause.</li>
                <li>• <b>Enforce policy in code</b> (whitelists, SemVer, licenses).</li>
                <li>• <b>Test in a sandbox</b> and mathematically verify by rescan diff.</li>
                <li>• <b>Keep humans in the loop</b> on high-risk major version changes.</li>
              </ul>
            </div>
          </div>
        </div>

        <div style="font-size: 12px; color: var(--text-dim); border-top: 1px solid var(--border-subtle); padding-top: 14px;">
          <span>SLIDE 02 / 13 • PROBLEM STATEMENT</span>
        </div>
      </section>

      <!-- SLIDE 3: DETECTION IS MATURE. REMEDIATION IS MANUAL -->
      <section class="slide" id="slide-3" data-duration="20"
               data-narration="Detection is mature, but remediation is still manual. Where the gap shows up: alert noise, duplicate root causes, toil and risk. In one real scan, four hundred twenty-six findings collapsed into forty-three direct root causes.">
        <div>
          <div class="slide-tagline" style="color: var(--amber);">⚡ The Operational Reality</div>
          <h2 class="slide-title">Detection is Mature. Remediation is Still Manual.</h2>
          <p class="slide-subtitle">Where the gap shows up: three pain points and one real data point.</p>
        </div>

        <div class="slide-body">
          <div class="grid-3" style="margin-bottom: 20px;">
            <div class="card card-accent-rose ppt-item">
              <div class="card-title" style="color: var(--rose);">🔔 Alert Noise</div>
              <p class="card-desc">Every scanner reports every CVE in every location. Repositories accumulate hundreds of duplicated alerts and backlogs outgrow human triage bandwidth.</p>
              <div style="margin-top: 10px;"><span class="badge badge-rose">Alert Fatigue</span></div>
            </div>

            <div class="card card-accent-amber ppt-item">
              <div class="card-title" style="color: var(--amber);">🌳 Duplicate Root Causes</div>
              <p class="card-desc">One outdated direct dependency fans out into dozens of transitive findings across lockfiles that share a single common root-cause fix.</p>
              <div style="margin-top: 10px;"><span class="badge badge-amber">Cascading Noise</span></div>
            </div>

            <div class="card card-accent-purple ppt-item">
              <div class="card-title" style="color: var(--purple);">🛠️ Toil and Risk</div>
              <p class="card-desc">Triage, policy checks, sandbox testing, and PR drafting are entirely manual. Meanwhile, blind bot upgrades break builds and stall CI/CD pipelines.</p>
              <div style="margin-top: 10px;"><span class="badge badge-purple">High Engineering Cost</span></div>
            </div>
          </div>

          <!-- Highlight Metric Card -->
          <div class="card ppt-item" style="background: var(--bg-surface); border: 1px solid var(--emerald); display: flex; align-items: center; justify-content: space-between; padding: 18px 24px;">
            <div>
              <div style="font-size: 11px; text-transform: uppercase; font-weight: 700; color: var(--emerald); letter-spacing: 1px;">Real Scan Data Point</div>
              <div style="font-size: 26px; font-weight: 800; color: var(--text-main); margin-top: 2px;">
                <span style="color: var(--rose);">426 findings</span> ➔ <span style="color: var(--emerald);">43 root causes</span>
              </div>
              <div style="font-size: 12px; color: var(--text-dim); margin-top: 4px;">Single test repository, shown for illustration. Not an average.</div>
            </div>
            <div style="text-align: right; max-width: 440px; font-size: 13px; color: var(--text-muted); line-height: 1.5;">
              By collapsing 426 scanner alerts into 43 root-cause packages, developers review 1 coherent fix instead of triaging dozens of identical alerts.
            </div>
          </div>
        </div>

        <div style="font-size: 12px; color: var(--text-dim); border-top: 1px solid var(--border-subtle); padding-top: 14px;">
          <span>SLIDE 03 / 13 • THE OPERATIONAL GAP</span>
        </div>
      </section>

      <!-- SLIDE 4: HOW VULNFLOW DIFFERS -->
      <section class="slide" id="slide-4" data-duration="22"
               data-narration="How VulnFlow differs from existing tools: detection, bump bots, and vendor autofix each cover part of the loop. VulnFlow closes it with built-in multi-scanner ingestion, root-cause grouping, policy in code, and sandboxed rescan verification.">
        <div>
          <div class="slide-tagline">⚔️ Market Differentiation</div>
          <h2 class="slide-title">How VulnFlow Differs from Existing Tools</h2>
          <p class="slide-subtitle">Detection, bump bots and vendor autofix each cover part of the loop. VulnFlow closes it.</p>
        </div>

        <div class="slide-body">
          <div class="card ppt-item" style="padding: 6px 12px; margin-bottom: 14px;">
            <table class="comp-table">
              <thead>
                <tr>
                  <th>Capability</th>
                  <th>Scanners</th>
                  <th>Bump Bots</th>
                  <th>Vendor Autofix</th>
                  <th>VulnFlow AI</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td><b>Ingests findings from many scanners</b></td>
                  <td>Built in</td>
                  <td>Not a focus</td>
                  <td>Partial</td>
                  <td>✅ Built in</td>
                </tr>
                <tr>
                  <td><b>Groups findings into root causes</b></td>
                  <td>Partial</td>
                  <td>Not a focus</td>
                  <td>Partial</td>
                  <td>✅ Built in</td>
                </tr>
                <tr>
                  <td><b>Enforces org policy as code</b></td>
                  <td>Partial</td>
                  <td>Partial</td>
                  <td>Partial</td>
                  <td>✅ Built in</td>
                </tr>
                <tr>
                  <td><b>Tests the fix in a sandbox before PR</b></td>
                  <td>Not a focus</td>
                  <td>Partial</td>
                  <td>Partial</td>
                  <td>✅ Built in</td>
                </tr>
                <tr>
                  <td><b>Rescans to prove the fix worked</b></td>
                  <td>Partial</td>
                  <td>Not a focus</td>
                  <td>Partial</td>
                  <td>✅ Built in</td>
                </tr>
                <tr>
                  <td><b>Gated approvals with an audit trail</b></td>
                  <td>Not a focus</td>
                  <td>Partial</td>
                  <td>Partial</td>
                  <td>✅ Built in</td>
                </tr>
                <tr>
                  <td><b>Agent retries when a fix fails</b></td>
                  <td>Not a focus</td>
                  <td>Not a focus</td>
                  <td>Partial</td>
                  <td>✅ Built in</td>
                </tr>
              </tbody>
            </table>
          </div>

          <div class="ppt-item" style="font-size: 11.5px; color: var(--text-dim); line-height: 1.5; background: var(--bg-surface); padding: 10px 14px; border-radius: 8px; border: 1px solid var(--border-subtle);">
            <b>Note:</b> Category-level view; capabilities vary by product. <i>Bump bots</i>: Dependabot or Renovate style. <i>Vendor autofix</i>: remediation features of a scanner vendor.
          </div>
        </div>

        <div style="font-size: 12px; color: var(--text-dim); border-top: 1px solid var(--border-subtle); padding-top: 14px;">
          <span>SLIDE 04 / 13 • HOW VULNFLOW DIFFERS</span>
        </div>
      </section>

      <!-- SLIDE 5: FOUR TIERS WITH HARD BOUNDARIES -->
      <section class="slide" id="slide-5" data-duration="24"
               data-narration="VulnFlow's architecture has four tiers with hard boundaries. Only Tier 2 calls an LLM. Everything that touches code, policy, or scans is deterministic.">
        <div>
          <div class="slide-tagline">🏛️ Architectural Boundaries</div>
          <h2 class="slide-title">Four Tiers with Hard Boundaries</h2>
          <p class="slide-subtitle">Only Tier 2 calls an LLM. Everything that touches code, policy or scans is deterministic.</p>
        </div>

        <div class="slide-body">
          <div class="grid-4" style="gap: 16px; margin-bottom: 20px;">
            <div class="card card-accent-cyan ppt-item">
              <div class="badge badge-cyan" style="margin-bottom: 8px;">TIER 1 • INGESTION</div>
              <div class="card-title">Ingest & Redaction</div>
              <ul style="list-style: none; font-size: 12px; line-height: 1.6; color: var(--text-muted); margin-top: 6px;">
                <li>• Reads Trivy, Grype, Gitleaks, Snyk</li>
                <li>• Redacts secrets at the edge</li>
                <li>• Fingerprints and dedupes</li>
              </ul>
            </div>

            <div class="card card-accent-emerald ppt-item">
              <div class="badge badge-emerald" style="margin-bottom: 8px;">TIER 2 • ORCHESTRATION</div>
              <div class="card-title">Agent Orchestration</div>
              <ul style="list-style: none; font-size: 12px; line-height: 1.6; color: var(--text-muted); margin-top: 6px;">
                <li>• LangGraph, 10 checkpointed nodes</li>
                <li>• Triage, root-cause, planner, fixer, verifier</li>
                <li>• Human approval gate</li>
              </ul>
            </div>

            <div class="card card-accent-amber ppt-item">
              <div class="badge badge-amber" style="margin-bottom: 8px;">TIER 3 • TOOLS (FastMCP)</div>
              <div class="card-title">FastMCP Tool Servers</div>
              <ul style="list-style: none; font-size: 12px; line-height: 1.6; color: var(--text-muted); margin-top: 6px;">
                <li>• Stdio servers, no pip dependencies</li>
                <li>• git, build, scan, policy tools</li>
                <li>• All side effects live here</li>
              </ul>
            </div>

            <div class="card card-accent-purple ppt-item">
              <div class="badge badge-purple" style="margin-bottom: 8px;">TIER 4 • VERIFICATION</div>
              <div class="card-title">Sandbox & Knowledge</div>
              <ul style="list-style: none; font-size: 12px; line-height: 1.6; color: var(--text-muted); margin-top: 6px;">
                <li>• Docker sandbox runs build & tests</li>
                <li>• Neo4j: dependency paths, blast radius</li>
                <li>• Vector RAG: advisories, playbooks</li>
              </ul>
            </div>
          </div>

          <div class="ppt-item" style="background: var(--bg-surface); border: 1px dashed var(--border-subtle); border-radius: 9px; padding: 12px 18px; display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; font-size: 11.5px;">
            <div><b style="color: var(--cyan);">Outputs:</b> PR with cited evidence, Jira exception, audit log, OTel traces</div>
            <div><b style="color: var(--emerald);">CI-native:</b> Single container step for GitHub Actions, GitLab CI, Jenkins</div>
            <div><b style="color: var(--purple);">Model-agnostic:</b> NVIDIA NIM, Claude, OpenAI, Bedrock, Ollama</div>
            <div><b style="color: var(--amber);">Control plane:</b> React web UI & REST API; Supabase durable approvals</div>
          </div>
        </div>

        <div style="font-size: 12px; color: var(--text-dim); border-top: 1px solid var(--border-subtle); padding-top: 14px;">
          <span>SLIDE 05 / 13 • FOUR TIERS WITH HARD BOUNDARIES</span>
        </div>
      </section>

      <!-- SLIDE 6: THE 10-NODE WORKFLOW -->
      <section class="slide" id="slide-6" data-duration="24"
               data-narration="The ten-node remediation workflow: a checkpointed LangGraph state machine where each node is either an AI agent, deterministic code, or a human decision gate.">
        <div>
          <div class="slide-tagline">⚙️ Operational State Machine</div>
          <h2 class="slide-title">The 10-Node Remediation Workflow</h2>
          <p class="slide-subtitle">A checkpointed LangGraph state machine. Each node is an agent, deterministic code, or a human.</p>
        </div>

        <div class="slide-body">
          <div class="state-machine-container">
            <!-- Row 1 -->
            <div class="flow-row ppt-item">
              <div class="node-box" data-node="ingest" onclick="selectNode('ingest')">
                <div class="node-num">01 INGEST</div>
                <div class="node-name">📥 Ingest</div>
                <div style="font-size: 9.5px; color: var(--text-dim); margin-top: 2px;">Code</div>
              </div>
              <div class="flow-arrow">➔</div>
              <div class="node-box" data-node="dedupe" onclick="selectNode('dedupe')">
                <div class="node-num">02 DEDUPE</div>
                <div class="node-name">🧹 Dedupe</div>
                <div style="font-size: 9.5px; color: var(--text-dim); margin-top: 2px;">Code</div>
              </div>
              <div class="flow-arrow">➔</div>
              <div class="node-box" data-node="rootcause" onclick="selectNode('rootcause')">
                <div class="node-num">03 ROOT CAUSE</div>
                <div class="node-name" style="color: var(--cyan);">🌳 Root Cause</div>
                <div style="font-size: 9.5px; color: var(--cyan); margin-top: 2px;">Agent</div>
              </div>
              <div class="flow-arrow">➔</div>
              <div class="node-box" data-node="policy" onclick="selectNode('policy')">
                <div class="node-num">04 POLICY</div>
                <div class="node-name">⚖️ Policy Check</div>
                <div style="font-size: 9.5px; color: var(--text-dim); margin-top: 2px;">Code</div>
              </div>
              <div class="flow-arrow">➔</div>
              <div class="node-box" data-node="plan" onclick="selectNode('plan')">
                <div class="node-num">05 PLAN</div>
                <div class="node-name" style="color: var(--cyan);">📝 Plan</div>
                <div style="font-size: 9.5px; color: var(--cyan); margin-top: 2px;">Agent</div>
              </div>
            </div>

            <!-- Row 2 -->
            <div class="flow-row ppt-item">
              <div class="node-box" data-node="approval" onclick="selectNode('approval')">
                <div class="node-num">06 APPROVAL</div>
                <div class="node-name" style="color: var(--amber);">🚦 Approval Gate</div>
                <div style="font-size: 9.5px; color: var(--amber); margin-top: 2px;">Human</div>
              </div>
              <div class="flow-arrow">➔</div>
              <div class="node-box" data-node="sandbox" onclick="selectNode('sandbox')">
                <div class="node-num">07 SANDBOX</div>
                <div class="node-name" style="color: var(--cyan);">🧪 Sandbox Loop</div>
                <div style="font-size: 9.5px; color: var(--cyan); margin-top: 2px;">Agent</div>
              </div>
              <div class="flow-arrow">➔</div>
              <div class="node-box" data-node="pr" onclick="selectNode('pr')">
                <div class="node-num">08 PULL REQUEST</div>
                <div class="node-name">🚀 Pull Request</div>
                <div style="font-size: 9.5px; color: var(--text-dim); margin-top: 2px;">Code</div>
              </div>
              <div class="flow-arrow">➔</div>
              <div class="node-box" data-node="verify" onclick="selectNode('verify')">
                <div class="node-num">09 VERIFY</div>
                <div class="node-name" style="color: var(--emerald);">🔍 Verify Rescan</div>
                <div style="font-size: 9.5px; color: var(--emerald); margin-top: 2px;">Code</div>
              </div>
              <div class="flow-arrow">➔</div>
              <div class="node-box" data-node="audit" onclick="selectNode('audit')">
                <div class="node-num">10 AUDIT</div>
                <div class="node-name">📊 Audit & Close</div>
                <div style="font-size: 9.5px; color: var(--text-dim); margin-top: 2px;">Code</div>
              </div>
            </div>

            <!-- Dynamic Node Info Panel -->
            <div id="nodeDetailPanel" class="node-detail-panel ppt-item">
              <div>
                <span id="detailBadge" class="badge badge-amber">NODE 06 • HUMAN APPROVAL GATE</span>
                <div id="detailTitle" style="font-weight: 700; color: var(--text-main); margin-top: 4px; font-size: 13.5px;">Human Authorization & State Checkpointing</div>
                <div id="detailText" style="color: var(--text-muted); font-size: 12px; margin-top: 2px;">
                  Pauses workflow on REVIEW-tier changes (major bumps, unapproved packages). Emits Exit Code 10, saves checkpoint to Supabase, and awaits reviewer authorization.
                </div>
              </div>
              <div id="detailExtra" style="text-align: right; font-family: var(--font-mono); font-size: 11px; color: var(--text-dim);">
                <div>INVARIANT: No PR without approval</div>
                <div style="color: var(--emerald); font-weight: 700;">STATUS: Gate Active</div>
              </div>
            </div>
          </div>

          <div class="ppt-item" style="display: flex; gap: 18px; justify-content: center; margin-top: 10px; font-size: 11.5px; color: var(--text-muted);">
            <span>🤖 <b style="color: var(--cyan);">Agent:</b> LLM reasoning</span>
            <span>⚙️ <b style="color: var(--text-main);">Deterministic code:</b> Hard rails</span>
            <span>🚦 <b style="color: var(--amber);">Human decision:</b> Exit code 10</span>
          </div>
        </div>

        <div style="font-size: 12px; color: var(--text-dim); border-top: 1px solid var(--border-subtle); padding-top: 14px;">
          <span>SLIDE 06 / 13 • 10-NODE REMEDIATION WORKFLOW</span>
        </div>
      </section>

      <!-- SLIDE 7: AGENTIC AI: SPECIALIZED AGENTS -->
      <section class="slide" id="slide-7" data-duration="24"
               data-narration="Agentic AI in VulnFlow uses specialized agents with bounded roles: triage, root-cause, planner, self-correcting fixer, verifier, and secrets and expiry agents. Each has its own tools and strict decision limits.">
        <div>
          <div class="slide-tagline">🧠 Agentic Intelligence</div>
          <h2 class="slide-title">Agentic AI: Specialized Agents, Bounded Roles</h2>
          <p class="slide-subtitle">Each agent has one job, its own tools, and a hard limit on what it can decide.</p>
        </div>

        <div class="slide-body">
          <div class="grid-6" style="margin-bottom: 16px;">
            <div class="card card-accent-cyan ppt-item">
              <div class="card-title">🎯 Triage Agent</div>
              <p class="card-desc">Sorts deduplicated findings so the right ones reach planning. Fast model here; a stronger one plans.</p>
              <div style="margin-top: 6px;"><span class="badge badge-cyan">Model Routing</span></div>
            </div>

            <div class="card card-accent-emerald ppt-item">
              <div class="card-title">🌳 Root-Cause Agent</div>
              <p class="card-desc">Traces transitive CVEs to the direct parent using the Neo4j graph. Cannot override graph facts.</p>
              <div style="margin-top: 6px;"><span class="badge badge-emerald">Graph Grounding</span></div>
            </div>

            <div class="card card-accent-purple ppt-item">
              <div class="card-title">📝 Planner Agent</div>
              <p class="card-desc">Proposes a target version and cites the advisories behind it. The policy engine can reject the plan.</p>
              <div style="margin-top: 6px;"><span class="badge badge-purple">Advisory Evidence</span></div>
            </div>

            <div class="card card-accent-amber ppt-item">
              <div class="card-title">🔄 Self-Correcting Fixer</div>
              <p class="card-desc">Reads build and test failures, rolls back and tries a safer version. Works only inside the sandbox.</p>
              <div style="margin-top: 6px;"><span class="badge badge-amber">Bounded Execution</span></div>
            </div>

            <div class="card card-accent-emerald ppt-item">
              <div class="card-title">✅ Verifier Agent</div>
              <p class="card-desc">Rescans and compares before and after diffs. Never reports a failed scan as success.</p>
              <div style="margin-top: 6px;"><span class="badge badge-emerald">Rescan Proof</span></div>
            </div>

            <div class="card card-accent-rose ppt-item">
              <div class="card-title">🔐 Secrets & Expiry</div>
              <p class="card-desc">Drafts rotation checklists for leaked secrets and flags expiring certificates. Sees fingerprints, never raw secrets.</p>
              <div style="margin-top: 6px;"><span class="badge badge-rose">Zero-Knowledge</span></div>
            </div>
          </div>

          <div class="ppt-item" style="text-align: center; font-size: 12px; color: var(--emerald); font-weight: 700; background: var(--bg-surface); padding: 9px; border-radius: 8px; border: 1px solid var(--border-subtle);">
            Goal-driven &bull; Tool-using via MCP &bull; Stateful and resumable &bull; Self-correcting &bull; Bounded autonomy
          </div>
        </div>

        <div style="font-size: 12px; color: var(--text-dim); border-top: 1px solid var(--border-subtle); padding-top: 14px;">
          <span>SLIDE 07 / 13 • AGENTIC AI SPECIALIZATION</span>
        </div>
      </section>

      <!-- SLIDE 8: SELF-CORRECTION -->
      <section class="slide" id="slide-8" data-duration="22"
               data-narration="Self-correction is the loop that removes broken PRs. When tests fail in the Docker sandbox, the fixer agent analyzes the compiler logs, rolls back breaking changes, and tests a safer version before any PR is created.">
        <div>
          <div class="slide-tagline">🔁 Autonomous Error Recovery</div>
          <h2 class="slide-title">Self-Correction: The Loop That Removes Broken PRs</h2>
          <p class="slide-subtitle">When tests fail, the agent reads the evidence and retries before any PR opens.</p>
        </div>

        <div class="slide-body">
          <div class="card ppt-item" style="background: var(--bg-surface); border: 1px solid var(--border-subtle); margin-bottom: 20px;">
            <div style="font-size: 12px; font-weight: 700; color: var(--text-dim); text-transform: uppercase; margin-bottom: 12px;">Illustrative Scenario Flow:</div>
            
            <div style="display: flex; align-items: center; justify-content: space-between; font-size: 12px; gap: 8px;">
              <div style="background: var(--bg-card); padding: 10px 14px; border-radius: 7px; border: 1px solid var(--border-subtle); text-align: center;">
                <b>1. Patch manifest</b><br>
                <code style="color: var(--text-muted);">Django 4.2 ➔ 5.2</code>
              </div>
              <div class="flow-arrow">➔</div>
              <div style="background: rgba(239, 68, 68, 0.12); padding: 10px 14px; border-radius: 7px; border: 1px solid rgba(239, 68, 68, 0.4); text-align: center;">
                <b style="color: var(--rose);">2. Sandbox tests fail</b><br>
                <span style="color: var(--rose); font-size: 11px;">[FAIL ❌] Breaking API</span>
              </div>
              <div class="flow-arrow">➔</div>
              <div style="background: rgba(6, 182, 212, 0.12); padding: 10px 14px; border-radius: 7px; border: 1px solid rgba(6, 182, 212, 0.4); text-align: center;">
                <b style="color: var(--cyan);">3. Agent reads logs</b><br>
                <span style="color: var(--cyan); font-size: 11px;">Rollback ➔ picks 5.0.12</span>
              </div>
              <div class="flow-arrow">➔</div>
              <div style="background: rgba(16, 185, 129, 0.12); padding: 10px 14px; border-radius: 7px; border: 1px solid rgba(16, 185, 129, 0.4); text-align: center;">
                <b style="color: var(--emerald);">4. Re-test passes</b><br>
                <span style="color: var(--emerald); font-size: 11px;">[PASS ✅] 0 errors</span>
              </div>
              <div class="flow-arrow">➔</div>
              <div style="background: var(--bg-card); padding: 10px 14px; border-radius: 7px; border: 1px solid var(--emerald); text-align: center;">
                <b style="color: var(--emerald);">5. Open PR</b><br>
                <span style="color: var(--text-main); font-size: 11px;">Cites advisories</span>
              </div>
            </div>
          </div>

          <div class="grid-3" style="gap: 16px;">
            <div class="card card-accent-emerald ppt-item">
              <div class="card-title" style="color: var(--emerald);">🛡️ No Broken PRs</div>
              <p class="card-desc">Developers receive a pull request that already passed compiler builds and unit test suites.</p>
            </div>
            <div class="card card-accent-cyan ppt-item">
              <div class="card-title" style="color: var(--cyan);">📦 Safe by Construction</div>
              <p class="card-desc">Patches run exclusively in an ephemeral sandbox container, never on main branches or developer laptops.</p>
            </div>
            <div class="card card-accent-purple ppt-item">
              <div class="card-title" style="color: var(--purple);">📜 Evidence Travels with Fix</div>
              <p class="card-desc">Every pull request includes exact CVE links, advisory vectors, and the test pass logs proving safety.</p>
            </div>
          </div>
        </div>

        <div style="font-size: 12px; color: var(--text-dim); border-top: 1px solid var(--border-subtle); padding-top: 14px;">
          <span>SLIDE 08 / 13 • SELF-CORRECTION LOOP</span>
        </div>
      </section>

      <!-- SLIDE 9: GOVERNANCE & SAFETY -->
      <section class="slide" id="slide-9" data-duration="22"
               data-narration="Governance: policy in code, humans at the gates. Rules load from YAML or enterprise registries, enforcing three deterministic risk tiers. Approval state is persisted durably in Supabase across all CI workers.">
        <div>
          <div class="slide-tagline" style="color: var(--amber);">🛡️ Safety, Trust & Governance</div>
          <h2 class="slide-title">Governance: Policy in Code, Humans at the Gates</h2>
          <p class="slide-subtitle">Rules load from YAML, Artifactory, Nexus or OPA. The model never makes the call.</p>
        </div>

        <div class="slide-body">
          <div class="grid-2" style="gap: 22px;">
            <!-- Column 1 -->
            <div class="card card-accent-amber ppt-item">
              <div class="card-title" style="color: var(--amber);">🚦 Risk Model Enforced in Code</div>
              <ul style="list-style: none; font-size: 12.5px; line-height: 1.75; color: var(--text-muted); margin-top: 8px;">
                <li>• <b style="color: var(--emerald);">AUTO:</b> Minor and patch bumps that pass sandbox tests open a PR directly.</li>
                <li>• <b style="color: var(--amber);">REVIEW:</b> Major upgrades and unknown packages pause the run (Exit Code 10).</li>
                <li>• <b style="color: var(--rose);">BLOCKED:</b> Banned packages open a Jira exception ticket (Exit Code 20).</li>
              </ul>
              <div style="margin-top: 14px; font-family: var(--font-mono); font-size: 11px; color: var(--text-dim); background: var(--bg-surface); padding: 8px 12px; border-radius: 6px;">
                Invariant: All policy logic evaluated in pure Python code.
              </div>
            </div>

            <!-- Column 2 -->
            <div class="card card-accent-cyan ppt-item">
              <div class="card-title" style="color: var(--cyan);">📋 Approval Workflow & Enterprise Controls</div>
              <div style="margin-top: 8px;">
                <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 6px;">
                  <span class="badge badge-emerald">BUILT</span>
                  <span style="font-size: 12.5px; color: var(--text-main); font-weight: 600;">Supabase Database Persistence</span>
                </div>
                <p class="card-desc" style="font-size: 12px; margin-left: 4px;">Approval state and execution checkpoints survive across ephemeral CI workers and action runs.</p>
              </div>

              <div style="margin-top: 14px; border-top: 1px dashed var(--border-subtle); padding-top: 10px;">
                <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 6px;">
                  <span class="badge badge-cyan">ROADMAP</span>
                  <span style="font-size: 12.5px; color: var(--text-main); font-weight: 600;">Enterprise Controls</span>
                </div>
                <ul style="list-style: none; font-size: 11.5px; line-height: 1.5; color: var(--text-muted); margin-left: 4px;">
                  <li>• SSO identity & group membership routing</li>
                  <li>• Separation of duties with append-only audit trail</li>
                  <li>• Expiry, escalation, and delegation rules</li>
                </ul>
              </div>
            </div>
          </div>
        </div>

        <div style="font-size: 12px; color: var(--text-dim); border-top: 1px solid var(--border-subtle); padding-top: 14px;">
          <span>SLIDE 09 / 13 • GOVERNANCE & POLICY</span>
        </div>
      </section>

      <!-- SLIDE 10: DEVELOPER PRODUCTIVITY -->
      <section class="slide" id="slide-10" data-duration="24"
               data-narration="Developer productivity: from toil to review. Developer time shifts from mechanical remediation tasks to simply reviewing an evidence-backed, pre-tested result.">
        <div>
          <div class="slide-tagline" style="color: var(--emerald);">🚀 Engineering Velocity</div>
          <h2 class="slide-title">Developer Productivity: From Toil to Review</h2>
          <p class="slide-subtitle">Developer time shifts from doing remediation work to reviewing a verified result.</p>
        </div>

        <div class="slide-body">
          <div style="display: flex; flex-direction: column; gap: 7px;">
            <div style="display: grid; grid-template-columns: 200px 1fr 1fr; gap: 14px; padding: 4px 14px; font-size: 11px; font-weight: 700; color: var(--text-dim); text-transform: uppercase;">
              <div>TASK</div>
              <div>TODAY: MANUAL TOIL</div>
              <div style="color: var(--emerald);">WITH VULNFLOW AI</div>
            </div>

            <div class="card ppt-item" style="display: grid; grid-template-columns: 200px 1fr 1fr; gap: 14px; padding: 8px 14px; align-items: center;">
              <div><b>🔍 Triage alerts</b></div>
              <div style="color: var(--text-muted); font-size: 12px;">Sort raw alerts by hand across multiple scanners</div>
              <div style="color: var(--emerald); font-weight: 600; font-size: 12px;">Agent groups findings into root causes</div>
            </div>

            <div class="card ppt-item" style="display: grid; grid-template-columns: 200px 1fr 1fr; gap: 14px; padding: 8px 14px; align-items: center;">
              <div><b>🌳 Find the cause</b></div>
              <div style="color: var(--text-muted); font-size: 12px;">Trace deep dependency locks manually</div>
              <div style="color: var(--emerald); font-weight: 600; font-size: 12px;">Graph traversal names the direct parent</div>
            </div>

            <div class="card ppt-item" style="display: grid; grid-template-columns: 200px 1fr 1fr; gap: 14px; padding: 8px 14px; align-items: center;">
              <div><b>⚖️ Check policy</b></div>
              <div style="color: var(--text-muted); font-size: 12px;">Cross-reference wikis and spreadsheets</div>
              <div style="color: var(--emerald); font-weight: 600; font-size: 12px;">Policy engine checks the rules in code</div>
            </div>

            <div class="card ppt-item" style="display: grid; grid-template-columns: 200px 1fr 1fr; gap: 14px; padding: 8px 14px; align-items: center;">
              <div><b>🧪 Test the upgrade</b></div>
              <div style="color: var(--text-muted); font-size: 12px;">Upgrade, build, run unit tests, find breakage</div>
              <div style="color: var(--emerald); font-weight: 600; font-size: 12px;">Sandbox tests first; agent self-corrects</div>
            </div>

            <div class="card ppt-item" style="display: grid; grid-template-columns: 200px 1fr 1fr; gap: 14px; padding: 8px 14px; align-items: center;">
              <div><b>📝 Write the PR</b></div>
              <div style="color: var(--text-muted); font-size: 12px;">Draft the PR description, hunt for advisory links</div>
              <div style="color: var(--emerald); font-weight: 600; font-size: 12px;">PR opens with cited advisory evidence</div>
            </div>

            <div class="card ppt-item" style="display: grid; grid-template-columns: 200px 1fr 1fr; gap: 14px; padding: 8px 14px; align-items: center;">
              <div><b>✅ Prove it is fixed</b></div>
              <div style="color: var(--text-muted); font-size: 12px;">Merge on green CI and hope rescan passes later</div>
              <div style="color: var(--emerald); font-weight: 600; font-size: 12px;">Rescan diff mathematically verifies the result</div>
            </div>
          </div>
        </div>

        <div style="font-size: 12px; color: var(--text-dim); border-top: 1px solid var(--border-subtle); padding-top: 14px;">
          <span>SLIDE 10 / 13 • DEVELOPER PRODUCTIVITY</span>
        </div>
      </section>

      <!-- SLIDE 11: A REAL RUN, END TO END -->
      <section class="slide" id="slide-11" data-duration="24"
               data-narration="A real run, end to end: output of one VulnFlow run in PR mode on a test repository. Four hundred twenty-six findings analyzed became forty-three root causes, three fixes applied, and one pull request opened.">
        <div>
          <div class="slide-tagline">💻 Execution Case Study</div>
          <h2 class="slide-title">A Real Run, End to End</h2>
          <p class="slide-subtitle">Output of one VulnFlow run in PR mode on a test repository (Illustrative, not an average).</p>
        </div>

        <div class="slide-body">
          <!-- KPI Bar -->
          <div class="ppt-item" style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 16px;">
            <div class="card" style="text-align: center; padding: 12px;">
              <div style="font-size: 26px; font-weight: 800; color: var(--rose);">426</div>
              <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; font-weight: 700;">Findings Analyzed</div>
            </div>
            <div class="card" style="text-align: center; padding: 12px;">
              <div style="font-size: 26px; font-weight: 800; color: var(--cyan);">43</div>
              <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; font-weight: 700;">Root Causes</div>
            </div>
            <div class="card" style="text-align: center; padding: 12px;">
              <div style="font-size: 26px; font-weight: 800; color: var(--emerald);">3</div>
              <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; font-weight: 700;">Fixes Applied</div>
            </div>
            <div class="card" style="text-align: center; padding: 12px;">
              <div style="font-size: 26px; font-weight: 800; color: var(--purple);">1</div>
              <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; font-weight: 700;">Pull Request Opened</div>
            </div>
          </div>

          <!-- Code Diff & Execution Log -->
          <div class="terminal-window ppt-item" style="margin-bottom: 16px;">
            <div class="terminal-header">
              <div class="term-dot term-red"></div>
              <div class="term-dot term-yellow"></div>
              <div class="term-dot term-green"></div>
              <span style="font-size: 11px; color: var(--text-dim); margin-left: 8px;">git diff --stat • 2 of 3 applied fixes shown</span>
            </div>
            <div class="terminal-body" style="padding: 12px 18px; max-height: 100px;">
              <span class="term-accent">--- a/package.json</span><br>
              <span class="term-diff-sub">-   "lodash": "4.17.4"</span><br>
              <span class="term-diff-add">+   "lodash": "4.18.0"</span><br>
              <span class="term-accent">--- a/requirements.txt</span><br>
              <span class="term-diff-sub">-   requests==2.6.0</span><br>
              <span class="term-diff-add">+   requests==2.33.0</span>
            </div>
          </div>

          <!-- 3 Takeaway Cards -->
          <div class="grid-3 ppt-item" style="gap: 16px;">
            <div class="card card-accent-emerald">
              <div class="card-title" style="color: var(--emerald); font-size: 13.5px;">✅ Applied</div>
              <p class="card-desc" style="font-size: 12px;">Safe bumps were written to manifests and opened as one PR with sandbox test validation.</p>
            </div>
            <div class="card card-accent-amber">
              <div class="card-title" style="color: var(--amber); font-size: 13.5px;">🚦 Held for Approval</div>
              <p class="card-desc" style="font-size: 12px;">Major upgrades and unapproved packages waited safely for a human decision in Supabase.</p>
            </div>
            <div class="card card-accent-cyan">
              <div class="card-title" style="color: var(--cyan); font-size: 13.5px;">🔍 Next Gate</div>
              <p class="card-desc" style="font-size: 12px;">Rescan verification proves zero remaining CVEs before production merge.</p>
            </div>
          </div>
        </div>

        <div style="font-size: 12px; color: var(--text-dim); border-top: 1px solid var(--border-subtle); padding-top: 14px;">
          <span>SLIDE 11 / 13 • A REAL RUN, END TO END</span>
        </div>
      </section>

      <!-- SLIDE 12: ROADMAP & METRICS -->
      <section class="slide" id="slide-12" data-duration="22"
               data-narration="Roadmap and how we will prove the impact: we report measured results from a pilot. We do not publish unverified projections. Key pilot metrics include review time, first-attempt build pass rate, and rescan-verified closures.">
        <div>
          <div class="slide-tagline">🗺️ Measurable Pilot</div>
          <h2 class="slide-title">Roadmap and How We Will Prove the Impact</h2>
          <p class="slide-subtitle">We report measured results from a pilot. We do not publish projections.</p>
        </div>

        <div class="slide-body">
          <div class="grid-2" style="gap: 22px;">
            <!-- Roadmap -->
            <div class="card card-accent-cyan ppt-item">
              <div class="card-title" style="color: var(--cyan);">🗺️ Roadmap Milestones</div>
              <div style="margin-top: 10px;">
                <div style="margin-bottom: 12px;">
                  <b style="color: var(--emerald); font-size: 13px;">1. Next:</b>
                  <p class="card-desc" style="font-size: 12px; margin-top: 2px;">SSO-based multi-approver workflow with routing, audit trail and escalation.</p>
                </div>
                <div style="margin-bottom: 12px;">
                  <b style="color: var(--cyan); font-size: 13px;">2. Then:</b>
                  <p class="card-desc" style="font-size: 12px; margin-top: 2px;">Org-wide remediation campaigns and a multi-repo portfolio view.</p>
                </div>
                <div>
                  <b style="color: var(--purple); font-size: 13px;">3. Always:</b>
                  <p class="card-desc" style="font-size: 12px; margin-top: 2px;">Stable-release target versions, and rescan verification on every run.</p>
                </div>
              </div>
            </div>

            <!-- Pilot Metrics -->
            <div class="card card-accent-emerald ppt-item">
              <div class="card-title" style="color: var(--emerald);">📊 Pilot Metrics We Will Instrument</div>
              <ul style="list-style: none; font-size: 12.5px; line-height: 1.8; color: var(--text-muted); margin-top: 8px;">
                <li>• ⏱️ <b>Time from scan to PR</b></li>
                <li>• 👨‍💻 <b>Developer review time per PR</b></li>
                <li>• 🚢 <b>PRs merged without edits</b></li>
                <li>• 🧪 <b>First-attempt build pass rate</b></li>
                <li>• 🌳 <b>Findings per root cause</b></li>
                <li>• 🔍 <b>Rescan-verified closures</b></li>
              </ul>
            </div>
          </div>
        </div>

        <div style="font-size: 12px; color: var(--text-dim); border-top: 1px solid var(--border-subtle); padding-top: 14px;">
          <span>SLIDE 12 / 13 • ROADMAP & PILOT METRICS</span>
        </div>
      </section>

      <!-- SLIDE 13: CONCLUSION -->
      <section class="slide" id="slide-13" data-duration="20"
               data-narration="In conclusion: agents propose, code decides, scanners verify. VulnFlow AI eliminates manual triage toil and turns security alerts into verified pipeline advantages. Proposed next step: a pilot on two or three repositories.">
        <div>
          <div class="slide-tagline" style="color: var(--emerald);">🚀 Core Thesis & Conclusion</div>
          <h2 class="slide-title">Agents Propose. Code Decides. Scanners Verify.</h2>
          <p class="slide-subtitle">Transforming vulnerability management from manual toil into verified, autonomous velocity.</p>
        </div>

        <div class="slide-body">
          <div class="grid-3" style="margin-bottom: 24px;">
            <div class="card card-accent-cyan ppt-item">
              <div class="card-title" style="color: var(--cyan);">🏛️ Architecture</div>
              <p class="card-desc">Four tiers with hard boundaries: only agents use an LLM, and nothing the model proposes is applied without code and tests.</p>
            </div>

            <div class="card card-accent-purple ppt-item">
              <div class="card-title" style="color: var(--purple);">🤖 Agentic AI</div>
              <p class="card-desc">Specialized, bounded agents, a self-correcting fixer, and human gates where risk is high.</p>
            </div>

            <div class="card card-accent-emerald ppt-item">
              <div class="card-title" style="color: var(--emerald);">👥 Developers</div>
              <p class="card-desc">One evidence-backed PR per root cause instead of a long list of alerts to triage.</p>
            </div>
          </div>

          <!-- Next Step Callout -->
          <div class="ppt-item" style="background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.35); border-radius: 9px; padding: 18px 24px; display: flex; align-items: center; justify-content: space-between;">
            <div>
              <div style="font-weight: 800; font-size: 15px; color: var(--text-main);">Proposed Next Step:</div>
              <div style="font-size: 13px; color: var(--text-muted); margin-top: 4px;">A pilot on two or three repositories, measured as on slide 12. Run: <code>vulnflow scan --repo . --mode report</code> or <code>vulnflow serve</code></div>
            </div>
            <button class="btn btn-primary" onclick="goToSlide(0)">Restart Briefing ↺</button>
          </div>
        </div>

        <div style="font-size: 12px; color: var(--text-dim); border-top: 1px solid var(--border-subtle); padding-top: 14px;">
          <span>SLIDE 13 / 13 • CONCLUSION & NEXT STEPS</span>
        </div>
      </section>

    </div>
  </main>

  <!-- Video Narration & Autoplay Control Bar -->
  <div class="narration-bar">
    <div class="narrator-avatar">
      <div class="audio-waves" id="audioWaves" title="Live Audio Waveform">
        <div class="wave-bar"></div>
        <div class="wave-bar"></div>
        <div class="wave-bar"></div>
        <div class="wave-bar"></div>
        <div class="wave-bar"></div>
      </div>
      <div>
        <div style="font-size: 12px; font-weight: 700; color: var(--text-main);">AI Presenter</div>
        <div style="font-size: 10.5px; color: var(--emerald);" id="audioStatusText">Voice Active</div>
      </div>
    </div>

    <div class="narration-text" id="narrationDisplay">
      <span>Voiceover:</span> Welcome to the VulnFlow AI Enterprise Architecture Briefing.
    </div>

    <div style="display: flex; align-items: center; gap: 14px;">
      <div class="progress-bar-container" title="Slide Progress">
        <div class="progress-bar-fill" id="progressFill"></div>
      </div>
      <div style="font-size: 12px; font-family: var(--font-mono); color: var(--text-muted);" id="timeElapsed">00:00</div>
    </div>

    <!-- Navigation buttons -->
    <div style="display: flex; gap: 8px; align-items: center;">
      <span style="font-size: 12.5px; font-weight: 700; color: var(--text-muted); min-width: 120px; text-align: right;" id="slideCounter">01 / 13</span>
      <button id="btnPrev" class="btn">◀ Prev</button>
      <button id="btnNext" class="btn">Next ▶</button>
    </div>
  </div>

  <!-- Speaker Notes Drawer -->
  <div id="speakerNotesDrawer">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; border-bottom: 1px solid var(--border-subtle); padding-bottom: 8px;">
      <b style="color: var(--text-main); font-size: 13.5px;">🎙️ Presenter Talking Points</b>
      <button class="btn" style="padding: 2px 8px; font-size: 11px;" onclick="toggleNotes()">Close</button>
    </div>
    <div id="notesContent">Loading notes...</div>
  </div>

  <script>
    // ==========================================
    // SOUND ENGINE (Web Audio API Synthesizer)
    // ==========================================
    class SoundEngine {
      constructor() {
        this.ctx = null;
        this.muted = false;
      }

      init() {
        if (this.ctx) return;
        try {
          const AudioContext = window.AudioContext || window.webkitAudioContext;
          if (AudioContext) {
            this.ctx = new AudioContext();
            this.ctx.resume();
          }
        } catch (e) {
          console.warn("AudioContext init error:", e);
        }
      }

      playTransition() {
        if (this.muted) return;
        this.init();
        if (!this.ctx) return;
        try {
          const t = this.ctx.currentTime;
          const osc = this.ctx.createOscillator();
          const gain = this.ctx.createGain();
          osc.type = 'sine';
          osc.frequency.setValueAtTime(280, t);
          osc.frequency.exponentialRampToValueAtTime(780, t + 0.15);
          gain.gain.setValueAtTime(0.06, t);
          gain.gain.exponentialRampToValueAtTime(0.001, t + 0.2);
          osc.connect(gain);
          gain.connect(this.ctx.destination);
          osc.start(t);
          osc.stop(t + 0.2);
        } catch (err) {}
      }

      playContentEntry() {
        if (this.muted) return;
        this.init();
        if (!this.ctx) return;
        try {
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
        } catch (err) {}
      }

      playSuccess() {
        if (this.muted) return;
        this.init();
        if (!this.ctx) return;
        try {
          const notes = [523.25, 659.25, 783.99, 1046.50]; // C5, E5, G5, C6
          notes.forEach((freq, idx) => {
            const t = this.ctx.currentTime + (idx * 0.08);
            const osc = this.ctx.createOscillator();
            const gain = this.ctx.createGain();
            osc.type = 'triangle';
            osc.frequency.setValueAtTime(freq, t);
            gain.gain.setValueAtTime(0.08, t);
            gain.gain.exponentialRampToValueAtTime(0.001, t + 0.32);
            osc.connect(gain);
            gain.connect(this.ctx.destination);
            osc.start(t);
            osc.stop(t + 0.32);
          });
        } catch (err) {}
      }

      playChirp() {
        if (this.muted) return;
        this.init();
        if (!this.ctx) return;
        try {
          const t = this.ctx.currentTime;
          const osc = this.ctx.createOscillator();
          const gain = this.ctx.createGain();
          osc.type = 'sine';
          osc.frequency.setValueAtTime(1100, t);
          osc.frequency.exponentialRampToValueAtTime(1600, t + 0.06);
          gain.gain.setValueAtTime(0.04, t);
          gain.gain.exponentialRampToValueAtTime(0.001, t + 0.07);
          osc.connect(gain);
          gain.connect(this.ctx.destination);
          osc.start(t);
          osc.stop(t + 0.07);
        } catch (err) {}
      }
    }

    const sfx = new SoundEngine();

    // ==========================================
    // SPEECH SYNTHESIS ENGINE (Voiceover)
    // ==========================================
    let isMuted = false;
    let voices = [];
    window.activeUtterance = null;
    let voiceFallbackTimer = null;

    function populateVoices() {
      if (!('speechSynthesis' in window)) return;
      voices = window.speechSynthesis.getVoices();
    }

    function getSelectedVoice() {
      if (!voices.length && 'speechSynthesis' in window) {
        voices = window.speechSynthesis.getVoices();
      }
      return voices.find(v => v.lang.startsWith('en') && (v.name.includes('Natural') || v.name.includes('Premium') || v.name.includes('Samantha') || v.name.includes('Daniel') || v.name.includes('Google'))) ||
             voices.find(v => v.lang.startsWith('en')) ||
             voices[0];
    }

    if ('speechSynthesis' in window) {
      window.speechSynthesis.onvoiceschanged = populateVoices;
      populateVoices();
    }

    function speakNarration(text, onComplete) {
      if (isMuted || !('speechSynthesis' in window)) {
        if (onComplete) {
          const words = text.split(' ').length;
          const estSeconds = Math.max(3, (words / 2.5));
          voiceFallbackTimer = setTimeout(onComplete, estSeconds * 1000);
        }
        return;
      }

      try {
        window.speechSynthesis.cancel();
        if (voiceFallbackTimer) clearTimeout(voiceFallbackTimer);

        const utterance = new SpeechSynthesisUtterance(text);
        const voice = getSelectedVoice();
        if (voice) utterance.voice = voice;
        utterance.rate = 1.0;
        utterance.pitch = 1.0;

        const waves = document.getElementById('audioWaves');

        utterance.onstart = () => {
          if (waves) waves.classList.add('waves-active');
        };

        utterance.onend = () => {
          if (waves) waves.classList.remove('waves-active');
          if (onComplete) onComplete();
        };

        utterance.onerror = (e) => {
          if (waves) waves.classList.remove('waves-active');
          if (onComplete) onComplete();
        };

        window.activeUtterance = utterance;
        window.speechSynthesis.speak(utterance);
      } catch (err) {
        console.warn("Speech synthesis error:", err);
        if (onComplete) onComplete();
      }
    }

    // ==========================================
    // AMBIENT PARTICLES CANVAS
    // ==========================================
    const canvas = document.getElementById('ambientCanvas');
    const ctx = canvas.getContext('2d');
    let particles = [];

    function resizeCanvas() {
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;
      initParticles();
    }

    function initParticles() {
      particles = [];
      const count = Math.floor(window.innerWidth / 36);
      for (let i = 0; i < count; i++) {
        particles.push({
          x: Math.random() * canvas.width,
          y: Math.random() * canvas.height,
          radius: Math.random() * 1.6 + 0.6,
          vx: (Math.random() - 0.5) * 0.35,
          vy: (Math.random() - 0.5) * 0.35
        });
      }
    }

    function drawParticles() {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      const isLight = document.body.classList.contains('light-theme');
      const dotColor = isLight ? 'rgba(2, 132, 199, 0.35)' : 'rgba(6, 182, 212, 0.4)';
      const lineColor = isLight ? 'rgba(5, 150, 105, 0.12)' : 'rgba(16, 185, 129, 0.15)';

      for (let i = 0; i < particles.length; i++) {
        const p = particles[i];
        p.x += p.vx;
        p.y += p.vy;

        if (p.x < 0 || p.x > canvas.width) p.vx *= -1;
        if (p.y < 0 || p.y > canvas.height) p.vy *= -1;

        ctx.beginPath();
        ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
        ctx.fillStyle = dotColor;
        ctx.fill();

        for (let j = i + 1; j < particles.length; j++) {
          const p2 = particles[j];
          const d2 = Math.hypot(p.x - p2.x, p.y - p2.y);
          if (d2 < 110) {
            ctx.beginPath();
            ctx.moveTo(p.x, p.y);
            ctx.lineTo(p2.x, p2.y);
            ctx.strokeStyle = lineColor;
            ctx.lineWidth = 0.75 * (1 - d2 / 110);
            ctx.stroke();
          }
        }
      }
      requestAnimationFrame(drawParticles);
    }

    window.addEventListener('resize', resizeCanvas);
    resizeCanvas();
    drawParticles();

    // ==========================================
    // PRESENTATION & SLIDE NAVIGATION
    // ==========================================
    const speakerNotes = [
      `<b>Slide 1 Talking Points:</b><br>
      • Welcome the audience to the VulnFlow AI Architecture Briefing.<br>
      • Core thesis: LLM agents propose, deterministic code executes, scanners verify.<br>
      • Highlight that VulnFlow is an orchestration and remediation platform, not a scanner.`,

      `<b>Slide 2 Talking Points:</b><br>
      • Frame the exact problem statement: scanners detect, but remediation remains slow and manual.<br>
      • Who feels it: developers lose sprint hours, security lacks fix grouping, leaders face backlog growth.<br>
      • Walk through the 4 requirements of any scalable solution.`,

      `<b>Slide 3 Talking Points:</b><br>
      • Explain the alert explosion: duplicate CVEs fanning out from shared dependencies.<br>
      • Highlight the real data point: 426 findings collapsed into 43 root causes.<br>
      • Emphasize the toil of manual triage and how blind bot upgrades break CI pipelines.`,

      `<b>Slide 4 Talking Points:</b><br>
      • Walk through the market differentiation table.<br>
      • Contrast VulnFlow with passive scanners, blind bump bots, and scanner-vendor autofix.<br>
      • Highlight built-in sandbox testing, rescan verification, and retry loops.`,

      `<b>Slide 5 Talking Points:</b><br>
      • Detail the 4-tier architecture and its strict boundaries.<br>
      • Key architectural guarantee: Only Tier 2 uses LLMs; Tiers 1, 3, and 4 are 100% deterministic code.<br>
      • Point out FastMCP JSON-RPC tools and Supabase durable approval persistence.`,

      `<b>Slide 6 Talking Points:</b><br>
      • Explain the 10-node LangGraph state machine.<br>
      • Click on the interactive nodes to inspect each node's inputs and guarantees.<br>
      • Highlight the Exit Code 10 safeguard at Node 06 (Human Approval Gate).`,

      `<b>Slide 7 Talking Points:</b><br>
      • Detail the 6 specialized agent personas.<br>
      • Note that each agent has bounded autonomy and cannot override graph facts or corporate policies.<br>
      • Emphasize the separation between the fast triage model and the deep planning model.`,

      `<b>Slide 8 Talking Points:</b><br>
      • Walk through the self-correction scenario (Django 4.2 -> 5.2 test failure -> fallback to 5.0.12).<br>
      • The 3 core guarantees: No broken PRs, safe by construction, and evidence travels with the fix.`,

      `<b>Slide 9 Talking Points:</b><br>
      • Explain the 3-tier risk engine (AUTO, REVIEW, BLOCKED).<br>
      • Review the Supabase durable approval architecture and enterprise roadmap (SSO, quorum routing).`,

      `<b>Slide 10 Talking Points:</b><br>
      • Walk through the 6 before-and-after task comparisons.<br>
      • Show how developer time shifts from manual toil to reviewing a verified, pre-tested result.`,

      `<b>Slide 11 Talking Points:</b><br>
      • Case study of a real end-to-end run on a test repository.<br>
      • 426 findings analyzed -> 43 root causes -> 3 safe fixes applied -> 1 clean PR opened.<br>
      • Review the code diff and takeaways.`,

      `<b>Slide 12 Talking Points:</b><br>
      • Roadmap milestones: SSO multi-approver workflow, org campaigns, stable-release targets.<br>
      • The 6 pilot instrumentation metrics to prove impact without speculative projections.`,

      `<b>Slide 13 Talking Points:</b><br>
      • Conclude with the core mantra: Agents propose. Code decides. Scanners verify.<br>
      • Propose a pilot on 2-3 repositories.<br>
      • Call to action: <code>vulnflow scan --repo . --mode report</code> or <code>vulnflow serve</code>.`
    ];

    const slides = document.querySelectorAll('.slide');
    const totalSlides = slides.length;
    let currentSlide = 0;

    const slideCounter = document.getElementById('slideCounter');
    const progressFill = document.getElementById('progressFill');
    const timeElapsed = document.getElementById('timeElapsed');
    const narrationDisplay = document.getElementById('narrationDisplay');
    const speakerNotesDrawer = document.getElementById('speakerNotesDrawer');
    const notesContent = document.getElementById('notesContent');
    const btnSoundToggle = document.getElementById('btnSoundToggle');
    const soundIcon = document.getElementById('soundIcon');
    const soundText = document.getElementById('soundText');
    const btnTestAudio = document.getElementById('btnTestAudio');
    const btnThemeToggle = document.getElementById('btnThemeToggle');
    const themeIcon = document.getElementById('themeIcon');
    const themeText = document.getElementById('themeText');
    const btnBuildToggle = document.getElementById('btnBuildToggle');
    const buildIcon = document.getElementById('buildIcon');
    const buildText = document.getElementById('buildText');
    const slideViewport = document.getElementById('slideViewport');

    // PowerPoint Build & Slide Navigation Engine
    let isBuildsEnabled = true;
    let videoBuildTimers = [];

    function toggleBuilds() {
      isBuildsEnabled = !isBuildsEnabled;
      sfx.playChirp();
      if (isBuildsEnabled) {
        document.body.classList.remove('builds-disabled');
        if (buildIcon) buildIcon.textContent = '✨';
        if (buildText) buildText.textContent = 'Builds: ON';
        const activeSlide = slides[currentSlide];
        activeSlide.querySelectorAll('.ppt-item').forEach(item => item.classList.remove('revealed', 'just-revealed'));
      } else {
        document.body.classList.add('builds-disabled');
        if (buildIcon) buildIcon.textContent = '⚡';
        if (buildText) buildText.textContent = 'Builds: OFF';
        const activeSlide = slides[currentSlide];
        activeSlide.querySelectorAll('.ppt-item').forEach(item => item.classList.add('revealed'));
      }
      updateBuildCounter();
    }

    function updateBuildCounter() {
      const activeSlide = slides[currentSlide];
      const allItems = activeSlide.querySelectorAll('.ppt-item');
      const revealedItems = activeSlide.querySelectorAll('.ppt-item.revealed');
      const total = allItems.length;
      const current = revealedItems.length;

      if (total > 0 && isBuildsEnabled) {
        slideCounter.innerHTML = `${String(currentSlide + 1).padStart(2, '0')} / ${String(totalSlides).padStart(2, '0')} <span style="opacity: 0.65; font-size: 11px; margin-left: 6px; font-weight: 600;">[Step ${current}/${total}]</span>`;
      } else {
        slideCounter.textContent = `${String(currentSlide + 1).padStart(2, '0')} / ${String(totalSlides).padStart(2, '0')}`;
      }
    }

    function clearVideoBuildTimers() {
      videoBuildTimers.forEach(t => clearTimeout(t));
      videoBuildTimers = [];
    }

    function updateSlide(direction = 'forward') {
      clearVideoBuildTimers();

      slides.forEach((s, idx) => {
        s.classList.remove('active', 'exit-left', 'exit-right');
        if (idx === currentSlide) {
          s.classList.add('active');
        } else if (idx < currentSlide) {
          s.classList.add('exit-left');
        } else {
          s.classList.add('exit-right');
        }
      });

      const activeSlide = slides[currentSlide];
      const allItems = activeSlide.querySelectorAll('.ppt-item');

      if (isBuildsEnabled) {
        if (direction === 'forward') {
          allItems.forEach(item => item.classList.remove('revealed', 'just-revealed'));
        } else {
          allItems.forEach(item => item.classList.add('revealed'));
        }
      } else {
        allItems.forEach(item => item.classList.add('revealed'));
      }

      updateBuildCounter();

      const narration = activeSlide.getAttribute('data-narration') || '';
      narrationDisplay.innerHTML = `<span>Voiceover:</span> ${narration}`;
      notesContent.innerHTML = speakerNotes[currentSlide] || 'No notes for this slide.';

      currentSlideDuration = parseInt(activeSlide.getAttribute('data-duration') || '15', 10);
      slideSecondsLeft = currentSlideDuration;
      progressFill.style.width = '0%';

      sfx.playTransition();
      if (currentSlide === 10 || currentSlide === 12) {
        setTimeout(() => sfx.playSuccess(), 450);
      }
    }

    function advanceStepOrSlide() {
      if (isBuildsEnabled) {
        const activeSlide = slides[currentSlide];
        const unrevealedItems = activeSlide.querySelectorAll('.ppt-item:not(.revealed)');
        if (unrevealedItems.length > 0) {
          const nextItem = unrevealedItems[0];
          nextItem.classList.add('revealed', 'just-revealed');
          setTimeout(() => nextItem.classList.remove('just-revealed'), 650);
          sfx.playContentEntry();
          updateBuildCounter();
          return;
        }
      }
      nextSlide();
    }

    function retreatStepOrSlide() {
      if (isBuildsEnabled) {
        const activeSlide = slides[currentSlide];
        const revealedItems = activeSlide.querySelectorAll('.ppt-item.revealed');
        if (revealedItems.length > 0) {
          const lastItem = revealedItems[revealedItems.length - 1];
          lastItem.classList.remove('revealed', 'just-revealed');
          sfx.playChirp();
          updateBuildCounter();
          return;
        }
      }
      prevSlide();
    }

    function nextSlide() {
      if (currentSlide < totalSlides - 1) {
        currentSlide++;
        updateSlide('forward');
        if (isVideoMode) {
          playCurrentSlideInVideoMode();
        }
      } else if (isVideoMode) {
        stopVideoMode();
      }
    }

    function prevSlide() {
      if (currentSlide > 0) {
        currentSlide--;
        updateSlide('backward');
        if (isVideoMode) {
          playCurrentSlideInVideoMode();
        }
      }
    }

    function goToSlide(idx) {
      if (idx >= 0 && idx < totalSlides) {
        const direction = idx > currentSlide ? 'forward' : 'backward';
        currentSlide = idx;
        updateSlide(direction);
        if (isVideoMode) {
          playCurrentSlideInVideoMode();
        }
      }
    }

    // Video Autoplay State
    let isVideoMode = false;
    let isPaused = false;
    let videoTimer = null;
    let slideSecondsLeft = 0;
    let currentSlideDuration = 15;
    let totalSecondsElapsed = 0;

    // Interactive State Machine Nodes
    const nodeData = {
      ingest: {
        badge: "NODE 01 • INGEST",
        title: "Scanner Adapters & Secret Redaction",
        desc: "Ingests raw SARIF/JSON from Trivy, Grype, Gitleaks, Snyk. Redacts passwords, API tokens, and JWTs at the edge so plaintext never reaches LLMs.",
        type: "Deterministic code"
      },
      dedupe: {
        badge: "NODE 02 • DEDUPE",
        title: "Finding Fingerprinting & Normalization",
        desc: "Normalizes scanner-specific severity schemes into CVSS v3.1 standard and hashes package/file coordinates to collapse duplicate reports.",
        type: "Deterministic code"
      },
      rootcause: {
        badge: "NODE 03 • ROOT CAUSE",
        title: "Neo4j Graph Traversal",
        desc: "Traverses project dependency graph to map transitive findings to their direct root parent manifest. Collapses dozens of alerts into 1 fix.",
        type: "Agent: LLM reasoning"
      },
      policy: {
        badge: "NODE 04 • POLICY CHECK",
        title: "Deterministic Governance Engine",
        desc: "Evaluates SemVer ranges, approved package whitelists, and copyleft license restrictions (GPL/AGPL) in pure Python code.",
        type: "Deterministic code"
      },
      plan: {
        badge: "NODE 05 • PLAN",
        title: "Remediation Candidate Formulation",
        desc: "Formulates target version bump, cites vector database advisories, and generates unified RemediationPlan object.",
        type: "Agent: LLM reasoning"
      },
      approval: {
        badge: "NODE 06 • HUMAN APPROVAL GATE",
        title: "Human Authorization & Supabase Checkpoint",
        desc: "Pauses workflow on REVIEW-tier changes (major bumps, unknown packages). Emits Exit Code 10, saves checkpoint in Supabase, and awaits reviewer authorization.",
        type: "Human decision"
      },
      sandbox: {
        badge: "NODE 07 • SANDBOX LOOP",
        title: "Docker Sandbox Build & Test Loop",
        desc: "Spawns isolated ephemeral container to execute builds and unit tests. If tests fail, agent reads compiler logs, rolls back, and retries safer versions.",
        type: "Agent: LLM reasoning"
      },
      pr: {
        badge: "NODE 08 • PULL REQUEST",
        title: "Automated Pull Request Creation",
        desc: "Creates branch vulnflow/fix-* and opens GitHub/GitLab PR with full advisory citations, changelog references, and sandbox test proof.",
        type: "Deterministic code"
      },
      verify: {
        badge: "NODE 09 • VERIFY RESCAN",
        title: "Rescan Diff Verification",
        desc: "Triggers post-fix scanner run in container. Mathematically verifies that target CVE count is 0 and no new regressions were introduced.",
        type: "Deterministic code"
      },
      audit: {
        badge: "NODE 10 • AUDIT & CLOSE",
        title: "Immutable Audit Log & OTel Export",
        desc: "Emits SHA-256 hash-chained JSONL audit entry, records run metrics to Supabase, and emits OpenTelemetry traces for SOC 2 / ISO 27001.",
        type: "Deterministic code"
      }
    };

    function selectNode(key) {
      document.querySelectorAll('.node-box').forEach(b => b.classList.remove('active-node'));
      const activeBox = document.querySelector(`.node-box[data-node="${key}"]`);
      if (activeBox) activeBox.classList.add('active-node');

      const d = nodeData[key];
      if (!d) return;

      const detailBadge = document.getElementById('detailBadge');
      const detailTitle = document.getElementById('detailTitle');
      const detailText = document.getElementById('detailText');

      detailBadge.textContent = d.badge;
      if (d.type.includes('Human')) {
        detailBadge.className = 'badge badge-amber';
      } else if (d.type.includes('Agent')) {
        detailBadge.className = 'badge badge-cyan';
      } else {
        detailBadge.className = 'badge badge-emerald';
      }

      detailTitle.textContent = d.title;
      detailText.textContent = d.desc;
      sfx.playChirp();
    }

    // Theme Switcher
    function toggleTheme() {
      const isLight = document.body.classList.toggle('light-theme');
      sfx.playChirp();
      if (isLight) {
        themeIcon.textContent = '🌙';
        themeText.textContent = 'Dark Mode';
        localStorage.setItem('vulnflow_theme_briefing', 'light');
      } else {
        themeIcon.textContent = '☀️';
        themeText.textContent = 'Light Mode';
        localStorage.setItem('vulnflow_theme_briefing', 'dark');
      }
    }

    if (localStorage.getItem('vulnflow_theme_briefing') === 'light') {
      document.body.classList.add('light-theme');
      themeIcon.textContent = '🌙';
      themeText.textContent = 'Dark Mode';
    }

    // Presenter Notes
    function toggleNotes() {
      speakerNotesDrawer.classList.toggle('open');
      sfx.playChirp();
    }

    // Audio & Sound
    function toggleSound() {
      isMuted = !isMuted;
      sfx.muted = isMuted;
      sfx.playChirp();

      const audioStatusText = document.getElementById('audioStatusText');
      if (isMuted) {
        soundIcon.textContent = '🔇';
        soundText.textContent = 'Muted';
        audioStatusText.textContent = 'Muted';
        audioStatusText.style.color = 'var(--rose)';
        if ('speechSynthesis' in window) window.speechSynthesis.cancel();
        const waves = document.getElementById('audioWaves');
        if (waves) waves.classList.remove('waves-active');
      } else {
        soundIcon.textContent = '🔊';
        soundText.textContent = 'Voice On';
        audioStatusText.textContent = 'Voice Active';
        audioStatusText.style.color = 'var(--emerald)';
      }
    }

    function testAudio() {
      sfx.init();
      sfx.playSuccess();
      speakNarration("Audio test successful. VulnFlow voiceover and sound effects are fully operational.", null);
    }

    // Video Mode
    const btnVideoMode = document.getElementById('btnVideoMode');
    const videoBtnText = document.getElementById('videoBtnText');
    const videoPlayIcon = document.getElementById('videoPlayIcon');

    function toggleVideoMode() {
      if (isVideoMode && !isPaused) {
        pauseVideoMode();
      } else if (isVideoMode && isPaused) {
        resumeVideoMode();
      } else {
        startVideoMode();
      }
    }

    function startVideoMode() {
      sfx.init();
      isVideoMode = true;
      isPaused = false;
      btnVideoMode.classList.add('btn-video-active');
      videoBtnText.textContent = 'Pause Video Demo';
      videoPlayIcon.textContent = '⏸';

      playCurrentSlideInVideoMode();
    }

    function playCurrentSlideInVideoMode() {
      if (!isVideoMode || isPaused) return;

      clearVideoBuildTimers();
      const activeSlide = slides[currentSlide];
      const narration = activeSlide.getAttribute('data-narration') || '';
      currentSlideDuration = parseInt(activeSlide.getAttribute('data-duration') || '15', 10);
      slideSecondsLeft = currentSlideDuration;
      let hasCompletedNarration = false;

      // Schedule progressive PowerPoint build items during slide video run
      const unrevealed = activeSlide.querySelectorAll('.ppt-item:not(.revealed)');
      if (unrevealed.length > 0 && isBuildsEnabled) {
        const stepInterval = (currentSlideDuration * 0.82) / (unrevealed.length + 0.5);
        unrevealed.forEach((item, idx) => {
          const delay = Math.max(1000, Math.round((idx + 0.8) * stepInterval * 1000));
          const timer = setTimeout(() => {
            if (isVideoMode && !isPaused && slides[currentSlide] === activeSlide) {
              item.classList.add('revealed', 'just-revealed');
              setTimeout(() => item.classList.remove('just-revealed'), 650);
              sfx.playContentEntry();
              updateBuildCounter();
            }
          }, delay);
          videoBuildTimers.push(timer);
        });
      }

      // Start narration speech
      speakNarration(narration, () => {
        hasCompletedNarration = true;
        if (isVideoMode && !isPaused) {
          progressFill.style.width = '100%';
          setTimeout(() => {
            if (isVideoMode && !isPaused) nextSlide();
          }, 1200);
        }
      });

      // Timer ticker for progress bar
      if (videoTimer) clearInterval(videoTimer);
      videoTimer = setInterval(() => {
        if (!isPaused) {
          totalSecondsElapsed++;
          if (slideSecondsLeft > 0) slideSecondsLeft--;

          const mins = String(Math.floor(totalSecondsElapsed / 60)).padStart(2, '0');
          const secs = String(totalSecondsElapsed % 60).padStart(2, '0');
          timeElapsed.textContent = `${mins}:${secs}`;

          if (!hasCompletedNarration) {
            const pct = ((currentSlideDuration - slideSecondsLeft) / currentSlideDuration) * 100;
            progressFill.style.width = `${Math.min(94, pct)}%`;
          }
        }
      }, 1000);
    }

    function pauseVideoMode() {
      isPaused = true;
      videoBtnText.textContent = 'Resume Video Demo';
      videoPlayIcon.textContent = '▶';
      if ('speechSynthesis' in window) {
        window.speechSynthesis.pause();
      }
      const waves = document.getElementById('audioWaves');
      if (waves) waves.classList.remove('waves-active');
    }

    function resumeVideoMode() {
      isPaused = false;
      videoBtnText.textContent = 'Pause Video Demo';
      videoPlayIcon.textContent = '⏸';
      if ('speechSynthesis' in window) {
        window.speechSynthesis.resume();
      }
      const waves = document.getElementById('audioWaves');
      if (waves && window.speechSynthesis && window.speechSynthesis.speaking) {
        waves.classList.add('waves-active');
      }
    }

    function stopVideoMode() {
      isVideoMode = false;
      isPaused = false;
      btnVideoMode.classList.remove('btn-video-active');
      videoBtnText.textContent = 'Auto-Play Video Demo';
      videoPlayIcon.textContent = '▶';

      const waves = document.getElementById('audioWaves');
      if (waves) waves.classList.remove('waves-active');

      if (videoTimer) clearInterval(videoTimer);
      clearVideoBuildTimers();
      if ('speechSynthesis' in window) {
        window.speechSynthesis.cancel();
      }
    }

    // Click anywhere on slide viewport advances PowerPoint build or slide
    slideViewport.addEventListener('click', (e) => {
      if (e.target.closest('button') || e.target.closest('a') || e.target.closest('.node-box') || e.target.closest('select')) {
        return;
      }
      advanceStepOrSlide();
    });

    // Keyboard Shortcuts
    window.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowRight' || e.key === ' ' || e.key === 'PageDown' || e.key === 'Enter') {
        e.preventDefault();
        advanceStepOrSlide();
      } else if (e.key === 'ArrowLeft' || e.key === 'PageUp' || e.key === 'Backspace') {
        e.preventDefault();
        retreatStepOrSlide();
      } else if (e.key === 'b' || e.key === 'B') {
        toggleBuilds();
      } else if (e.key === 's' || e.key === 'S') {
        toggleNotes();
      } else if (e.key === 'm' || e.key === 'M') {
        toggleSound();
      } else if (e.key === 't' || e.key === 'T') {
        toggleTheme();
      } else if (e.key === 'f' || e.key === 'F') {
        if (!document.fullscreenElement) {
          document.documentElement.requestFullscreen().catch(() => {});
        } else {
          document.exitFullscreen().catch(() => {});
        }
      } else if (e.key === 'Home') {
        goToSlide(0);
      } else if (e.key === 'End') {
        goToSlide(totalSlides - 1);
      }
    });

    // Event Listeners
    document.getElementById('btnPrev').addEventListener('click', retreatStepOrSlide);
    document.getElementById('btnNext').addEventListener('click', advanceStepOrSlide);
    document.getElementById('btnVideoMode').addEventListener('click', toggleVideoMode);
    document.getElementById('btnSoundToggle').addEventListener('click', toggleSound);
    document.getElementById('btnTestAudio').addEventListener('click', testAudio);
    btnThemeToggle.addEventListener('click', toggleTheme);
    btnBuildToggle.addEventListener('click', toggleBuilds);
    document.getElementById('btnNotes').addEventListener('click', toggleNotes);
    document.getElementById('btnPrint').addEventListener('click', () => window.print());
    document.getElementById('btnFullscreen').addEventListener('click', () => {
      if (!document.fullscreenElement) {
        document.documentElement.requestFullscreen().catch(() => {});
      } else {
        document.exitFullscreen().catch(() => {});
      }
    });

    // Initialize
    updateSlide('forward');
    selectNode('approval');
    audioWaves.style.opacity = '0.35';
  </script>
</body>
</html>
"""

with open('demo_assets/vulnflow_architecture_briefing.html', 'w', encoding='utf-8') as f:
    f.write(html_template)

print("Generated demo_assets/vulnflow_architecture_briefing.html successfully.")
