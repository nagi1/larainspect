package html

// embeddedCSS contains the self-contained dark-theme stylesheet for the
// standalone HTML report. Kept in a separate file to keep reporter.go
// focused on structure and rendering logic.
const embeddedCSS = `
  :root {
    --bg: #0a0a0f;
    --bg-raised: #0e0e16;
    --surface: #13131d;
    --border: #1c1c2c;
    --text: #c8c8d8;
    --text-bright: #f0f0f5;
    --text-dim: #6b6b80;
    --critical: #ff3333;
    --high: #ff2d55;
    --medium: #fbbf24;
    --low: #67e8f9;
    --informational: #6b6b80;
    --unknown: #a78bfa;
    --accent: #7c4dff;
    --green: #3ddc84;
    --radius: 10px;
    --sidebar-w: 260px;
  }

  * { margin: 0; padding: 0; box-sizing: border-box; }

  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.65;
    display: flex;
    min-height: 100vh;
  }

  .sidebar {
    position: fixed;
    top: 0; left: 0; bottom: 0;
    width: var(--sidebar-w);
    background: var(--bg-raised);
    border-right: 1px solid var(--border);
    padding: 28px 20px;
    display: flex;
    flex-direction: column;
    overflow-y: auto;
    z-index: 10;
  }
  .sidebar-logo {
    font-family: "SF Mono", "Consolas", "Liberation Mono", Menlo, monospace;
    font-size: 14px;
    font-weight: 700;
    letter-spacing: 3px;
    background: linear-gradient(135deg, #ff3333, #7c4dff);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    margin-bottom: 32px;
  }
  .toc { flex: 1; }
  .toc-title {
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 2px;
    color: var(--text-dim);
    margin-bottom: 10px;
    font-weight: 600;
  }
  .toc-link {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 7px 12px;
    margin-bottom: 2px;
    border-radius: 6px;
    color: var(--text-dim);
    text-decoration: none;
    font-size: 13px;
    transition: background .15s, color .15s;
  }
  .toc-link:hover {
    background: rgba(124,77,255,.08);
    color: var(--text);
  }
  .toc-count {
    font-family: "SF Mono", Consolas, monospace;
    font-size: 11px;
    background: rgba(124,77,255,.12);
    color: var(--accent);
    padding: 1px 7px;
    border-radius: 4px;
  }
  .sidebar-footer {
    font-size: 11px;
    color: var(--text-dim);
    margin-top: 20px;
    padding-top: 16px;
    border-top: 1px solid var(--border);
  }

  .main {
    margin-left: var(--sidebar-w);
    flex: 1;
    padding: 40px 48px 80px;
    max-width: 960px;
  }

  .header { margin-bottom: 48px; }
  .header h1 {
    font-size: 32px;
    font-weight: 800;
    color: var(--text-bright);
    letter-spacing: -.3px;
    margin-bottom: 6px;
  }
  .header-meta {
    font-size: 14px;
    color: var(--text-dim);
  }

  .section {
    margin-bottom: 56px;
    scroll-margin-top: 24px;
  }
  .section-title {
    font-size: 22px;
    font-weight: 700;
    color: var(--text-bright);
    margin-bottom: 20px;
    letter-spacing: -.2px;
  }

  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(110px, 1fr));
    gap: 12px;
    margin-bottom: 20px;
  }
  .stat-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 18px 16px;
    text-align: center;
  }
  .stat-num {
    font-size: 28px;
    font-weight: 800;
    line-height: 1;
    margin-bottom: 4px;
  }
  .stat-label {
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text-dim);
  }
  .stat-card.total         .stat-num { color: var(--accent); }
  .stat-card.critical      .stat-num { color: var(--critical); }
  .stat-card.high          .stat-num { color: var(--high); }
  .stat-card.medium        .stat-num { color: var(--medium); }
  .stat-card.low           .stat-num { color: var(--low); }
  .stat-card.informational .stat-num { color: var(--text-dim); }
  .stat-card.unknown       .stat-num { color: var(--unknown); }

  .severity-bar {
    display: flex;
    height: 8px;
    border-radius: 4px;
    overflow: hidden;
    margin-bottom: 20px;
    background: var(--surface);
  }
  .bar-seg { min-width: 4px; }
  .bar-seg.critical      { background: var(--critical); }
  .bar-seg.high          { background: var(--high); }
  .bar-seg.medium        { background: var(--medium); }
  .bar-seg.low           { background: var(--low); }
  .bar-seg.informational { background: var(--text-dim); }

  .class-breakdown {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }
  .class-label {
    font-size: 13px;
    color: var(--text-dim);
  }
  .class-tag {
    font-family: "SF Mono", Consolas, monospace;
    font-size: 12px;
    padding: 3px 12px;
    border-radius: 6px;
    background: rgba(124,77,255,.08);
    color: var(--text-dim);
    border: 1px solid var(--border);
  }

  .info-grid {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
  }
  .info-row {
    display: flex;
    padding: 12px 20px;
    border-bottom: 1px solid var(--border);
    font-size: 14px;
  }
  .info-row:last-child { border-bottom: none; }
  .info-label {
    min-width: 140px;
    color: var(--text-dim);
    font-weight: 500;
  }
  .info-value {
    color: var(--text-bright);
  }

  .cat-header {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 16px;
  }
  .cat-header .section-title { margin-bottom: 0; }
  .cat-count {
    font-size: 12px;
    padding: 3px 10px;
    border-radius: 6px;
    background: rgba(124,77,255,.1);
    color: var(--accent);
    font-weight: 600;
  }

  .empty-note {
    font-size: 14px;
    color: var(--text-dim);
    font-style: italic;
  }

  .finding {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    margin-bottom: 10px;
    overflow: hidden;
  }
  .finding[open] { border-color: var(--accent); }
  .unknown-card[open] { border-color: var(--unknown); }
  .finding-summary {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 14px 18px;
    cursor: pointer;
    list-style: none;
    font-size: 14px;
    transition: background .15s;
  }
  .finding-summary:hover { background: rgba(255,255,255,.02); }
  .finding-summary::-webkit-details-marker { display: none; }
  .finding-summary::marker { content: ""; }

  .finding-title {
    flex: 1;
    font-weight: 600;
    color: var(--text-bright);
  }
  .finding-id, .finding-confidence {
    font-family: "SF Mono", Consolas, monospace;
    font-size: 11px;
    color: var(--text-dim);
  }
  .chevron {
    color: var(--text-dim);
    transition: transform .2s;
    flex-shrink: 0;
  }
  .finding[open] .chevron { transform: rotate(180deg); }

  .finding-body {
    padding: 0 18px 18px;
    border-top: 1px solid var(--border);
    padding-top: 16px;
  }
  .finding-desc {
    font-size: 14px;
    color: var(--text);
    margin-bottom: 14px;
    line-height: 1.7;
  }

  .finding-evidence, .finding-affected {
    margin-bottom: 14px;
  }
  .evidence-label, .affected-label {
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    color: var(--accent);
    font-weight: 700;
    margin-bottom: 6px;
  }
  .evidence-item, .affected-item {
    font-size: 13px;
    color: var(--text);
    padding: 4px 0;
  }
  .evidence-key {
    color: var(--text-dim);
    font-weight: 600;
  }
  .evidence-item code, .affected-item code {
    font-family: "SF Mono", Consolas, monospace;
    font-size: 12px;
    background: var(--bg);
    padding: 2px 6px;
    border-radius: 4px;
    border: 1px solid var(--border);
  }

  .finding-fix {
    background: rgba(124,77,255,.06);
    border-left: 3px solid var(--accent);
    border-radius: 0 8px 8px 0;
    padding: 14px 16px;
    margin-bottom: 14px;
  }
  .fix-label {
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    color: var(--accent);
    font-weight: 700;
    margin-bottom: 6px;
  }
  .finding-fix p {
    font-size: 14px;
    color: var(--text);
    line-height: 1.6;
    white-space: pre-wrap;
  }

  .badge {
    display: inline-block;
    padding: 2px 10px;
    border-radius: 5px;
    font-size: 10px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: .5px;
    flex-shrink: 0;
    font-family: "SF Mono", Consolas, monospace;
  }
  .badge.critical      { background: rgba(255,51,51,.15); color: var(--critical); }
  .badge.high          { background: rgba(255,45,85,.15); color: var(--high); }
  .badge.medium        { background: rgba(251,191,36,.12); color: var(--medium); }
  .badge.low           { background: rgba(103,232,249,.1); color: var(--low); }
  .badge.informational { background: rgba(107,107,128,.12); color: var(--text-dim); }
  .badge.unknown       { background: rgba(167,139,250,.12); color: var(--unknown); }

  .report-footer {
    margin-top: 64px;
    padding-top: 20px;
    border-top: 1px solid var(--border);
    font-size: 13px;
    color: var(--text-dim);
  }
  .report-footer a {
    color: var(--accent);
    text-decoration: none;
  }

  @media (max-width: 800px) {
    .sidebar { display: none; }
    .main { margin-left: 0; padding: 24px 20px 60px; }
    .stats-grid { grid-template-columns: repeat(3, 1fr); }
    .finding-summary { flex-wrap: wrap; gap: 8px; }
  }

  @media print {
    .sidebar { display: none; }
    .main { margin-left: 0; }
    .finding { break-inside: avoid; }
    body { background: #fff; color: #1a1a1a; }
    .stat-card, .info-grid, .finding { border-color: #ddd; background: #f9f9f9; }
  }
`
