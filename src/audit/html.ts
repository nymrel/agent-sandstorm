/**
 * @file html.ts
 * @description Standalone interactive HTML audit report generator
 * @author Nymrel / JalenBuilds LLC <contact@jalenbuilds.com>
 * @license MIT
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import type { AuditEvent, AuditIntegrityResult } from '../types.js';
import { formatEventSummary } from './timeline.js';

export function generateHtmlReport(
  events: AuditEvent[],
  integrity: AuditIntegrityResult,
  metadata: {
    workspace: string;
    totalSpendUsd?: number;
    totalTokens?: number;
    rollbackPerformed?: boolean;
  } = { workspace: '' }
): string {
  const eventsJson = JSON.stringify(events, null, 2);
  const criticalCount = events.filter(e => e.severity === 'critical').length;
  const errorCount = events.filter(e => e.severity === 'error').length;
  const warnCount = events.filter(e => e.severity === 'warn').length;
  const infoCount = events.filter(e => e.severity === 'info').length;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sandstorm Execution Audit Report - Nymrel</title>
  <style>
    :root {
      --bg-primary: #FAF8F2;
      --bg-card: #FFFFFF;
      --bg-warm: #F4F0E6;
      --text-main: #2A332E;
      --text-muted: #6B7280;
      --accent-cedar: #2A332E;
      --accent-terracotta: #A8541F;
      --accent-green: #15803D;
      --accent-red: #DC2626;
      --accent-amber: #D97706;
      --border-color: #E5E0D4;
      --font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg-primary);
      color: var(--text-main);
      font-family: var(--font-family);
      line-height: 1.5;
      padding: 2rem;
    }

    .container {
      max-width: 1200px;
      margin: 0 auto;
    }

    header {
      border-bottom: 2px solid var(--border-color);
      padding-bottom: 1.5rem;
      margin-bottom: 2rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1rem;
    }

    .logo-badge {
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }

    .logo-badge h1 {
      font-size: 1.75rem;
      font-weight: 700;
      color: var(--accent-cedar);
    }

    .subtitle {
      font-size: 0.9rem;
      color: var(--text-muted);
    }

    .status-badge {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.5rem 1rem;
      border-radius: 9999px;
      font-weight: 600;
      font-size: 0.875rem;
    }

    .status-badge.verified {
      background-color: #DCFCE7;
      color: var(--accent-green);
      border: 1px solid #BBF7D0;
    }

    .status-badge.unverified {
      background-color: #FEE2E2;
      color: var(--accent-red);
      border: 1px solid #FECACA;
    }

    .metrics-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }

    .card {
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 1.25rem;
      box-shadow: 0 1px 3px rgba(0,0,0,0.04);
    }

    .card-title {
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      margin-bottom: 0.5rem;
    }

    .card-value {
      font-size: 1.5rem;
      font-weight: 700;
      color: var(--accent-cedar);
    }

    .card-meta {
      font-size: 0.75rem;
      color: var(--text-muted);
      margin-top: 0.25rem;
    }

    .controls {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1rem;
      gap: 1rem;
      flex-wrap: wrap;
    }

    .search-input {
      padding: 0.5rem 1rem;
      border: 1px solid var(--border-color);
      border-radius: 6px;
      font-size: 0.9rem;
      width: 300px;
      max-width: 100%;
      background: var(--bg-card);
    }

    .table-container {
      background: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      overflow-x: auto;
      margin-bottom: 2rem;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 0.875rem;
    }

    th {
      background: var(--bg-warm);
      padding: 0.75rem 1rem;
      font-weight: 600;
      color: var(--accent-cedar);
      border-bottom: 1px solid var(--border-color);
    }

    td {
      padding: 0.75rem 1rem;
      border-bottom: 1px solid var(--border-color);
      vertical-align: top;
    }

    tr:last-child td { border-bottom: none; }
    tr:hover { background-color: #FAF9F5; }

    .tag {
      display: inline-block;
      padding: 0.15rem 0.5rem;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
      font-family: var(--font-mono);
    }

    .tag.critical { background: #FEE2E2; color: var(--accent-red); }
    .tag.error { background: #FFEDD5; color: var(--accent-terracotta); }
    .tag.warn { background: #FEF3C7; color: var(--accent-amber); }
    .tag.info { background: #E0E7FF; color: #3730A3; }

    .mono {
      font-family: var(--font-mono);
      font-size: 0.8rem;
    }

    .hash-badge {
      background: var(--bg-warm);
      padding: 0.2rem 0.4rem;
      border-radius: 4px;
      font-family: var(--font-mono);
      font-size: 0.75rem;
      color: var(--text-muted);
    }

    footer {
      text-align: center;
      font-size: 0.8rem;
      color: var(--text-muted);
      padding-top: 2rem;
      border-top: 1px solid var(--border-color);
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="logo-badge">
        <div>
          <h1>Sandstorm Security Audit</h1>
          <div class="subtitle">Nymrel Zero-Trust Agent Execution Runtime</div>
        </div>
      </div>
      <div>
        <div class="status-badge ${integrity.valid ? 'verified' : 'unverified'}">
          <span>${integrity.valid ? '✓ Cryptographically Verified' : '⚠ Tamper Detected'}</span>
        </div>
      </div>
    </header>

    <div class="metrics-grid">
      <div class="card">
        <div class="card-title">Total Audit Events</div>
        <div class="card-value">${events.length}</div>
        <div class="card-meta">SHA-256 Hash Chained</div>
      </div>
      <div class="card">
        <div class="card-title">Security Incidents</div>
        <div class="card-value" style="color: ${criticalCount > 0 ? 'var(--accent-red)' : 'var(--accent-green)'};">${criticalCount}</div>
        <div class="card-meta">${warnCount} warnings, ${errorCount} errors</div>
      </div>
      <div class="card">
        <div class="card-title">Total LLM Spend</div>
        <div class="card-value">$${(metadata.totalSpendUsd || 0).toFixed(4)}</div>
        <div class="card-meta">${metadata.totalTokens || 0} tokens tracked</div>
      </div>
      <div class="card">
        <div class="card-title">Workspace Integrity</div>
        <div class="card-value">${metadata.rollbackPerformed ? 'Reverted' : 'Preserved'}</div>
        <div class="card-meta">${metadata.workspace || 'Active'}</div>
      </div>
    </div>

    <div class="controls">
      <h2>Cryptographic Event Journal</h2>
      <input type="text" id="searchInput" class="search-input" placeholder="Search events, types, payloads..." onkeyup="filterEvents()">
    </div>

    <div class="table-container">
      <table id="eventsTable">
        <thead>
          <tr>
            <th>#</th>
            <th>Timestamp</th>
            <th>Severity</th>
            <th>Type</th>
            <th>Summary / Payload</th>
            <th>Event Hash</th>
          </tr>
        </thead>
        <tbody>
          ${events.map((ev) => `
            <tr>
              <td class="mono">${ev.index}</td>
              <td class="mono">${ev.isoTime.substring(11, 23)}</td>
              <td><span class="tag ${ev.severity}">${ev.severity}</span></td>
              <td class="mono"><strong>${ev.type}</strong></td>
              <td>
                <div>${formatEventSummary(ev)}</div>
                <details style="margin-top:0.25rem; font-size:0.75rem; color:var(--text-muted);">
                  <summary>raw payload</summary>
                  <pre class="mono" style="background:#F4F0E6; padding:0.5rem; border-radius:4px; margin-top:0.25rem; overflow-x:auto;">${JSON.stringify(ev.payload, null, 2)}</pre>
                </details>
              </td>
              <td><span class="hash-badge" title="${ev.hash}">${ev.hash.substring(0, 12)}...</span></td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>

    <footer>
      Built by Nymrel · Parent Organization: JalenBuilds LLC · Zero-Trust Machine Execution Engine
    </footer>
  </div>

  <script>
    function filterEvents() {
      const input = document.getElementById('searchInput');
      const filter = input.value.toLowerCase();
      const table = document.getElementById('eventsTable');
      const trs = table.getElementsByTagName('tr');

      for (let i = 1; i < trs.length; i++) {
        const text = trs[i].textContent || trs[i].innerText;
        if (text.toLowerCase().indexOf(filter) > -1) {
          trs[i].style.display = '';
        } else {
          trs[i].style.display = 'none';
        }
      }
    }
  </script>
</body>
</html>`;
}

export function exportHtmlReportToFile(
  filePath: string,
  events: AuditEvent[],
  integrity: AuditIntegrityResult,
  metadata?: {
    workspace: string;
    totalSpendUsd?: number;
    totalTokens?: number;
    rollbackPerformed?: boolean;
  }
): void {
  const html = generateHtmlReport(events, integrity, metadata);
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(filePath, html, 'utf-8');
}
