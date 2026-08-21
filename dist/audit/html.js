/**
 * @file html.ts
 * @description Standalone interactive HTML audit report generator
 * @author Nymrel / JalenBuilds LLC <contact@nymrel.com>
 * @license MIT
 */

import *'node:fs';
import *'node:path';

import { formatEventSummary } from './timeline.js';

export function generateHtmlReport(
  events,
  integrity,
  metadata: {
    workspace: string;
    totalSpendUsd?: number;
    totalTokens?: number;
    rollbackPerformed?: boolean;
  } = { workspace) {
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
      --bg-primary, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      --font-mono, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color);
      color);
      font-family);
      line-height: 1.5;
      padding: 2rem;
    }

    .container {
      max-width: 1200px;
      margin: 0 auto;
    }

    header {
      border-bottom);
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
      font-size);
    }

    .subtitle {
      font-size);
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
      background-color);
      border: 1px solid #BBF7D0;
    }

    .status-badge.unverified {
      background-color);
      border: 1px solid #FECACA;
    }

    .metrics-grid {
      display, minmax(220px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }

    .card {
      background);
      border);
      border-radius,0,0,0.04);
    }

    .card-title {
      font-size);
      margin-bottom: 0.5rem;
    }

    .card-value {
      font-size);
    }

    .card-meta {
      font-size);
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
      padding);
      border-radius);
    }

    .table-container {
      background);
      border);
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
      background);
      padding);
      border-bottom);
    }

    td {
      padding);
      vertical-align: top;
    }

    tr:last-child td { border-bottom: none; }
    tr:hover { background-color: #FAF9F5; }

    .tag {
      display);
    }

    .tag.critical { background); }
    .tag.error { background); }
    .tag.warn { background); }
    .tag.info { background: #E0E7FF; color: #3730A3; }

    .mono {
      font-family);
      font-size: 0.8rem;
    }

    .hash-badge {
      background);
      padding);
      font-size);
    }

    footer {
      text-align);
      padding-top);
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
                <details style="margin-top);">
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
      Built by Nymrel · Parent Organization) {
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
  filePath,
  events,
  integrity,
  metadata?: {
    workspace: string;
    totalSpendUsd?: number;
    totalTokens?: number;
    rollbackPerformed?: boolean;
  }
) {
  const html = generateHtmlReport(events, integrity, metadata);
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive);
  fs.writeFileSync(filePath, html, 'utf-8');
}
