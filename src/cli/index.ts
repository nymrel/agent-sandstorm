/**
 * @file index.ts
 * @description CLI implementation for agent-sandstorm
 * @author Nymrel / JalenBuilds LLC <contact@nymrel.com>
 * @license MIT
 */

import * as path from 'node:path';
import * as fs from 'node:fs';
import { Sandstorm } from '../sandbox.js';
import { CoWSnapshotManager } from '../cow/index.js';
import { AuditLogger, exportTimelineAscii, exportHtmlReportToFile } from '../audit/index.js';
import { ZeroTrustProxy } from '../proxy/index.js';

export async function runCli(args: string[]): Promise<number> {
  const command = args[0];

  if (!command || command === '--help' || command === '-h' || command === 'help') {
    printHelp();
    return 0;
  }

  if (command === '--version' || command === '-v' || command === 'version') {
    console.log('@nymrel/agent-sandstorm v1.0.0');
    return 0;
  }

  const workspace = getArgValue(args, '--workspace') || process.cwd();

  switch (command) {
    case 'run': {
      const commandArgs = extractCommandArgs(args.slice(1));
      if (commandArgs.length === 0) {
        console.error('Error: sandstorm run requires a command to execute. Example: sandstorm run "npm test"');
        return 1;
      }

      const cmdToRun = commandArgs.join(' ');
      const allowDomains = getArgValues(args, '--allow');
      const maxSpend = parseFloat(getArgValue(args, '--max-spend') || '0') || undefined;
      const maxTokens = parseInt(getArgValue(args, '--max-tokens') || '0', 10) || undefined;
      const maxSteps = parseInt(getArgValue(args, '--max-steps') || '0', 10) || undefined;
      const noRollback = args.includes('--no-rollback');
      const jsonOutput = args.includes('--json');
      const htmlReport = getArgValue(args, '--report');

      if (!jsonOutput) {
        console.log(`\n🛡️  SANDSTORM: Initializing Zero-Trust Sandbox in ${workspace}`);
        console.log(`▶ Executing: "${cmdToRun}"\n`);
      }

      const sandbox = new Sandstorm({
        workspace,
        allowDomains: allowDomains.length > 0 ? allowDomains : undefined,
        maxSpendUsd: maxSpend,
        maxTokens,
        maxSteps,
        autoRollbackOnError: !noRollback,
      });

      const result = await sandbox.run(async (ctx) => {
        return await ctx.exec(cmdToRun);
      });

      if (htmlReport) {
        sandbox.exportHtmlReport(path.resolve(htmlReport));
        if (!jsonOutput) {
          console.log(`\n📊 HTML Audit Report exported to: ${htmlReport}`);
        }
      }

      if (jsonOutput) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        if (result.success) {
          console.log(`\n✅ Execution succeeded in ${result.durationMs}ms`);
        } else {
          console.error(`\n❌ Execution failed: ${result.error?.message}`);
          if (result.rollbackPerformed) {
            console.log(`🔄 Automatic CoW Rollback performed: workspace restored to pristine baseline.`);
            console.log(`   Restored: ${result.rollbackSummary?.restoredFiles.length || 0}, Reverted: ${result.rollbackSummary?.revertedFiles.length || 0}, Deleted: ${result.rollbackSummary?.deletedFiles.length || 0}`);
          }
        }
        console.log(`\n` + sandbox.getTimeline());
      }

      return result.success ? 0 : 1;
    }

    case 'snapshot': {
      const name = args[1]?.startsWith('--') ? undefined : args[1];
      const cow = new CoWSnapshotManager(workspace);
      const snap = cow.createSnapshot(name);
      console.log(`\n📸 Snapshot created successfully:`);
      console.log(`   ID:         ${snap.id}`);
      console.log(`   Name:       ${snap.name}`);
      console.log(`   Files:      ${snap.fileCount} (${(snap.totalSizeBytes / 1024).toFixed(2)} KB)`);
      console.log(`   Merkle:     ${snap.treeHash}\n`);
      return 0;
    }

    case 'rollback': {
      const snapshotId = args[1]?.startsWith('--') ? undefined : args[1];
      const cow = new CoWSnapshotManager(workspace);
      const res = cow.rollback(snapshotId);

      if (!res.success) {
        console.error(`\n❌ Rollback failed: ${res.error}\n`);
        return 1;
      }

      console.log(`\n🔄 Rollback executed in ${res.durationMs}ms:`);
      console.log(`   Snapshot ID:    ${res.snapshotId}`);
      console.log(`   Restored Files: ${res.restoredFiles.length}`);
      console.log(`   Reverted Files: ${res.revertedFiles.length}`);
      console.log(`   Deleted Files:  ${res.deletedFiles.length}\n`);
      return 0;
    }

    case 'diff': {
      const cow = new CoWSnapshotManager(workspace);
      const diff = cow.diff();
      console.log(`\n📊 Workspace Diff (vs ${diff.baseSnapshotId}):`);
      console.log(`   Added (${diff.added.length}):    ${diff.added.join(', ') || 'none'}`);
      console.log(`   Modified (${diff.modified.length}): ${diff.modified.join(', ') || 'none'}`);
      console.log(`   Deleted (${diff.deleted.length}):  ${diff.deleted.join(', ') || 'none'}`);
      console.log(`   Unchanged:       ${diff.unchangedCount} files\n`);
      return 0;
    }

    case 'commit': {
      const name = args[1]?.startsWith('--') ? undefined : args[1];
      const cow = new CoWSnapshotManager(workspace);
      const res = cow.commit(name);
      console.log(`\n💾 Changes committed into baseline snapshot:`);
      console.log(`   Snapshot ID: ${res.snapshotId}`);
      console.log(`   Merkle Hash: ${res.treeHash}\n`);
      return 0;
    }

    case 'audit': {
      const logPath = path.join(workspace, '.sandstorm', 'audit.jsonl');
      if (!fs.existsSync(logPath)) {
        console.log(`No audit log found at ${logPath}`);
        return 0;
      }

      const rawLines = fs.readFileSync(logPath, 'utf-8').trim().split('\n').filter(Boolean);
      const events = rawLines.map(l => JSON.parse(l));

      const logger = new AuditLogger();
      // rebuild events
      (logger as any).events = events;
      (logger as any).latestHash = events[events.length - 1]?.hash || '';

      const integrity = logger.verifyIntegrity();
      const htmlPath = getArgValue(args, '--html');

      if (htmlPath) {
        exportHtmlReportToFile(path.resolve(htmlPath), events, integrity, { workspace });
        console.log(`\n📊 HTML Audit Report generated: ${htmlPath}`);
      }

      console.log(`\n` + exportTimelineAscii(events));
      console.log(`\n🔐 Cryptographic Integrity: ${integrity.valid ? '✅ VERIFIED (SHA-256 Chain Intact)' : '❌ TAMPER DETECTED at index ' + integrity.corruptedIndex}`);
      return integrity.valid ? 0 : 1;
    }

    case 'proxy': {
      const port = parseInt(getArgValue(args, '--port') || '9090', 10);
      const allowDomains = getArgValues(args, '--allow');
      const proxy = new ZeroTrustProxy({
        port,
        allowedDomains: allowDomains.length > 0 ? allowDomains : ['api.openai.com', 'api.anthropic.com', 'registry.npmjs.org'],
        scanPayloads: true,
      });

      const info = await proxy.start(port);
      console.log(`\n🛡️  Sandstorm Zero-Trust Outbound Proxy running on http://${info.host}:${info.port}`);
      console.log(`   Allowed Domains: ${allowDomains.join(', ') || 'default'}`);
      console.log(`   Secret Exfiltration Scanning: ACTIVE`);
      console.log(`   Press Ctrl+C to stop.\n`);

      process.on('SIGINT', async () => {
        await proxy.stop();
        process.exit(0);
      });
      return 0;
    }

    default:
      console.error(`Unknown command: ${command}`);
      printHelp();
      return 1;
  }
}

function printHelp(): void {
  console.log(`
🛡️  SANDSTORM - Zero-Trust Agent Sandbox & CoW Workspace Isolation Engine
   Nymrel / JalenBuilds LLC (v1.0.0)

USAGE:
  sandstorm run <command...> [options]
  sandstorm snapshot [name]
  sandstorm rollback [snapshot-id]
  sandstorm diff
  sandstorm commit [name]
  sandstorm audit [--html <path>] [--verify]
  sandstorm proxy [--port <port>] [--allow <domain...>]

COMMANDS:
  run          Execute a command inside the Zero-Trust Sandbox with automatic rollback on error
  snapshot     Create an instant immutable Copy-on-Write snapshot of the workspace
  rollback     Revert workspace instantly to the snapshot baseline (1-click restoration)
  diff         Inspect uncommitted file modifications, additions, and deletions
  commit       Approve current modifications and create a new baseline snapshot
  audit        View the cryptographic SHA-256 audit timeline and export HTML reports
  proxy        Start a standalone Zero-Trust outbound network proxy with secret detection

OPTIONS:
  --workspace <path>    Target workspace directory (default: current directory)
  --allow <domain>      Allowlist outbound destination domain (repeatable, supports wildcards)
  --max-spend <usd>     Spend budget cap in USD (e.g. 5.00)
  --max-tokens <num>    Token rate limit ceiling
  --max-steps <num>     Maximum tool execution steps before brake
  --no-rollback         Disable automatic CoW rollback on execution error
  --report <path>       Generate and save interactive HTML audit dashboard
  --json                Output results in JSON format
  --help, -h            Show this help message
`);
}

function getArgValue(args: string[], flag: string): string | undefined {
  const idx = args.indexOf(flag);
  if (idx !== -1 && idx < args.length - 1) {
    return args[idx + 1];
  }
  return undefined;
}

function getArgValues(args: string[], flag: string): string[] {
  const results: string[] = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === flag && i < args.length - 1) {
      results.push(args[i + 1]!);
    }
  }
  return results;
}

function extractCommandArgs(args: string[]): string[] {
  const flagsWithValue = new Set(['--workspace', '--allow', '--max-spend', '--max-tokens', '--max-steps', '--report', '--port', '--html']);
  const booleanFlags = new Set(['--no-rollback', '--json', '--verify', '--help', '-h', '--version', '-v']);
  const result: string[] = [];

  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (booleanFlags.has(arg)) {
      continue;
    }
    if (flagsWithValue.has(arg)) {
      i++; // skip value
      continue;
    }
    result.push(arg);
  }

  return result;
}
