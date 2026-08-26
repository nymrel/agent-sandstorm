/**
 * @file sandbox.ts
 * @description Experimental agent execution guardrail orchestrator
 * @author Nymrel / JalenBuilds LLC <contact@nymrel.com>
 * @license MIT
 */

import * as path from 'node:path';
import { spawn } from 'node:child_process';
import type {
  SandstormOptions,
  SandboxContext,
  SandboxResult,
  ExecOptions,
  ExecResult,
  SnapshotMetadata,
  RollbackResult,
  CommitResult,
  WorkspaceDiff,
  CommandInput,
} from './types.js';
import { CoWSnapshotManager } from './cow/index.js';
import { ZeroTrustProxy } from './proxy/index.js';
import { ExecutionLimiter } from './limiter/index.js';
import { AuditLogger, exportTimelineAscii, exportHtmlReportToFile } from './audit/index.js';

function definedProcessEnv(): Record<string, string> {
  const environment: Record<string, string> = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (value !== undefined) environment[key] = value;
  }
  return environment;
}

/** Parse a portable command string for the default shell-free execution path. */
function parseCommandLine(command: string): [string, string[]] {
  const args: string[] = [];
  let current = '';
  let quote: '"' | "'" | null = null;
  let tokenStarted = false;

  for (let index = 0; index < command.length; index += 1) {
    const char = command[index]!;
    const next = command[index + 1];

    if (char === '\\' && next !== undefined && (next === '\\' || next === '"' || next === "'" || /\s/.test(next))) {
      current += next;
      tokenStarted = true;
      index += 1;
      continue;
    }

    if (quote) {
      if (char === quote) quote = null;
      else current += char;
      tokenStarted = true;
      continue;
    }

    if (char === '"' || char === "'") {
      quote = char;
      tokenStarted = true;
    } else if (/\s/.test(char)) {
      if (tokenStarted) {
        args.push(current);
        current = '';
        tokenStarted = false;
      }
    } else {
      current += char;
      tokenStarted = true;
    }
  }

  if (quote) throw new Error('Command contains an unterminated quote');
  if (tokenStarted) args.push(current);
  if (args.length === 0) throw new Error('Command must not be empty');

  return [args[0]!, args.slice(1)];
}

function formatCommand(command: CommandInput): string {
  if (typeof command === 'string') return command;
  if (command.length === 0) throw new Error('Command must not be empty');

  return command.map((argument) => {
    if (typeof argument !== 'string') throw new TypeError('Command arguments must be strings');
    return /^[a-zA-Z0-9_./:@%+=,-]+$/.test(argument) ? argument : JSON.stringify(argument);
  }).join(' ');
}

export class CommandExecutionError extends Error {
  public readonly command: string;
  public readonly execution: ExecResult;

  constructor(command: string, execution: ExecResult) {
    super(`Command exited with code ${execution.exitCode}: ${command}`);
    this.name = 'CommandExecutionError';
    this.command = command;
    this.execution = execution;
  }
}

export class Sandstorm {
  public readonly workspace: string;
  public readonly cow: CoWSnapshotManager;
  public readonly proxy: ZeroTrustProxy;
  public readonly limiter: ExecutionLimiter;
  public readonly audit: AuditLogger;
  public readonly options: Required<SandstormOptions>;

  constructor(options: SandstormOptions) {
    this.workspace = path.resolve(options.workspace);
    const sandstormDir = path.join(this.workspace, '.sandstorm');

    this.options = {
      workspace: this.workspace,
      allowDomains: options.allowDomains ?? [],
      blockDomains: options.blockDomains || [],
      maxSpendUsd: options.maxSpendUsd ?? Infinity,
      maxTokens: options.maxTokens ?? Infinity,
      maxSteps: options.maxSteps ?? 100,
      maxDurationMs: options.maxDurationMs ?? Infinity,
      autoRollbackOnError: options.autoRollbackOnError ?? true,
      detectRunawayLoops: options.detectRunawayLoops ?? true,
      loopThreshold: options.loopThreshold ?? 3,
      scanSecrets: options.scanSecrets ?? true,
      customSecretPatterns: options.customSecretPatterns || [],
      auditLogPath: options.auditLogPath || path.join(sandstormDir, 'audit.jsonl'),
      silent: options.silent ?? false,
    };

    this.cow = new CoWSnapshotManager(this.workspace);

    this.audit = new AuditLogger({
      logFilePath: this.options.auditLogPath,
      initialPayload: {
        workspace: this.workspace,
        allowDomains: this.options.allowDomains,
        autoRollback: this.options.autoRollbackOnError,
      },
    });

    this.proxy = new ZeroTrustProxy({
      allowedDomains: this.options.allowDomains,
      blockedDomains: this.options.blockDomains,
      scanPayloads: this.options.scanSecrets,
      customSecretPatterns: this.options.customSecretPatterns,
      onSecretDetected: (detection) => {
        this.audit.recordEvent('SECRET_BLOCKED', 'critical', {
          pattern: this.proxy.redactForAudit(detection.patternName),
          severity: detection.severity,
          location: detection.location,
          redacted: detection.redactedText,
        });
      },
      onBlockedDomain: (domain, url) => {
        this.audit.recordEvent('DOMAIN_BLOCKED', 'warn', {
          domain: this.proxy.redactForAudit(domain),
          url: this.proxy.redactForAudit(url),
        });
      },
    });

    this.limiter = new ExecutionLimiter({
      maxSpendUsd: this.options.maxSpendUsd,
      maxTotalTokens: this.options.maxTokens,
      maxSteps: this.options.maxSteps,
      maxDurationMs: this.options.maxDurationMs,
      loopDetection: this.options.detectRunawayLoops,
      loopThreshold: this.options.loopThreshold,
    });
  }

  /**
   * Run a callback with the configured cooperative guardrails
   */
  public async run<T = unknown>(
    fn: (ctx: SandboxContext) => Promise<T>
  ): Promise<SandboxResult<T>> {
    const startTime = Date.now();
    this.limiter.reset();

    // 1. Create Pristine Baseline CoW Snapshot
    const baseSnapshot = this.cow.createSnapshot('pre-execution-baseline');
    this.audit.recordEvent('SNAPSHOT_CREATED', 'info', {
      snapshotId: baseSnapshot.id,
      name: baseSnapshot.name,
      fileCount: baseSnapshot.fileCount,
      treeHash: baseSnapshot.treeHash,
    });

    // 2. Start the cooperative outbound proxy
    await this.proxy.start();
    const proxyEnv = this.proxy.getEnv();

    let resultValue: T | undefined;
    let executionError: Error | undefined;
    let rollbackPerformed = false;
    let rollbackSummary: RollbackResult | undefined;

    const ctx: SandboxContext = {
      workspace: this.workspace,
      env: { ...definedProcessEnv(), ...proxyEnv },
      exec: async (command: CommandInput, options: ExecOptions = {}) => {
        const displayCommand = formatCommand(command);
        const actionName = typeof command === 'string' ? command.trim().split(/\s+/, 1)[0] : command[0];
        if (!actionName) throw new Error('Command must not be empty');
        this.limiter.recordStep(actionName, displayCommand);
        const redactedCommand = this.proxy.redactForAudit(displayCommand);
        this.audit.recordEvent('EXEC_STARTED', 'info', { command: redactedCommand });

        const execRes = await this.execCommandInternal(command, {
          ...options,
          cwd: options.cwd ?? this.workspace,
          // A caller may add variables, but must not silently replace the
          // proxy variables that define the guarded child-process boundary.
          env: { ...options.env, ...proxyEnv },
        });

        this.audit.recordEvent('EXEC_FINISHED', execRes.exitCode === 0 ? 'info' : 'warn', {
          command: redactedCommand,
          exitCode: execRes.exitCode,
          durationMs: execRes.durationMs,
        });

        if (execRes.exitCode !== 0 && !options.allowNonZeroExit) {
          throw new CommandExecutionError(redactedCommand, {
            ...execRes,
            stdout: this.proxy.redactForAudit(execRes.stdout),
            stderr: this.proxy.redactForAudit(execRes.stderr),
          });
        }

        return execRes;
      },
      recordTokenUsage: (model: string, promptTokens: number, completionTokens: number) => {
        const usage = this.limiter.recordTokens(model, promptTokens, completionTokens);
        this.audit.recordEvent('BUDGET_ACCUMULATED', 'info', {
          model: this.proxy.redactForAudit(model),
          promptTokens,
          completionTokens,
          spendUsd: usage.currentSpendUsd,
          totalTokens: usage.totalTokens,
        });
        return usage;
      },
      recordStep: (actionName: string, detail?: string) => {
        this.limiter.recordStep(actionName, detail);
        this.audit.recordEvent('STEP_EXECUTED', 'info', {
          actionName: this.proxy.redactForAudit(actionName),
          detail: detail === undefined ? undefined : this.proxy.redactForAudit(detail),
        });
      },
      snapshot: (name?: string) => {
        const snap = this.cow.createSnapshot(name);
        this.audit.recordEvent('SNAPSHOT_CREATED', 'info', {
          snapshotId: snap.id,
          name: snap.name,
          treeHash: snap.treeHash,
        });
        return snap;
      },
      rollback: (snapshotId?: string) => {
        const rb = this.cow.rollback(snapshotId);
        this.audit.recordEvent('ROLLBACK_TRIGGERED', 'warn', {
          snapshotId: rb.snapshotId,
          restored: rb.restoredFiles.length,
          deleted: rb.deletedFiles.length,
          reverted: rb.revertedFiles.length,
        });
        return rb;
      },
      diff: () => this.cow.diff(),
    };

    try {
      resultValue = await fn(ctx);
    } catch (err: unknown) {
      executionError = err instanceof Error ? err : new Error(String(err));
      this.audit.recordEvent('CIRCUIT_BREAKER_TRIPPED', 'critical', {
        error: this.proxy.redactForAudit(executionError.message),
        stack: executionError.stack === undefined ? undefined : this.proxy.redactForAudit(executionError.stack),
      });

      if (this.options.autoRollbackOnError) {
        rollbackSummary = this.cow.rollback(baseSnapshot.id);
        rollbackPerformed = true;
        this.audit.recordEvent('ROLLBACK_TRIGGERED', 'warn', {
          snapshotId: baseSnapshot.id,
          success: rollbackSummary.success,
          restored: rollbackSummary.restoredFiles.length,
          deleted: rollbackSummary.deletedFiles.length,
          reverted: rollbackSummary.revertedFiles.length,
          durationMs: rollbackSummary.durationMs,
          error: rollbackSummary.error,
        });
      }
    } finally {
      await this.proxy.stop();
    }

    const spendSummary = this.limiter.getSummary();
    const auditVerified = this.audit.verifyIntegrity();
    const durationMs = Date.now() - startTime;
    const finalTreeHash = this.cow.createSnapshot('final-state').treeHash;

    return {
      success: !executionError,
      result: resultValue,
      error: executionError,
      rollbackPerformed,
      rollbackSummary,
      baseSnapshot,
      finalTreeHash,
      auditSummary: {
        eventCount: this.audit.getEvents().length,
        verified: auditVerified.valid,
        latestHash: this.audit.getLatestHash(),
      },
      spendSummary: {
        totalSpendUsd: spendSummary.totalSpendUsd,
        totalTokens: spendSummary.totalTokens,
        stepsExecuted: spendSummary.stepsExecuted,
      },
      durationMs,
    };
  }

  /**
   * Helper to execute a command with sandboxed environment variables
   */
  public async exec(command: CommandInput, options: ExecOptions = {}): Promise<ExecResult> {
    return this.execCommandInternal(command, {
      cwd: this.workspace,
      ...options,
    });
  }

  private execCommandInternal(command: CommandInput, options: ExecOptions = {}): Promise<ExecResult> {
    return new Promise((resolve) => {
      const startTime = Date.now();
      const spawnOptions = {
        cwd: options.cwd || this.workspace,
        env: { ...process.env, ...options.env },
      };
      const shell = options.shell ?? false;
      if (shell && typeof command !== 'string') {
        throw new TypeError('Shell execution requires a command string');
      }
      const [executable, args] = typeof command === 'string'
        ? parseCommandLine(command)
        : (() => {
            if (command.length === 0) throw new Error('Command must not be empty');
            if (command.some((argument) => typeof argument !== 'string')) {
              throw new TypeError('Command arguments must be strings');
            }
            return [command[0]!, [...command.slice(1)]] as [string, string[]];
          })();
      const child = shell
        ? spawn(command as string, { ...spawnOptions, shell })
        : spawn(executable, args, { ...spawnOptions, shell: false });

      let stdout = '';
      let stderr = '';

      child.stdout?.on('data', (chunk) => {
        stdout += chunk.toString();
      });

      child.stderr?.on('data', (chunk) => {
        stderr += chunk.toString();
      });

      let timer: NodeJS.Timeout | null = null;
      if (options.timeoutMs) {
        timer = setTimeout(() => {
          child.kill('SIGKILL');
          stderr += `\nCommand timed out after ${options.timeoutMs}ms`;
        }, options.timeoutMs);
      }

      child.on('close', (exitCode) => {
        if (timer) clearTimeout(timer);
        resolve({
          // A process closed by a signal has no numeric exit code. Treat that
          // as failure; mapping null to zero would incorrectly report success.
          exitCode: exitCode ?? 1,
          stdout,
          stderr,
          durationMs: Date.now() - startTime,
        });
      });

      child.on('error', (err) => {
        if (timer) clearTimeout(timer);
        resolve({
          exitCode: 1,
          stdout,
          stderr: `${stderr}\n${err.message}`,
          durationMs: Date.now() - startTime,
        });
      });
    });
  }

  public snapshot(name?: string): SnapshotMetadata {
    return this.cow.createSnapshot(name);
  }

  public rollback(snapshotId?: string): RollbackResult {
    return this.cow.rollback(snapshotId);
  }

  public diff(snapshotId?: string): WorkspaceDiff {
    return this.cow.diff(snapshotId);
  }

  public commit(name?: string): CommitResult {
    return this.cow.commit(name);
  }

  public getTimeline(): string {
    return exportTimelineAscii(this.audit.getEvents());
  }

  public exportHtmlReport(filePath: string): void {
    const integrity = this.audit.verifyIntegrity();
    const spend = this.limiter.getSummary();
    exportHtmlReportToFile(filePath, this.audit.getEvents(), integrity, {
      workspace: this.workspace,
      totalSpendUsd: spend.totalSpendUsd,
      totalTokens: spend.totalTokens,
    });
  }
}
