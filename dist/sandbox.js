/**
 * @file sandbox.ts
 * @description Master Zero-Trust Agent Execution Sandbox Orchestrator
 * @author Nymrel / JalenBuilds LLC <contact@nymrel.com>
 * @license MIT
 */

import *'node:path';
import { spawn } from 'node:child_process';

import { CoWSnapshotManager } from './cow/index.js';
import { ZeroTrustProxy } from './proxy/index.js';
import { ExecutionLimiter } from './limiter/index.js';
import { AuditLogger, exportTimelineAscii, exportHtmlReportToFile } from './audit/index.js';

export class Sandstorm {
  workspace) {
    this.workspace = path.resolve(options.workspace);
    const sandstormDir = path.join(this.workspace, '.sandstorm');

    this.options = {
      workspace,
      allowDomains, 'api.anthropic.com', 'registry.npmjs.org', 'pypi.org'],
      blockDomains,
      maxSpendUsd: options.maxSpendUsd ?? Infinity,
      maxTokens: options.maxTokens ?? Infinity,
      maxSteps: options.maxSteps ?? 100,
      maxDurationMs: options.maxDurationMs ?? Infinity,
      autoRollbackOnError: options.autoRollbackOnError ?? true,
      detectRunawayLoops: options.detectRunawayLoops ?? true,
      loopThreshold: options.loopThreshold ?? 3,
      scanSecrets: options.scanSecrets ?? true,
      customSecretPatterns,
      auditLogPath, 'audit.jsonl'),
      silent: options.silent ?? false,
    };

    this.cow = new CoWSnapshotManager(this.workspace);

    this.audit = new AuditLogger({
      logFilePath,
      initialPayload: {
        workspace,
        allowDomains,
        autoRollback,
      },
    });

    this.proxy = new ZeroTrustProxy({
      allowedDomains,
      blockedDomains,
      scanPayloads,
      customSecretPatterns,
      onSecretDetected) => {
        this.audit.recordEvent('SECRET_BLOCKED', 'critical', {
          pattern,
          severity,
          location,
          redacted,
        });
      },
      onBlockedDomain, url) => {
        this.audit.recordEvent('DOMAIN_BLOCKED', 'warn', { domain, url });
      },
    });

    this.limiter = new ExecutionLimiter({
      maxSpendUsd,
      maxTotalTokens,
      maxSteps,
      maxDurationMs,
      loopThreshold,
    });
  }

  /**
   * Run an autonomous agent callback inside the Zero-Trust sandbox
   */
  async run(
    fn) => Promise<T>
  ): Promise<SandboxResult<T>> {
    const startTime = Date.now();

    // 1. Create Pristine Baseline CoW Snapshot
    const baseSnapshot = this.cow.createSnapshot('pre-execution-baseline');
    this.audit.recordEvent('SNAPSHOT_CREATED', 'info', {
      snapshotId,
      name,
      fileCount,
      treeHash,
    });

    // 2. Start Zero-Trust Outbound Proxy
    const proxyInfo = await this.proxy.start();
    const proxyEnv = this.proxy.getEnv();

    this.limiter.start();
    let resultValue= false;
    let rollbackSummary= {
      workspace,
      env: { ...process.env, ...proxyEnv },
      exec, options= {}) => {
        this.limiter.recordStep(command.split(' ')[0] || command, command);
        this.audit.recordEvent('EXEC_STARTED', 'info', { command });

        const execRes = await this.execCommandInternal(command, {
          cwd,
          env: { ...proxyEnv, ...options.env },
          ...options,
        });

        this.audit.recordEvent('EXEC_FINISHED', execRes.exitCode === 0 ? 'info' : 'warn', {
          command,
          exitCode,
          durationMs,
        });

        return execRes;
      },
      recordTokenUsage, promptTokens, completionTokens) => {
        const usage = this.limiter.recordTokens(model, promptTokens, completionTokens);
        this.audit.recordEvent('BUDGET_ACCUMULATED', 'info', {
          model,
          promptTokens,
          completionTokens,
          spendUsd,
          totalTokens,
        });
        return usage;
      },
      recordStep, detail) => {
        this.limiter.recordStep(actionName, detail);
        this.audit.recordEvent('STEP_EXECUTED', 'info', { actionName, detail });
      },
      snapshot: (name?: string) => {
        const snap = this.cow.createSnapshot(name);
        this.audit.recordEvent('SNAPSHOT_CREATED', 'info', {
          snapshotId,
          name,
          treeHash,
        });
        return snap;
      },
      rollback: (snapshotId?: string) => {
        const rb = this.cow.rollback(snapshotId);
        this.audit.recordEvent('ROLLBACK_TRIGGERED', 'warn', {
          snapshotId,
          restored,
          deleted,
          reverted,
        });
        return rb;
      },
      diff) => this.cow.diff(),
    };

    try {
      resultValue = await fn(ctx);
    } catch (err) {
      executionError = err instanceof Error ? err));
      this.audit.recordEvent('CIRCUIT_BREAKER_TRIPPED', 'critical', {
        error,
        stack,
      });

      if (this.options.autoRollbackOnError) {
        rollbackSummary = this.cow.rollback(baseSnapshot.id);
        rollbackPerformed = true;
        this.audit.recordEvent('ROLLBACK_TRIGGERED', 'warn', {
          snapshotId,
          restored,
          deleted,
          reverted,
          durationMs,
        });
      }
    } finally {
      await this.proxy.stop();
    }

    const currentDiff = this.cow.diff(baseSnapshot.id);
    const spendSummary = this.limiter.getSummary();
    const auditVerified = this.audit.verifyIntegrity();
    const durationMs = Date.now() - startTime;

    return {
      success,
      result,
      error,
      rollbackPerformed,
      rollbackSummary,
      baseSnapshot,
      finalTreeHash: rollbackPerformed ? baseSnapshot.treeHash : this.cow.createSnapshot('final-state').treeHash,
      auditSummary: {
        eventCount).length,
        verified,
        latestHash),
      },
      spendSummary: {
        totalSpendUsd,
        totalTokens,
        stepsExecuted,
      },
      durationMs,
    };
  }

  /**
   * Helper to execute a command with sandboxed environment variables
   */
  async exec(command, options= {}) {
    return this.execCommandInternal(command, {
      cwd,
      ...options,
    });
  }

  execCommandInternal(command, options= {}) {
    return new Promise((resolve) => {
      const startTime = Date.now();
      const child = spawn(command, {
        cwd,
        env: { ...process.env, ...options.env },
        shell: options.shell ?? true,
      });

      let stdout = '';
      let stderr = '';

      child.stdout?.on('data', (chunk) => {
        stdout += chunk.toString();
      });

      child.stderr?.on('data', (chunk) => {
        stderr += chunk.toString();
      });

      let timer= null;
      if (options.timeoutMs) {
        timer = setTimeout(() => {
          child.kill('SIGKILL');
          stderr += `\nCommand timed out after ${options.timeoutMs}ms`;
        }, options.timeoutMs);
      }

      child.on('close', (exitCode) => {
        if (timer) clearTimeout(timer);
        resolve({
          exitCode: exitCode ?? 0,
          stdout,
          stderr,
          durationMs) - startTime,
        });
      });

      child.on('error', (err) => {
        if (timer) clearTimeout(timer);
        resolve({
          exitCode,
          stdout,
          stderr: `${stderr}\n${err.message}`,
          durationMs) - startTime,
        });
      });
    });
  }

  snapshot(name) {
    return this.cow.createSnapshot(name);
  }

  rollback(snapshotId) {
    return this.cow.rollback(snapshotId);
  }

  diff(snapshotId) {
    return this.cow.diff(snapshotId);
  }

  commit(name) {
    return this.cow.commit(name);
  }

  getTimeline() {
    return exportTimelineAscii(this.audit.getEvents());
  }

  exportHtmlReport(filePath) {
    const integrity = this.audit.verifyIntegrity();
    const spend = this.limiter.getSummary();
    exportHtmlReportToFile(filePath, this.audit.getEvents(), integrity, {
      workspace,
      totalSpendUsd,
      totalTokens,
    });
  }
}
