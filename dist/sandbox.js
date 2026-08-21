/**
 * @file sandbox.ts
 * @description Master Zero-Trust Agent Execution Sandbox Orchestrator
 * @author Nymrel / JalenBuilds LLC <contact@nymrel.com>
 * @license MIT
 */
import * as path from 'node:path';
import { spawn } from 'node:child_process';
import { CoWSnapshotManager } from './cow/index.js';
import { ZeroTrustProxy } from './proxy/index.js';
import { ExecutionLimiter } from './limiter/index.js';
import { AuditLogger, exportTimelineAscii, exportHtmlReportToFile } from './audit/index.js';
export class Sandstorm {
    workspace;
    cow;
    proxy;
    limiter;
    audit;
    options;
    constructor(options) {
        this.workspace = path.resolve(options.workspace);
        const sandstormDir = path.join(this.workspace, '.sandstorm');
        this.options = {
            workspace: this.workspace,
            allowDomains: options.allowDomains || ['api.openai.com', 'api.anthropic.com', 'registry.npmjs.org', 'pypi.org'],
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
                    pattern: detection.patternName,
                    severity: detection.severity,
                    location: detection.location,
                    redacted: detection.redactedText,
                });
            },
            onBlockedDomain: (domain, url) => {
                this.audit.recordEvent('DOMAIN_BLOCKED', 'warn', { domain, url });
            },
        });
        this.limiter = new ExecutionLimiter({
            maxSpendUsd: this.options.maxSpendUsd,
            maxTotalTokens: this.options.maxTokens,
            maxSteps: this.options.maxSteps,
            maxDurationMs: this.options.maxDurationMs,
            loopThreshold: this.options.loopThreshold,
        });
    }
    /**
     * Run an autonomous agent callback inside the protected Zero-Trust sandbox
     */
    async run(fn) {
        const startTime = Date.now();
        // 1. Create Pristine Baseline CoW Snapshot
        const baseSnapshot = this.cow.createSnapshot('pre-execution-baseline');
        this.audit.recordEvent('SNAPSHOT_CREATED', 'info', {
            snapshotId: baseSnapshot.id,
            name: baseSnapshot.name,
            fileCount: baseSnapshot.fileCount,
            treeHash: baseSnapshot.treeHash,
        });
        // 2. Start Zero-Trust Outbound Proxy
        const proxyInfo = await this.proxy.start();
        const proxyEnv = this.proxy.getEnv();
        this.limiter.start();
        let resultValue;
        let executionError;
        let rollbackPerformed = false;
        let rollbackSummary;
        const ctx = {
            workspace: this.workspace,
            env: { ...process.env, ...proxyEnv },
            exec: async (command, options = {}) => {
                this.limiter.recordStep(command.split(' ')[0] || command, command);
                this.audit.recordEvent('EXEC_STARTED', 'info', { command });
                const execRes = await this.execCommandInternal(command, {
                    cwd: this.workspace,
                    env: { ...proxyEnv, ...options.env },
                    ...options,
                });
                this.audit.recordEvent('EXEC_FINISHED', execRes.exitCode === 0 ? 'info' : 'warn', {
                    command,
                    exitCode: execRes.exitCode,
                    durationMs: execRes.durationMs,
                });
                return execRes;
            },
            recordTokenUsage: (model, promptTokens, completionTokens) => {
                const usage = this.limiter.recordTokens(model, promptTokens, completionTokens);
                this.audit.recordEvent('BUDGET_ACCUMULATED', 'info', {
                    model,
                    promptTokens,
                    completionTokens,
                    spendUsd: usage.currentSpendUsd,
                    totalTokens: usage.totalTokens,
                });
                return usage;
            },
            recordStep: (actionName, detail) => {
                this.limiter.recordStep(actionName, detail);
                this.audit.recordEvent('STEP_EXECUTED', 'info', { actionName, detail });
            },
            snapshot: (name) => {
                const snap = this.cow.createSnapshot(name);
                this.audit.recordEvent('SNAPSHOT_CREATED', 'info', {
                    snapshotId: snap.id,
                    name: snap.name,
                    treeHash: snap.treeHash,
                });
                return snap;
            },
            rollback: (snapshotId) => {
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
        }
        catch (err) {
            executionError = err instanceof Error ? err : new Error(String(err));
            this.audit.recordEvent('CIRCUIT_BREAKER_TRIPPED', 'critical', {
                error: executionError.message,
                stack: executionError.stack,
            });
            if (this.options.autoRollbackOnError) {
                rollbackSummary = this.cow.rollback(baseSnapshot.id);
                rollbackPerformed = true;
                this.audit.recordEvent('ROLLBACK_TRIGGERED', 'warn', {
                    snapshotId: baseSnapshot.id,
                    restored: rollbackSummary.restoredFiles.length,
                    deleted: rollbackSummary.deletedFiles.length,
                    reverted: rollbackSummary.revertedFiles.length,
                    durationMs: rollbackSummary.durationMs,
                });
            }
        }
        finally {
            await this.proxy.stop();
        }
        const currentDiff = this.cow.diff(baseSnapshot.id);
        const spendSummary = this.limiter.getSummary();
        const auditVerified = this.audit.verifyIntegrity();
        const durationMs = Date.now() - startTime;
        return {
            success: !executionError,
            result: resultValue,
            error: executionError,
            rollbackPerformed,
            rollbackSummary,
            baseSnapshot,
            finalTreeHash: rollbackPerformed ? baseSnapshot.treeHash : this.cow.createSnapshot('final-state').treeHash,
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
    async exec(command, options = {}) {
        return this.execCommandInternal(command, {
            cwd: this.workspace,
            ...options,
        });
    }
    execCommandInternal(command, options = {}) {
        return new Promise((resolve) => {
            const startTime = Date.now();
            const child = spawn(command, {
                cwd: options.cwd || this.workspace,
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
            let timer = null;
            if (options.timeoutMs) {
                timer = setTimeout(() => {
                    child.kill('SIGKILL');
                    stderr += `\nCommand timed out after ${options.timeoutMs}ms`;
                }, options.timeoutMs);
            }
            child.on('close', (exitCode) => {
                if (timer)
                    clearTimeout(timer);
                resolve({
                    exitCode: exitCode ?? 0,
                    stdout,
                    stderr,
                    durationMs: Date.now() - startTime,
                });
            });
            child.on('error', (err) => {
                if (timer)
                    clearTimeout(timer);
                resolve({
                    exitCode: 1,
                    stdout,
                    stderr: `${stderr}\n${err.message}`,
                    durationMs: Date.now() - startTime,
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
            workspace: this.workspace,
            totalSpendUsd: spend.totalSpendUsd,
            totalTokens: spend.totalTokens,
        });
    }
}
//# sourceMappingURL=sandbox.js.map