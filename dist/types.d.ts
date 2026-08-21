/**
 * @file types.ts
 * @description Core types and interfaces for @nymrel/agent-sandstorm
 * @author Nymrel / JalenBuilds LLC <contact@nymrel.com>
 * @license MIT
 */
export interface FileSnapshot {
    path: string;
    relativePath: string;
    sha256: string;
    size: number;
    mtimeMs: number;
    mode?: number;
}
export interface SnapshotMetadata {
    id: string;
    name: string;
    timestamp: number;
    isoTime: string;
    workspacePath: string;
    fileCount: number;
    totalSizeBytes: number;
    treeHash: string;
    files: Record<string, FileSnapshot>;
    metadata?: Record<string, unknown>;
}
export type MutationType = 'created' | 'modified' | 'deleted';
export interface JournalMutation {
    type: MutationType;
    relativePath: string;
    timestamp: number;
    previousSha256?: string;
    currentSha256?: string;
    previousSize?: number;
    currentSize?: number;
}
export interface TransactionJournal {
    id: string;
    name: string;
    startTime: number;
    baseSnapshotId: string;
    mutations: JournalMutation[];
}
export interface RollbackResult {
    success: boolean;
    snapshotId: string;
    restoredFiles: string[];
    deletedFiles: string[];
    revertedFiles: string[];
    durationMs: number;
    error?: string;
}
export interface CommitResult {
    success: boolean;
    snapshotId: string;
    transactionId?: string;
    fileCount: number;
    treeHash: string;
    durationMs: number;
}
export interface WorkspaceDiff {
    baseSnapshotId: string;
    added: string[];
    modified: string[];
    deleted: string[];
    unchangedCount: number;
    totalChanged: number;
}
export interface SecretPattern {
    name: string;
    regex: RegExp;
    description: string;
    severity: 'high' | 'critical';
}
export interface SecretDetection {
    patternName: string;
    description: string;
    severity: 'high' | 'critical';
    matchedText: string;
    redactedText: string;
    location: 'url' | 'header' | 'body';
    timestamp: number;
}
export interface ProxyConfig {
    port?: number;
    host?: string;
    allowedDomains: string[];
    blockedDomains?: string[];
    scanPayloads?: boolean;
    customSecretPatterns?: SecretPattern[];
    onSecretDetected?: (detection: SecretDetection) => void;
    onBlockedDomain?: (domain: string, url: string) => void;
    logRequests?: boolean;
}
export interface ModelPricing {
    promptCostPer1k: number;
    completionCostPer1k: number;
}
export interface LimiterConfig {
    maxSpendUsd?: number;
    maxTotalTokens?: number;
    maxSteps?: number;
    maxDurationMs?: number;
    loopDetection?: boolean;
    loopThreshold?: number;
    windowSize?: number;
    customPricing?: Record<string, ModelPricing>;
}
export type AuditSeverity = 'info' | 'warn' | 'error' | 'critical';
export interface AuditEvent {
    index: number;
    prevHash: string;
    hash: string;
    timestamp: number;
    isoTime: string;
    type: string;
    severity: AuditSeverity;
    payload: Record<string, unknown>;
}
export interface AuditIntegrityResult {
    valid: boolean;
    eventCount: number;
    corruptedIndex?: number;
    genesisHash: string;
    latestHash: string;
}
export interface SandstormOptions {
    workspace: string;
    allowDomains?: string[];
    blockDomains?: string[];
    maxSpendUsd?: number;
    maxTokens?: number;
    maxSteps?: number;
    maxDurationMs?: number;
    autoRollbackOnError?: boolean;
    detectRunawayLoops?: boolean;
    loopThreshold?: number;
    scanSecrets?: boolean;
    customSecretPatterns?: SecretPattern[];
    auditLogPath?: string;
    silent?: boolean;
}
export interface ExecOptions {
    cwd?: string;
    env?: Record<string, string>;
    timeoutMs?: number;
    shell?: string | boolean;
}
export interface ExecResult {
    exitCode: number;
    stdout: string;
    stderr: string;
    durationMs: number;
}
export interface SandboxContext {
    workspace: string;
    exec: (command: string, options?: ExecOptions) => Promise<ExecResult>;
    env: Record<string, string>;
    recordTokenUsage: (model: string, promptTokens: number, completionTokens: number) => {
        currentSpendUsd: number;
        exceeded: boolean;
    };
    recordStep: (actionName: string, detail?: string) => void;
    snapshot: (name?: string) => SnapshotMetadata;
    rollback: (snapshotId?: string) => RollbackResult;
    diff: () => WorkspaceDiff;
}
export interface SandboxResult<T = unknown> {
    success: boolean;
    result?: T;
    error?: Error;
    rollbackPerformed: boolean;
    rollbackSummary?: RollbackResult;
    baseSnapshot: SnapshotMetadata;
    finalTreeHash: string;
    auditSummary: {
        eventCount: number;
        verified: boolean;
        latestHash: string;
    };
    spendSummary: {
        totalSpendUsd: number;
        totalTokens: number;
        stepsExecuted: number;
    };
    durationMs: number;
}
//# sourceMappingURL=types.d.ts.map