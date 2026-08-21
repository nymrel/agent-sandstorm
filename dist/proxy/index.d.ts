export * from '../types.js';
import type { ProxyConfig, SecretDetection, SecretPattern } from '../types.js';

export declare class SecretScanner {
  constructor(customPatterns?: SecretPattern[]);
  scan(text: string, location?: 'url' | 'header' | 'body'): SecretDetection[];
  redactAll(text: string): string;
}

export declare class DomainFilter {
  constructor(allowedDomains?: string[], blockedDomains?: string[]);
  isAllowed(hostHeader: string): boolean;
}

export declare class ZeroTrustProxy {
  constructor(config: ProxyConfig);
  start(requestedPort?: number, host?: string): Promise<{ port: number; host: string }>;
  getEnv(): Record<string, string>;
  getPort(): number;
  stop(): Promise<void>;
}
