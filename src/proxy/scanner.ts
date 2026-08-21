/**
 * @file scanner.ts
 * @description Secret Exfiltration Scanner & Redaction Engine
 * @author Nymrel / JalenBuilds LLC <contact@jalenbuilds.com>
 * @license MIT
 */

import type { SecretPattern, SecretDetection } from '../types.js';

export const BUILTIN_SECRET_PATTERNS: SecretPattern[] = [
  {
    name: 'OpenAI API Key',
    regex: /sk-(?:proj-|svcacct-|admin-)?[a-zA-Z0-9_-]{20,}/g,
    description: 'OpenAI API secret key pattern',
    severity: 'critical',
  },
  {
    name: 'Anthropic API Key',
    regex: /sk-ant-[a-zA-Z0-9_-]{20,}/g,
    description: 'Anthropic API secret key pattern',
    severity: 'critical',
  },
  {
    name: 'AWS Access Key ID',
    regex: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g,
    description: 'AWS IAM access key ID',
    severity: 'critical',
  },
  {
    name: 'GitHub Token',
    regex: /(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/g,
    description: 'GitHub personal access or OAuth token',
    severity: 'critical',
  },
  {
    name: 'Google API Key',
    regex: /AIza[0-9A-Za-z-_]{35}/g,
    description: 'Google Cloud / Maps / Gemini API Key',
    severity: 'critical',
  },
  {
    name: 'Private Key (PEM)',
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----/g,
    description: 'Cryptographic private key file header',
    severity: 'critical',
  },
  {
    name: 'Slack Token',
    regex: /xox[baprs]-[0-9a-zA-Z]{10,48}/g,
    description: 'Slack API token',
    severity: 'high',
  },
  {
    name: 'Stripe Secret Key',
    regex: /sk_live_[0-9a-zA-Z]{24,}/g,
    description: 'Stripe live payment secret key',
    severity: 'critical',
  },
  {
    name: 'JSON Web Token (JWT)',
    regex: /eyJ[A-Za-z0-9-_]{10,}\.eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}/g,
    description: 'Signed JSON Web Token credentials',
    severity: 'high',
  },
];

export function redactSecret(secret: string): string {
  if (!secret || secret.length <= 6) {
    return '***[REDACTED]***';
  }
  const prefix = secret.substring(0, 4);
  const suffix = secret.substring(secret.length - 2);
  return `${prefix}...[REDACTED]...${suffix}`;
}

export class SecretScanner {
  private readonly patterns: SecretPattern[];

  constructor(customPatterns: SecretPattern[] = []) {
    this.patterns = [...BUILTIN_SECRET_PATTERNS, ...customPatterns];
  }

  /**
   * Scan text for any secrets
   */
  public scan(
    text: string,
    location: 'url' | 'header' | 'body' = 'body'
  ): SecretDetection[] {
    if (!text || typeof text !== 'string') {
      return [];
    }

    const detections: SecretDetection[] = [];

    for (const pattern of this.patterns) {
      // Reset regex state for global regexes
      pattern.regex.lastIndex = 0;
      let match: RegExpExecArray | null;

      while ((match = pattern.regex.exec(text)) !== null) {
        const matched = match[0];
        detections.push({
          patternName: pattern.name,
          description: pattern.description,
          severity: pattern.severity,
          matchedText: matched,
          redactedText: redactSecret(matched),
          location,
          timestamp: Date.now(),
        });
      }
    }

    return detections;
  }

  /**
   * Redact all detected secrets from a text string
   */
  public redactAll(text: string): string {
    if (!text || typeof text !== 'string') return text;
    let redacted = text;
    for (const pattern of this.patterns) {
      pattern.regex.lastIndex = 0;
      redacted = redacted.replace(pattern.regex, (match) => redactSecret(match));
    }
    return redacted;
  }
}
