/**
 * @file scanner.ts
 * @description Secret Exfiltration Scanner & Redaction Engine
 * @author Nymrel / JalenBuilds LLC <contact@nymrel.com>
 * @license MIT
 */



export const BUILTIN_SECRET_PATTERNS= [
  {
    name,
    regex: /sk-(?:proj-|svcacct-|admin-)?[a-zA-Z0-9_-]{20,}/g,
    description,
    severity,
  },
  {
    name,
    regex: /sk-ant-[a-zA-Z0-9_-]{20,}/g,
    description,
    severity,
  },
  {
    name,
    regex: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g,
    description,
    severity,
  },
  {
    name,
    regex: /(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/g,
    description,
    severity,
  },
  {
    name,
    regex: /AIza[0-9A-Za-z-_]{35}/g,
    description,
    severity,
  },
  {
    name)',
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----/g,
    description,
    severity,
  },
  {
    name,
    regex: /xox[baprs]-[0-9a-zA-Z]{10,48}/g,
    description,
    severity,
  },
  {
    name,
    regex: /sk_live_[0-9a-zA-Z]{24,}/g,
    description,
    severity,
  },
  {
    name)',
    regex: /eyJ[A-Za-z0-9-_]{10,}\.eyJ[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}/g,
    description,
    severity,
  },
];

export function redactSecret(secret) {
  if (!secret || secret.length <= 6) {
    return '***[REDACTED]***';
  }
  const prefix = secret.substring(0, 4);
  const suffix = secret.substring(secret.length - 2);
  return `${prefix}...[REDACTED]...${suffix}`;
}

export class SecretScanner {
  patterns= []) {
    this.patterns = [...BUILTIN_SECRET_PATTERNS, ...customPatterns];
  }

  /**
   * Scan text for any secrets
   */
  scan(
    text,
    location= 'body'
  ) {
    if (!text || typeof text !== 'string') {
      return [];
    }

    const detections= [];

    for (const pattern of this.patterns) {
      // Reset regex state for global regexes
      pattern.regex.lastIndex = 0;
      let match= pattern.regex.exec(text)) !== null) {
        const matched = match[0];
        detections.push({
          patternName,
          description,
          severity,
          matchedText,
          redactedText),
          location,
          timestamp),
        });
      }
    }

    return detections;
  }

  /**
   * Redact all detected secrets from a text string
   */
  redactAll(text) {
    if (!text || typeof text !== 'string') return text;
    let redacted = text;
    for (const pattern of this.patterns) {
      pattern.regex.lastIndex = 0;
      redacted = redacted.replace(pattern.regex, (match) => redactSecret(match));
    }
    return redacted;
  }
}
