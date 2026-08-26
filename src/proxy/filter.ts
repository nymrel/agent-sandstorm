/**
 * @file filter.ts
 * @description Domain allowlist & denylist matcher with wildcard support
 * @author Nymrel / JalenBuilds LLC <contact@nymrel.com>
 * @license MIT
 */

import { isIP } from 'node:net';

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function normalizeHost(hostHeader: string): string {
  const value = hostHeader.trim();
  if (!value) return '';

  try {
    const hostname = new URL(`http://${value}`).hostname;
    return hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
  } catch {
    return '';
  }
}

export class DomainFilter {
  private readonly allowedPatterns: RegExp[];
  private readonly blockedPatterns: RegExp[];

  constructor(allowedDomains: string[] = [], blockedDomains: string[] = []) {
    this.allowedPatterns = allowedDomains.map(d => this.domainToRegex(d));
    this.blockedPatterns = blockedDomains.map(d => this.domainToRegex(d));
  }

  private domainToRegex(pattern: string): RegExp {
    const normalized = pattern.trim().replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
    if (!normalized) throw new TypeError('Domain patterns must not be empty');

    if (isIP(normalized)) {
      return new RegExp(`^${escapeRegExp(normalized)}$`, 'i');
    }

    const labels = normalized.split('.');
    if (labels.some(label => !label)) {
      throw new TypeError(`Invalid domain pattern: ${pattern}`);
    }

    const fragments = labels.map((label) => {
      if (label === '*') return '[a-z0-9_-]+';
      if (!/^[a-z0-9_-]+$/.test(label)) {
        throw new TypeError(`Invalid domain label '${label}' in pattern '${pattern}'`);
      }
      return escapeRegExp(label);
    });

    // A wildcard matches exactly one DNS label. Recursive matching requires an
    // explicit wildcard for each label, e.g. *.*.example.com.
    return new RegExp(`^${fragments.join('\\.')}$`, 'i');
  }

  /**
   * Check if a host (with or without port) is allowed
   */
  public isAllowed(hostHeader: string): boolean {
    if (!hostHeader) return false;
    const cleanHost = normalizeHost(hostHeader);
    if (!cleanHost) return false;

    // Check denylist first
    for (const pattern of this.blockedPatterns) {
      if (pattern.test(cleanHost)) {
        return false;
      }
    }

    // If no allowlist is configured, block by default (Zero-Trust)
    if (this.allowedPatterns.length === 0) {
      return false;
    }

    // Check allowlist
    for (const pattern of this.allowedPatterns) {
      if (pattern.test(cleanHost)) {
        return true;
      }
    }

    return false;
  }
}
