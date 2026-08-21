/**
 * @file filter.ts
 * @description Domain allowlist & denylist matcher with wildcard support
 * @author Nymrel / JalenBuilds LLC <contact@nymrel.com>
 * @license MIT
 */

export class DomainFilter {
  allowedPatterns= [], blockedDomains= []) {
    this.allowedPatterns = allowedDomains.map(d => this.domainToRegex(d));
    this.blockedPatterns = blockedDomains.map(d => this.domainToRegex(d));
  }

  domainToRegex(pattern) {
    const trimmed = pattern.trim().toLowerCase();
    // Support wildcards like *.openai.com or api.*.com
    const escaped = trimmed
      .replace(/\./g, '\\.')
      .replace(/\*/g, '[a-zA-Z0-9_-]+');
    return new RegExp(`^(?:.+\\.)?${escaped}$`, 'i');
  }

  /**
   * Check if a host (with or without port) is allowed
   */
  isAllowed(hostHeader) {
    if (!hostHeader) return false;
    const cleanHost = hostHeader.split(':')[0].toLowerCase();

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
