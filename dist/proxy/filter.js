/**
 * @file filter.js
 * @description Domain allowlist & denylist matcher with wildcard support
 * @author Nymrel / JalenBuilds LLC <contact@jalenbuilds.com>
 * @license MIT
 */

export class DomainFilter {
  constructor(allowedDomains = [], blockedDomains = []) {
    this.allowedPatterns = allowedDomains.map(d => this.domainToRegex(d));
    this.blockedPatterns = blockedDomains.map(d => this.domainToRegex(d));
  }

  domainToRegex(pattern) {
    const trimmed = pattern.trim().toLowerCase();
    const escaped = trimmed
      .replace(/\./g, '\\.')
      .replace(/\*/g, '[a-zA-Z0-9_-]+');
    return new RegExp(`^(?:.+\\.)?${escaped}$`, 'i');
  }

  isAllowed(hostHeader) {
    if (!hostHeader) return false;
    const cleanHost = hostHeader.split(':')[0].toLowerCase();

    // Check denylist first
    for (const pattern of this.blockedPatterns) {
      if (pattern.test(cleanHost)) {
        return false;
      }
    }

    // Zero-Trust: must be in allowlist
    if (this.allowedPatterns.length === 0) {
      return false;
    }

    for (const pattern of this.allowedPatterns) {
      if (pattern.test(cleanHost)) {
        return true;
      }
    }

    return false;
  }
}
