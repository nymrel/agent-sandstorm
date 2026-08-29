/**
 * @file server.ts
 * @description Cooperative HTTP/CONNECT proxy with a default-deny domain policy
 * @author Nymrel / JalenBuilds LLC <contact@nymrel.com>
 * @license MIT
 */

import * as http from 'node:http';
import * as net from 'node:net';
import * as url from 'node:url';
import type { ProxyConfig, SecretDetection } from '../types.js';
import { SecretScanner } from './scanner.js';
import { DomainFilter } from './filter.js';

export interface ProxyMetrics {
  totalRequests: number;
  allowedRequests: number;
  blockedRequests: number;
  secretsDetected: number;
  bytesTransferred: number;
}

const DEFAULT_ALLOWED_PORTS: readonly number[] = [80, 443];
const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

function connectionHeaderTokens(value: string | string[] | undefined): Set<string> {
  const values = Array.isArray(value) ? value : [value || ''];
  return new Set(
    values
      .flatMap((entry) => entry.split(','))
      .map((token) => token.trim().toLowerCase())
      .filter(Boolean),
  );
}

function normalizeAllowedPorts(ports?: number[]): ReadonlySet<number> {
  const source = ports ?? DEFAULT_ALLOWED_PORTS;
  if (source.length === 0) {
    throw new Error('Invalid allowedPorts configuration: at least one destination port is required.');
  }
  for (const port of source) {
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new Error(`Invalid allowedPorts configuration: expected integers from 1 through 65535 (received ${JSON.stringify(ports)}).`);
    }
  }
  return new Set(source);
}

function parseAuthority(authority: string, defaultPort: number): { hostname: string; port: number } {
  let hostname = authority.trim();
  let portToken: string | undefined;

  if (hostname.startsWith('[')) {
    const close = hostname.indexOf(']');
    if (close < 0) return { hostname: '', port: Number.NaN };
    const remainder = hostname.slice(close + 1);
    hostname = hostname.slice(1, close);
    if (remainder === '') return { hostname, port: defaultPort };
    if (!remainder.startsWith(':')) return { hostname: '', port: Number.NaN };
    portToken = remainder.slice(1);
  } else {
    const firstColon = hostname.indexOf(':');
    const lastColon = hostname.lastIndexOf(':');
    if (firstColon !== -1) {
      if (firstColon !== lastColon) return { hostname: '', port: Number.NaN };
      portToken = hostname.slice(lastColon + 1);
      hostname = hostname.slice(0, lastColon);
    }
  }

  if (portToken === undefined) return { hostname, port: defaultPort };
  if (!/^\d+$/.test(portToken)) return { hostname, port: Number.NaN };

  const parsedPort = Number(portToken);
  return Number.isInteger(parsedPort) && parsedPort >= 1 && parsedPort <= 65535
    ? { hostname, port: parsedPort }
    : { hostname, port: Number.NaN };
}

function formatAuthority(hostname: string, port: number, defaultPort: number): string {
  const host = hostname.includes(':') ? `[${hostname}]` : hostname;
  return port === defaultPort ? host : `${host}:${port}`;
}

function formatPolicyHost(hostname: string): string {
  return hostname.includes(':') ? `[${hostname}]` : hostname;
}

export class ZeroTrustProxy {
  private server: http.Server | null = null;
  private readonly config: ProxyConfig;
  private readonly scanner: SecretScanner;
  private readonly filter: DomainFilter;
  private readonly allowedPorts: ReadonlySet<number>;
  private port = 0;
  private host = '127.0.0.1';
  private metrics: ProxyMetrics = {
    totalRequests: 0,
    allowedRequests: 0,
    blockedRequests: 0,
    secretsDetected: 0,
    bytesTransferred: 0,
  };

  constructor(config: ProxyConfig) {
    this.config = {
      scanPayloads: true,
      logRequests: false,
      ...config,
    };
    this.scanner = new SecretScanner(this.config.customSecretPatterns);
    this.filter = new DomainFilter(this.config.allowedDomains, this.config.blockedDomains);
    this.allowedPorts = normalizeAllowedPorts(this.config.allowedPorts);
  }

  /**
   * Start the proxy server
   */
  public async start(requestedPort = this.config.port || 0, host = this.config.host || '127.0.0.1'): Promise<{ port: number; host: string }> {
    this.host = host;

    return new Promise((resolve, reject) => {
      this.server = http.createServer((req, res) => {
        this.handleHttpRequest(req, res);
      });

      this.server.on('connect', (req, clientSocket, head) => {
        this.handleHttpsConnect(req, clientSocket as net.Socket, head);
      });

      this.server.on('error', (err) => {
        reject(err);
      });

      this.server.listen(requestedPort, this.host, () => {
        const address = this.server?.address();
        if (address && typeof address === 'object') {
          this.port = address.port;
          resolve({ port: this.port, host: this.host });
        } else {
          reject(new Error('Failed to obtain proxy address'));
        }
      });
    });
  }

  /**
   * Handle plain HTTP requests
   */
  private handleHttpRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
    this.metrics.totalRequests++;

    const rawUrl = req.url || '';
    let targetHost = req.headers.host || '';
    let targetPath = rawUrl;

    try {
      if (rawUrl.startsWith('http://') || rawUrl.startsWith('https://')) {
        const parsed = new url.URL(rawUrl);
        if (parsed.protocol !== 'http:') {
          this.metrics.blockedRequests++;
          this.sendBlockedResponse(
            res,
            'ERR_SANDSTORM_SCHEME_UNSUPPORTED',
            'Plain HTTP forwarding accepts only http:// targets; HTTPS must use CONNECT.',
            'Sandstorm Cooperative Proxy Scheme Policy',
          );
          return;
        }
        const rawAuthority = rawUrl
          .slice(parsed.protocol.length + 2)
          .split(/[/?#]/, 1)[0]!;
        targetHost = rawAuthority.includes('@')
          ? rawAuthority.slice(rawAuthority.lastIndexOf('@') + 1)
          : rawAuthority;
        targetPath = parsed.pathname + parsed.search;
      }
    } catch {
      this.metrics.blockedRequests++;
      this.sendBlockedResponse(
        res,
        'ERR_SANDSTORM_TARGET_INVALID',
        'The outbound target URL is malformed.',
        'Sandstorm Cooperative Proxy Target Policy',
      );
      return;
    }

    const upstream = parseAuthority(targetHost, 80);

    // 1. Check Domain Allowlist
    if (!upstream.hostname || !this.filter.isAllowed(formatPolicyHost(upstream.hostname))) {
      this.metrics.blockedRequests++;
      this.config.onBlockedDomain?.(targetHost, rawUrl);
      this.sendBlockedResponse(
        res,
        'ERR_SANDSTORM_DOMAIN_BLOCKED',
        `Domain '${targetHost}' is not in the Sandstorm allowlist.`,
        'Sandstorm Domain Allowlist',
      );
      return;
    }

    // 2. An allowed hostname does not authorize arbitrary service ports.
    if (!this.isPortAllowed(upstream.port)) {
      this.metrics.blockedRequests++;
      this.config.onBlockedPort?.(upstream.hostname, upstream.port, rawUrl);
      const portLabel = Number.isNaN(upstream.port) ? '(invalid)' : String(upstream.port);
      this.sendBlockedResponse(
        res,
        'ERR_SANDSTORM_PORT_BLOCKED',
        `Destination port ${portLabel} on '${upstream.hostname}' is not permitted (allowed: ${this.getAllowedPorts().join(', ')}).`,
        'Sandstorm Destination Port Allowlist',
      );
      return;
    }

    // 3. Scan URL and Request Headers for Secret Exfiltration
    if (this.config.scanPayloads) {
      const urlSecrets = this.scanner.scan(rawUrl, 'url');
      if (urlSecrets.length > 0) {
        this.handleSecretViolation(res, urlSecrets, targetHost);
        return;
      }

      for (const headerVal of Object.values(req.headers)) {
        const values = Array.isArray(headerVal) ? headerVal : [headerVal];
        for (const value of values) {
          if (typeof value !== 'string') continue;
          const headerSecrets = this.scanner.scan(value, 'header');
          if (headerSecrets.length > 0) {
            this.handleSecretViolation(res, headerSecrets, targetHost);
            return;
          }
        }
      }
    }

    // 4. Read Body & Scan for Secrets
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => {
      chunks.push(chunk);
    });

    req.on('end', () => {
      const bodyBuffer = Buffer.concat(chunks);
      this.metrics.bytesTransferred += bodyBuffer.length;

      if (this.config.scanPayloads && bodyBuffer.length > 0) {
        const bodyText = bodyBuffer.toString('utf-8');
        const bodySecrets = this.scanner.scan(bodyText, 'body');

        if (bodySecrets.length > 0) {
          this.handleSecretViolation(res, bodySecrets, targetHost);
          return;
        }
      }

      // Forward request
      this.forwardHttpRequest(req, res, upstream.hostname, upstream.port, targetPath, bodyBuffer);
    });
  }

  /**
   * Forward verified HTTP request
   */
  private forwardHttpRequest(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    hostname: string,
    port: number,
    targetPath: string,
    bodyBuffer: Buffer
  ): void {
    const connectionTokens = connectionHeaderTokens(req.headers.connection);
    const headers: http.OutgoingHttpHeaders = {};
    for (const [name, value] of Object.entries(req.headers)) {
      const normalized = name.toLowerCase();
      if (HOP_BY_HOP_HEADERS.has(normalized) || connectionTokens.has(normalized) || normalized === 'host') continue;
      headers[name] = value;
    }
    headers.host = formatAuthority(hostname, port, 80);

    const proxyReq = http.request(
      {
        hostname,
        port,
        path: targetPath,
        method: req.method,
        headers,
      },
      (proxyRes) => {
        this.metrics.allowedRequests++;
        const responseConnectionTokens = connectionHeaderTokens(proxyRes.headers.connection);
        const responseHeaders: http.OutgoingHttpHeaders = {};
        for (const [name, value] of Object.entries(proxyRes.headers)) {
          const normalized = name.toLowerCase();
          if (HOP_BY_HOP_HEADERS.has(normalized) || responseConnectionTokens.has(normalized)) continue;
          responseHeaders[name] = value;
        }
        res.writeHead(proxyRes.statusCode || 200, responseHeaders);
        proxyRes.pipe(res);
      }
    );

    proxyReq.on('error', (err) => {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'BAD_GATEWAY', message: err.message }));
    });

    if (bodyBuffer.length > 0) {
      proxyReq.write(bodyBuffer);
    }
    proxyReq.end();
  }

  /**
   * Handle HTTPS CONNECT tunnels
   */
  private handleHttpsConnect(
    req: http.IncomingMessage,
    clientSocket: net.Socket,
    head: Buffer
  ): void {
    this.metrics.totalRequests++;
    const targetUrl = req.url || '';
    const { hostname, port } = parseAuthority(targetUrl, 443);

    if (!hostname || !this.filter.isAllowed(formatPolicyHost(hostname))) {
      this.metrics.blockedRequests++;
      this.config.onBlockedDomain?.(hostname || 'unknown', targetUrl);
      clientSocket.write(this.connectBlockedMessage(
        'ERR_SANDSTORM_DOMAIN_BLOCKED',
        `Domain '${hostname}' is not permitted by the Sandstorm allowlist.`,
      ));
      clientSocket.end();
      return;
    }

    if (!this.isPortAllowed(port)) {
      this.metrics.blockedRequests++;
      this.config.onBlockedPort?.(hostname, port, targetUrl);
      const portLabel = Number.isNaN(port) ? '(invalid)' : String(port);
      clientSocket.write(this.connectBlockedMessage(
        'ERR_SANDSTORM_PORT_BLOCKED',
        `Destination port ${portLabel} on '${hostname}' is not permitted (allowed: ${this.getAllowedPorts().join(', ')}).`,
      ));
      clientSocket.end();
      return;
    }

    // Connect to target server
    const serverSocket = net.connect(port, hostname, () => {
      this.metrics.allowedRequests++;
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head && head.length > 0) {
        serverSocket.write(head);
      }
      serverSocket.pipe(clientSocket);
      clientSocket.pipe(serverSocket);
    });

    serverSocket.on('error', () => {
      clientSocket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n');
      clientSocket.end();
    });

    clientSocket.on('error', () => {
      serverSocket.destroy();
    });
  }

  private handleSecretViolation(
    res: http.ServerResponse,
    detections: SecretDetection[],
    targetHost: string
  ): void {
    this.metrics.secretsDetected += detections.length;
    this.metrics.blockedRequests++;

    const first = detections[0]!;
    this.config.onSecretDetected?.(first);

    res.writeHead(403, { 'Content-Type': 'application/json' });
    res.end(
      JSON.stringify({
        error: 'ERR_SANDSTORM_SECRET_EXFILTRATION_BLOCKED',
        severity: first.severity,
        pattern: first.patternName,
        redacted: first.redactedText,
        location: first.location,
        targetHost,
        message: 'Outbound request blocked by Sandstorm: high-entropy secret detected in outbound payload.',
      })
    );
  }

  private isPortAllowed(port: number): boolean {
    return Number.isInteger(port) && this.allowedPorts.has(port);
  }

  public getAllowedPorts(): number[] {
    return [...this.allowedPorts].sort((left, right) => left - right);
  }

  private connectBlockedMessage(error: string, reason: string): string {
    const body = JSON.stringify({ error, reason });
    return `HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`;
  }

  private sendBlockedResponse(
    res: http.ServerResponse,
    error: string,
    reason: string,
    policy: string,
  ): void {
    res.writeHead(403, { 'Content-Type': 'application/json' });
    res.end(
      JSON.stringify({
        error,
        reason,
        policy,
      })
    );
  }

  /**
   * Get environment variables to inject into child processes
   */
  public getEnv(): Record<string, string> {
    if (!this.port) {
      throw new Error('Proxy server is not running');
    }
    const proxyUrl = `http://${this.host}:${this.port}`;
    return {
      HTTP_PROXY: proxyUrl,
      HTTPS_PROXY: proxyUrl,
      http_proxy: proxyUrl,
      https_proxy: proxyUrl,
      ALL_PROXY: proxyUrl,
      all_proxy: proxyUrl,
      NO_PROXY: 'localhost,127.0.0.1',
      no_proxy: 'localhost,127.0.0.1',
    };
  }

  public getPort(): number {
    return this.port;
  }

  public getMetrics(): ProxyMetrics {
    return { ...this.metrics };
  }

  /** Redact recognized credentials before text is persisted or displayed. */
  public redactForAudit(text: string): string {
    return this.scanner.redactAll(text);
  }

  /**
   * Stop the proxy server
   */
  public async stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => {
          this.server = null;
          this.port = 0;
          resolve();
        });
      } else {
        resolve();
      }
    });
  }
}
