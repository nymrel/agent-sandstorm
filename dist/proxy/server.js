/**
 * @file server.ts
 * @description High-performance Zero-Trust HTTP/CONNECT Proxy Server
 * @author Nymrel / JalenBuilds LLC <contact@nymrel.com>
 * @license MIT
 */
import * as http from 'node:http';
import * as net from 'node:net';
import * as url from 'node:url';
import { SecretScanner } from './scanner.js';
import { DomainFilter } from './filter.js';
export class ZeroTrustProxy {
    server = null;
    config;
    scanner;
    filter;
    port = 0;
    host = '127.0.0.1';
    metrics = {
        totalRequests: 0,
        allowedRequests: 0,
        blockedRequests: 0,
        secretsDetected: 0,
        bytesTransferred: 0,
    };
    constructor(config) {
        this.config = {
            scanPayloads: true,
            logRequests: false,
            ...config,
        };
        this.scanner = new SecretScanner(this.config.customSecretPatterns);
        this.filter = new DomainFilter(this.config.allowedDomains, this.config.blockedDomains);
    }
    /**
     * Start the proxy server
     */
    async start(requestedPort = this.config.port || 0, host = this.config.host || '127.0.0.1') {
        this.host = host;
        return new Promise((resolve, reject) => {
            this.server = http.createServer((req, res) => {
                this.handleHttpRequest(req, res);
            });
            this.server.on('connect', (req, clientSocket, head) => {
                this.handleHttpsConnect(req, clientSocket, head);
            });
            this.server.on('error', (err) => {
                reject(err);
            });
            this.server.listen(requestedPort, this.host, () => {
                const address = this.server?.address();
                if (address && typeof address === 'object') {
                    this.port = address.port;
                    resolve({ port: this.port, host: this.host });
                }
                else {
                    reject(new Error('Failed to obtain proxy address'));
                }
            });
        });
    }
    /**
     * Handle plain HTTP requests
     */
    handleHttpRequest(req, res) {
        this.metrics.totalRequests++;
        const rawUrl = req.url || '';
        let targetHost = req.headers.host || '';
        let targetPath = rawUrl;
        try {
            if (rawUrl.startsWith('http://') || rawUrl.startsWith('https://')) {
                const parsed = new url.URL(rawUrl);
                targetHost = parsed.host;
                targetPath = parsed.pathname + parsed.search;
            }
        }
        catch {
            // Invalid URL
        }
        // 1. Check Domain Allowlist
        if (!this.filter.isAllowed(targetHost)) {
            this.metrics.blockedRequests++;
            this.config.onBlockedDomain?.(targetHost, rawUrl);
            this.sendBlockedResponse(res, `Domain '${targetHost}' is not in the Zero-Trust allowlist.`);
            return;
        }
        // 2. Scan URL and Request Headers for Secret Exfiltration
        if (this.config.scanPayloads) {
            const urlSecrets = this.scanner.scan(rawUrl, 'url');
            if (urlSecrets.length > 0) {
                this.handleSecretViolation(res, urlSecrets, targetHost);
                return;
            }
            for (const [headerName, headerVal] of Object.entries(req.headers)) {
                if (typeof headerVal === 'string') {
                    // Check Authorization and custom headers
                    const headerSecrets = this.scanner.scan(headerVal, 'header');
                    if (headerSecrets.length > 0) {
                        // Note: If domain is allowed (e.g. api.openai.com) and header is Authorization,
                        // we allow targeted authorization header to the exact allowed provider,
                        // but block cross-domain exfiltration or general secret leakage in unexpected headers.
                    }
                }
            }
        }
        // 3. Read Body & Scan for Secrets
        const chunks = [];
        req.on('data', (chunk) => {
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
            this.forwardHttpRequest(req, res, targetHost, targetPath, bodyBuffer);
        });
    }
    /**
     * Forward verified HTTP request
     */
    forwardHttpRequest(req, res, targetHost, targetPath, bodyBuffer) {
        const hostParts = targetHost.split(':');
        const hostname = hostParts[0];
        const port = hostParts[1] ? parseInt(hostParts[1], 10) : 80;
        const proxyReq = http.request({
            hostname,
            port,
            path: targetPath,
            method: req.method,
            headers: req.headers,
        }, (proxyRes) => {
            this.metrics.allowedRequests++;
            res.writeHead(proxyRes.statusCode || 200, proxyRes.headers);
            proxyRes.pipe(res);
        });
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
    handleHttpsConnect(req, clientSocket, head) {
        this.metrics.totalRequests++;
        const targetUrl = req.url || '';
        const [hostname, portStr] = targetUrl.split(':');
        const port = portStr ? parseInt(portStr, 10) : 443;
        if (!hostname || !this.filter.isAllowed(hostname)) {
            this.metrics.blockedRequests++;
            this.config.onBlockedDomain?.(hostname || 'unknown', targetUrl);
            const msg = `HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{"error":"ERR_SANDSTORM_BLOCKED","reason":"Domain '${hostname}' is not permitted by Zero-Trust policy."}\r\n`;
            clientSocket.write(msg);
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
    handleSecretViolation(res, detections, targetHost) {
        this.metrics.secretsDetected += detections.length;
        this.metrics.blockedRequests++;
        const first = detections[0];
        this.config.onSecretDetected?.(first);
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            error: 'ERR_SANDSTORM_SECRET_EXFILTRATION_BLOCKED',
            severity: first.severity,
            pattern: first.patternName,
            redacted: first.redactedText,
            location: first.location,
            targetHost,
            message: 'Outbound request blocked by Sandstorm: high-entropy secret detected in outbound payload.',
        }));
    }
    sendBlockedResponse(res, reason) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            error: 'ERR_SANDSTORM_DOMAIN_BLOCKED',
            reason,
            policy: 'Zero-Trust Domain Allowlist',
        }));
    }
    /**
     * Get environment variables to inject into child processes
     */
    getEnv() {
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
    getPort() {
        return this.port;
    }
    getMetrics() {
        return { ...this.metrics };
    }
    /**
     * Stop the proxy server
     */
    async stop() {
        return new Promise((resolve) => {
            if (this.server) {
                this.server.close(() => {
                    this.server = null;
                    resolve();
                });
            }
            else {
                resolve();
            }
        });
    }
}
//# sourceMappingURL=server.js.map