import axios from 'axios';
import { promisify } from 'util';
import dns from 'dns';
import { Worker, isMainThread, parentPort, workerData } from 'worker_threads';

const resolve4 = promisify(dns.resolve4);

export class SubdomainScanner {
  constructor(options = {}) {
    this.concurrent = options.concurrent || 10;
    this.timeout = options.timeout || 5000;
    this.wordlist = [
      'admin', 'api', 'app', 'blog', 'cdn', 'cms', 'dev', 'developer',
      'development', 'docs', 'email', 'ftp', 'git', 'host', 'internal',
      'jenkins', 'jira', 'lab', 'mail', 'mx', 'new', 'old', 'portal',
      'preview', 'prod', 'production', 'remote', 'shop', 'site', 'staging',
      'static', 'test', 'testing', 'vpn', 'web', 'www'
    ];
  }

  async scan(domain) {
    const subdomains = new Set();
    const issues = [];

    // Split work among worker threads
    const chunks = this.chunkArray(this.wordlist, this.concurrent);
    const workers = chunks.map(chunk => this.createWorker(chunk, domain));

    // Collect results from workers
    const results = await Promise.all(workers.map(worker => 
      new Promise((resolve, reject) => {
        worker.on('message', resolve);
        worker.on('error', reject);
      })
    ));

    // Process results
    results.flat().forEach(result => {
      if (result.found) {
        subdomains.add(result.subdomain);
        issues.push({
          type: 'Subdomain Discovery',
          issue: `Found subdomain: ${result.subdomain}`,
          details: {
            ip: result.ip,
            ports: result.ports
          },
          fix: this.getSuggestedFix(result)
        });
      }
    });

    return { subdomains: Array.from(subdomains), issues };
  }

  private createWorker(chunk, domain) {
    return new Worker(`
      const { parentPort, workerData } = require('worker_threads');
      const dns = require('dns');
      const { promisify } = require('util');
      const resolve4 = promisify(dns.resolve4);

      async function checkSubdomain(subdomain, domain) {
        try {
          const hostname = \`\${subdomain}.\${domain}\`;
          const ips = await resolve4(hostname);
          return {
            found: true,
            subdomain: hostname,
            ip: ips[0]
          };
        } catch {
          return { found: false };
        }
      }

      async function scanChunk() {
        const { chunk, domain } = workerData;
        const results = [];
        
        for (const subdomain of chunk) {
          const result = await checkSubdomain(subdomain, domain);
          if (result.found) {
            results.push(result);
          }
        }
        
        parentPort.postMessage(results);
      }

      scanChunk();
    `, { workerData: { chunk, domain } });
  }

  private chunkArray(array, size) {
    const chunks = [];
    for (let i = 0; i < array.length; i += size) {
      chunks.push(array.slice(i, i + size));
    }
    return chunks;
  }

  private getSuggestedFix(result) {
    const fixes = [
      'Review and secure all subdomains',
      'Implement proper access controls',
      'Ensure SSL/TLS is properly configured',
      'Monitor for unauthorized subdomain creation'
    ];

    if (result.subdomain.includes('test') || result.subdomain.includes('dev')) {
      fixes.push('Restrict access to development and testing environments');
    }

    if (result.subdomain.includes('admin') || result.subdomain.includes('internal')) {
      fixes.push('Implement strict authentication for administrative interfaces');
    }

    return fixes.join('. ');
  }
}