import axios from 'axios';
import { readFileSync } from 'fs';
import { join } from 'path';
import { fileURLToPath } from 'url';

const __dirname = fileURLToPath(new URL('.', import.meta.url));

export class DirectoryEnumerator {
  constructor(options = {}) {
    this.client = axios.create({
      validateStatus: () => true,
      timeout: options.timeout || 5000
    });
    this.wordlist = this.loadWordlist(options.wordlist);
    this.extensions = options.extensions || [
      '', '.php', '.asp', '.aspx', '.jsp', '.html', '.js', '.txt', '.git', '.env',
      '.bak', '.backup', '.swp', '.old', '.db', '.sql', '.conf', '.config'
    ];
  }

  private loadWordlist(customPath) {
    try {
      const path = customPath || join(__dirname, 'wordlists', 'common.txt');
      return readFileSync(path, 'utf8').split('\n').filter(Boolean);
    } catch {
      // Fallback to basic wordlist if file not found
      return [
        'admin', 'api', 'backup', 'config', 'dashboard', 'db', 'debug',
        'dev', 'development', 'files', 'images', 'img', 'login', 'logs',
        'private', 'prod', 'production', 'secret', 'secure', 'security',
        'staff', 'staging', 'test', 'tmp', 'upload', 'uploads'
      ];
    }
  }

  async enumerate(baseUrl) {
    const findings = [];
    const seen = new Set();

    for (const word of this.wordlist) {
      for (const ext of this.extensions) {
        const path = `${word}${ext}`;
        if (seen.has(path)) continue;
        seen.add(path);

        const url = new URL(path, baseUrl).href;
        try {
          const response = await this.client.head(url);
          const status = response.status;

          if (status !== 404) {
            const finding = {
              url,
              status,
              size: response.headers['content-length'],
              type: response.headers['content-type']
            };

            findings.push({
              type: 'Directory Enumeration',
              issue: `Found: ${url} (Status: ${status})`,
              details: finding,
              fix: this.getSuggestedFix(finding)
            });
          }
        } catch (error) {
          // Skip connection errors
        }
      }
    }

    return findings;
  }

  private getSuggestedFix(finding) {
    const { url, status, type } = finding;

    if (url.includes('.git') || url.includes('.env')) {
      return 'Remove sensitive version control and configuration files';
    }

    if (url.includes('backup') || url.includes('.bak')) {
      return 'Remove backup files from public access';
    }

    if (status === 200 && type?.includes('text/plain')) {
      return 'Protect sensitive text files from public access';
    }

    return 'Review access controls and implement proper authentication';
  }
}