import axios from 'axios';

export class DirectoryEnumerator {
  constructor() {
    this.commonPaths = [
      'admin', 'backup', 'config', 'db', 'debug', 'dev',
      'login', 'logs', 'private', 'test', 'tmp', 'upload'
    ];
  }

  async enumerate(baseUrl) {
    const issues = [];

    for (const path of this.commonPaths) {
      try {
        const url = new URL(path, baseUrl).href;
        const response = await axios.head(url);
        
        if (response.status === 200) {
          issues.push({
            type: 'Directory Enumeration',
            issue: `Found accessible path: ${path}`,
            fix: 'Restrict access to sensitive directories'
          });
        }
      } catch (error) {
        // Skip 404s and other errors
      }
    }

    return issues;
  }
}