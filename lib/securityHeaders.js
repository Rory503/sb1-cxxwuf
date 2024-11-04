import axios from 'axios';

export class SecurityHeaderChecker {
  constructor() {
    this.requiredHeaders = {
      'strict-transport-security': {
        message: 'Missing HSTS header',
        fix: 'Add Strict-Transport-Security header with appropriate max-age'
      },
      'x-content-type-options': {
        message: 'Missing X-Content-Type-Options header',
        fix: 'Add X-Content-Type-Options: nosniff'
      },
      'x-frame-options': {
        message: 'Missing X-Frame-Options header',
        fix: 'Add X-Frame-Options: DENY or SAMEORIGIN'
      },
      'content-security-policy': {
        message: 'Missing Content Security Policy',
        fix: 'Implement a strict Content Security Policy'
      },
      'x-xss-protection': {
        message: 'Missing XSS Protection header',
        fix: 'Add X-XSS-Protection: 1; mode=block'
      },
      'referrer-policy': {
        message: 'Missing Referrer Policy',
        fix: 'Add Referrer-Policy: strict-origin-when-cross-origin'
      }
    };
  }

  async check(url) {
    const issues = [];
    
    try {
      const response = await axios.get(url, {
        validateStatus: () => true,
        maxRedirects: 5
      });

      const headers = response.headers;

      Object.entries(this.requiredHeaders).forEach(([header, info]) => {
        if (!headers[header.toLowerCase()]) {
          issues.push({
            type: 'Security Headers',
            issue: info.message,
            fix: info.fix
          });
        }
      });

      // Check for insecure headers
      if (headers['server']) {
        issues.push({
          type: 'Security Headers',
          issue: 'Server header reveals version information',
          fix: 'Remove or customize Server header to hide version details'
        });
      }

      if (headers['x-powered-by']) {
        issues.push({
          type: 'Security Headers',
          issue: 'X-Powered-By header reveals technology stack',
          fix: 'Remove X-Powered-By header'
        });
      }

    } catch (error) {
      if (error.code === 'ECONNREFUSED') {
        issues.push({
          type: 'Security Headers',
          issue: 'Connection refused',
          fix: 'Ensure the server is running and accessible'
        });
      } else if (error.code === 'ETIMEDOUT') {
        issues.push({
          type: 'Security Headers',
          issue: 'Connection timed out',
          fix: 'Check server response time and network connectivity'
        });
      } else {
        issues.push({
          type: 'Security Headers',
          issue: `Error: ${error.message}`,
          fix: 'Verify server configuration and accessibility'
        });
      }
    }

    return issues;
  }
}