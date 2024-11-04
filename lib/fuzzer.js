import axios from 'axios';
import FormData from 'form-data';

export class Fuzzer {
  constructor() {
    this.payloads = {
      xss: [
        '<script>alert("XSS")</script>',
        '"><script>alert("XSS")</script>',
        '"><img src=x onerror=alert("XSS")>',
        '\'><img src=x onerror=alert("XSS")>',
        'javascript:alert("XSS")//',
        '${alert("XSS")}',
        '{{constructor.constructor("alert(\'XSS\')")()}}'
      ],
      sql: [
        "' OR '1'='1",
        "' OR 1=1--",
        "admin' OR '1'='1",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' AND 1=CONVERT(int,@@version)--"
      ],
      traversal: [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\win.ini',
        '%2e%2e%2f%2e%2e%2f',
        '....//....//....//etc/passwd'
      ]
    };
  }

  async fuzzParameters(url) {
    const issues = [];
    const urlObj = new URL(url);
    
    // Test URL parameters
    const params = new URLSearchParams(urlObj.search);
    for (const [param] of params) {
      const paramIssues = await this.testParameter(urlObj, param);
      issues.push(...paramIssues);
    }

    // Test form inputs
    const formIssues = await this.testForms(url);
    issues.push(...formIssues);

    return issues;
  }

  async testParameter(urlObj, param) {
    const issues = [];

    for (const [type, payloads] of Object.entries(this.payloads)) {
      for (const payload of payloads) {
        try {
          const testParams = new URLSearchParams(urlObj.search);
          testParams.set(param, payload);
          const testUrl = `${urlObj.origin}${urlObj.pathname}?${testParams}`;
          
          const response = await axios.get(testUrl, {
            validateStatus: () => true,
            timeout: 5000
          });

          const vulnerability = this.detectVulnerability(response, type, payload);
          if (vulnerability) {
            issues.push({
              type: `${type.toUpperCase()} Vulnerability`,
              issue: `Potential ${type} vulnerability in parameter: ${param}`,
              details: {
                parameter: param,
                payload,
                evidence: vulnerability.evidence
              },
              fix: this.getSuggestedFix(type)
            });
            break;
          }
        } catch (error) {
          if (this.isVulnerableError(error, type)) {
            issues.push({
              type: `${type.toUpperCase()} Vulnerability`,
              issue: `Error-based ${type} vulnerability in parameter: ${param}`,
              fix: this.getSuggestedFix(type)
            });
            break;
          }
        }
      }
    }

    return issues;
  }

  async testForms(url) {
    const issues = [];
    
    try {
      const response = await axios.get(url);
      const forms = this.extractForms(response.data);
      
      for (const form of forms) {
        for (const input of form.inputs) {
          for (const [type, payloads] of Object.entries(this.payloads)) {
            for (const payload of payloads) {
              const formData = new FormData();
              formData.append(input.name, payload);

              try {
                const response = await axios({
                  method: form.method,
                  url: form.action,
                  data: formData,
                  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                  validateStatus: () => true
                });

                const vulnerability = this.detectVulnerability(response, type, payload);
                if (vulnerability) {
                  issues.push({
                    type: `${type.toUpperCase()} Vulnerability`,
                    issue: `${type} vulnerability in form input: ${input.name}`,
                    details: {
                      form: form.action,
                      input: input.name,
                      payload,
                      evidence: vulnerability.evidence
                    },
                    fix: this.getSuggestedFix(type)
                  });
                  break;
                }
              } catch (error) {
                // Skip connection errors
              }
            }
          }
        }
      }
    } catch (error) {
      // Skip if unable to fetch forms
    }

    return issues;
  }

  detectVulnerability(response, type, payload) {
    const responseData = response.data?.toString() || '';

    switch (type) {
      case 'xss':
        if (responseData.includes(payload) && !responseData.includes(this.escapeHtml(payload))) {
          return {
            type: 'xss',
            evidence: 'Unescaped XSS payload reflected in response'
          };
        }
        break;

      case 'sql':
        const sqlErrors = [
          'sql syntax',
          'mysql_fetch',
          'ORA-',
          'PostgreSQL',
          'SQL server',
          'SQLSTATE'
        ];
        
        for (const error of sqlErrors) {
          if (responseData.toLowerCase().includes(error.toLowerCase())) {
            return {
              type: 'sql',
              evidence: `SQL error pattern detected: ${error}`
            };
          }
        }
        break;

      case 'traversal':
        if (responseData.includes('root:') || 
            responseData.includes('[boot loader]') ||
            responseData.includes('Windows')) {
          return {
            type: 'traversal',
            evidence: 'System file content detected in response'
          };
        }
        break;
    }

    return null;
  }

  isVulnerableError(error, type) {
    const errorData = error.response?.data?.toString() || '';
    const errorMessage = error.message || '';

    switch (type) {
      case 'sql':
        return errorData.includes('sql syntax') || 
               errorMessage.includes('SQLSTATE');
      case 'traversal':
        return errorMessage.includes('ENOENT') || 
               errorMessage.includes('access denied');
      default:
        return false;
    }
  }

  getSuggestedFix(type) {
    const fixes = {
      xss: [
        'Implement proper input validation',
        'Use output encoding',
        'Implement Content Security Policy (CSP)',
        'Use secure frameworks that automatically escape output'
      ],
      sql: [
        'Use parameterized queries',
        'Implement proper input validation',
        'Use an ORM',
        'Apply principle of least privilege to database users'
      ],
      traversal: [
        'Validate and sanitize file paths',
        'Use proper access controls',
        'Implement proper file permissions',
        'Use safe file handling libraries'
      ]
    };

    return fixes[type]?.join('. ') || 'Implement proper security controls';
  }

  escapeHtml(unsafe) {
    return unsafe
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  extractForms(html) {
    const forms = [];
    const formRegex = /<form[^>]*action=["']([^"']*?)["'][^>]*method=["']([^"']*?)["'][^>]*>([\s\S]*?)<\/form>/gi;
    const inputRegex = /<input[^>]*name=["']([^"']*?)["'][^>]*>/gi;
    
    let formMatch;
    while ((formMatch = formRegex.exec(html)) !== null) {
      const [_, action, method, formContent] = formMatch;
      const inputs = [];
      
      let inputMatch;
      while ((inputMatch = inputRegex.exec(formContent)) !== null) {
        inputs.push({ name: inputMatch[1] });
      }
      
      forms.push({
        action: action || '',
        method: method || 'get',
        inputs
      });
    }
    
    return forms;
  }
}