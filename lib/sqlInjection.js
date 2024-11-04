import axios from 'axios';
import FormData from 'form-data';

const SQL_PAYLOADS = [
  "' OR '1'='1",
  "' OR 1=1--",
  "admin' OR '1'='1",
  "' AND 1=1--",
  "'; WAITFOR DELAY '0:0:5'--"
];

export async function sqlInjectionTest(url) {
  const issues = [];
  const urlObj = new URL(url);
  
  try {
    // Test GET parameters
    const params = new URLSearchParams(urlObj.search);
    for (const [param] of params) {
      for (const payload of SQL_PAYLOADS) {
        const testParams = new URLSearchParams(urlObj.search);
        testParams.set(param, payload);
        const testUrl = `${urlObj.origin}${urlObj.pathname}?${testParams}`;
        
        try {
          const response = await axios.get(testUrl);
          if (detectSQLInjection(response.data)) {
            issues.push({
              type: 'SQL Injection',
              issue: `Potential SQL injection in parameter: ${param}`,
              fix: 'Use parameterized queries and input validation'
            });
            break;
          }
        } catch (error) {
          // Skip errors
        }
      }
    }
  } catch (error) {
    console.error('SQL Injection test error:', error.message);
  }
  
  return issues;
}

function detectSQLInjection(response) {
  const errorPatterns = [
    'sql syntax',
    'mysql_fetch',
    'ORA-',
    'PostgreSQL',
    'SQL server',
    'SQLSTATE'
  ];
  
  const responseStr = String(response).toLowerCase();
  return errorPatterns.some(pattern => responseStr.includes(pattern.toLowerCase()));
}