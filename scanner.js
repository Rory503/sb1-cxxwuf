import axios from 'axios';
import chalk from 'chalk';
import { program } from 'commander';
import * as cheerio from 'cheerio';
import sslChecker from 'ssl-checker';
import portscanner from 'node-port-scanner';

// Initialize CLI
program
  .version('1.0.0')
  .description('Website Security Scanner')
  .argument('<url>', 'URL to scan')
  .option('-p, --ports', 'Enable port scanning')
  .parse(process.argv);

const url = program.args[0];
const options = program.opts();

if (!url) {
  console.error(chalk.red('Please provide a URL to scan'));
  process.exit(1);
}

// SQL Injection payloads
const SQL_PAYLOADS = [
  "' OR '1'='1",
  "' OR 1=1--",
  "admin' OR '1'='1"
];

// XSS payloads
const XSS_PAYLOADS = [
  '<script>alert("XSS")</script>',
  '"><img src=x onerror=alert("XSS")>'
];

async function testSQLInjection(url) {
  const issues = [];
  const urlObj = new URL(url);
  const params = new URLSearchParams(urlObj.search);

  for (const [param] of params) {
    for (const payload of SQL_PAYLOADS) {
      try {
        const testParams = new URLSearchParams(urlObj.search);
        testParams.set(param, payload);
        const testUrl = `${urlObj.origin}${urlObj.pathname}?${testParams}`;
        
        const response = await axios.get(testUrl);
        if (response.data.includes('error in your SQL')) {
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
  
  return issues;
}

async function testXSS(url) {
  const issues = [];
  const urlObj = new URL(url);
  const params = new URLSearchParams(urlObj.search);

  for (const [param] of params) {
    for (const payload of XSS_PAYLOADS) {
      try {
        const testParams = new URLSearchParams(urlObj.search);
        testParams.set(param, payload);
        const testUrl = `${urlObj.origin}${urlObj.pathname}?${testParams}`;
        
        const response = await axios.get(testUrl);
        if (response.data.includes(payload)) {
          issues.push({
            type: 'XSS',
            issue: `Potential XSS vulnerability in parameter: ${param}`,
            fix: 'Implement proper input sanitization and output encoding'
          });
          break;
        }
      } catch (error) {
        // Skip errors
      }
    }
  }
  
  return issues;
}

async function checkSecurity(url) {
  const issues = [];
  const hostname = new URL(url).hostname;

  try {
    // Basic security checks
    const response = await axios.get(url);
    const headers = response.headers;

    // Check security headers
    const requiredHeaders = {
      'strict-transport-security': 'Missing HSTS header',
      'x-content-type-options': 'Missing X-Content-Type-Options header',
      'x-frame-options': 'Missing X-Frame-Options header',
      'content-security-policy': 'Missing Content Security Policy'
    };

    Object.entries(requiredHeaders).forEach(([header, message]) => {
      if (!headers[header]) {
        issues.push({
          type: 'Security Headers',
          issue: message,
          fix: `Add ${header} header`
        });
      }
    });

    // Check SSL
    try {
      const sslInfo = await sslChecker(hostname);
      if (sslInfo.daysRemaining < 30) {
        issues.push({
          type: 'SSL Security',
          issue: `SSL certificate expires in ${sslInfo.daysRemaining} days`,
          fix: 'Renew SSL certificate soon'
        });
      }
    } catch (error) {
      issues.push({
        type: 'SSL Security',
        issue: 'Unable to verify SSL configuration',
        fix: 'Ensure SSL is properly configured'
      });
    }

    // Port scanning
    if (options.ports) {
      try {
        const ports = await portscanner(hostname, [21, 22, 23, 25, 80, 443, 8080]);
        ports.open.forEach(port => {
          issues.push({
            type: 'Port Security',
            issue: `Port ${port} is open`,
            fix: 'Close unnecessary ports and secure required ones'
          });
        });
      } catch (error) {
        console.error('Port scanning error:', error.message);
      }
    }

    // Test for SQL Injection
    const sqlIssues = await testSQLInjection(url);
    issues.push(...sqlIssues);

    // Test for XSS
    const xssIssues = await testXSS(url);
    issues.push(...xssIssues);

    return issues;
  } catch (error) {
    throw new Error(`Unable to connect to ${url}: ${error.message}`);
  }
}

async function scanWebsite(targetUrl) {
  console.log(chalk.blue(`🔍 Starting security scan of ${targetUrl}\n`));
  
  try {
    const issues = await checkSecurity(targetUrl);

    console.log(chalk.yellow('\n📊 Scan Results:\n'));

    if (issues.length === 0) {
      console.log(chalk.green('✅ No security issues found!'));
    } else {
      const groupedIssues = issues.reduce((acc, issue) => {
        if (!acc[issue.type]) acc[issue.type] = [];
        acc[issue.type].push(issue);
        return acc;
      }, {});

      Object.entries(groupedIssues).forEach(([type, typeIssues]) => {
        console.log(chalk.red(`\n🔍 ${type} Issues:`));
        typeIssues.forEach((issue, index) => {
          console.log(chalk.yellow(`\n   ${index + 1}. Issue: ${issue.issue}`));
          if (issue.fix) {
            console.log(chalk.green(`      Fix: ${issue.fix}`));
          }
        });
      });
    }

    const score = Math.max(0, Math.round((1 - issues.length / 20) * 100));
    console.log(chalk.blue('\n📈 Security Score:'), 
      chalk.yellow(`${score}%`));

  } catch (error) {
    console.error(chalk.red('\n❌ Error during scan:'), error.message);
    process.exit(1);
  }
}

// Run the scanner
scanWebsite(url);