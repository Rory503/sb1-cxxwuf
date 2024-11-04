import sslChecker from 'ssl-checker';

export class SSLChecker {
  async check(hostname) {
    const issues = [];
    
    try {
      const sslInfo = await sslChecker(hostname);

      if (sslInfo.daysRemaining < 30) {
        issues.push({
          type: 'SSL Security',
          issue: `SSL certificate expires in ${sslInfo.daysRemaining} days`,
          fix: 'Renew SSL certificate soon'
        });
      }

      if (sslInfo.protocol !== 'TLSv1.3' && sslInfo.protocol !== 'TLSv1.2') {
        issues.push({
          type: 'SSL Security',
          issue: 'Outdated SSL/TLS protocol version',
          fix: 'Upgrade to TLS 1.2 or 1.3'
        });
      }
    } catch (error) {
      issues.push({
        type: 'SSL Security',
        issue: 'Unable to verify SSL configuration',
        fix: 'Ensure SSL is properly configured'
      });
    }

    return issues;
  }
}