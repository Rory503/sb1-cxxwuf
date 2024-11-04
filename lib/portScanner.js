import portscanner from 'node-port-scanner';

export class PortScanner {
  constructor() {
    this.commonPorts = [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5432, 8080];
  }

  async scan(hostname) {
    const issues = [];
    
    try {
      const results = await portscanner(hostname, this.commonPorts);
      
      results.open.forEach(port => {
        issues.push({
          type: 'Open Port',
          issue: `Port ${port} is open`,
          fix: 'Close unnecessary ports and secure required ones with proper firewall rules'
        });
      });
    } catch (error) {
      issues.push({
        type: 'Port Scanning',
        issue: 'Unable to complete port scan',
        fix: 'Ensure host is accessible and firewall rules allow scanning'
      });
    }

    return issues;
  }
}