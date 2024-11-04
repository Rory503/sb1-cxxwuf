import { ZapClient } from 'zaproxy';

export async function zapScan(url) {
  const issues = [];
  const zap = new ZapClient({
    apiKey: process.env.ZAP_API_KEY || '',
    proxy: {
      host: 'localhost',
      port: 8080
    }
  });

  try {
    // Spider scan
    await zap.spider.scan(url);
    
    // Active scan
    await zap.ascan.scan(url);
    
    // Get alerts
    const alerts = await zap.alert.alerts(url);
    
    alerts.forEach(alert => {
      issues.push({
        type: 'ZAP Security',
        issue: `${alert.risk} - ${alert.name}`,
        fix: alert.solution
      });
    });
  } catch (error) {
    issues.push({
      type: 'ZAP Security',
      issue: 'Unable to complete ZAP scan',
      fix: 'Ensure ZAP proxy is running and configured correctly'
    });
  }

  return issues;
}