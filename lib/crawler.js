import axios from 'axios';
import * as cheerio from 'cheerio';
import { URL } from 'url';

const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

export class WebCrawler {
  constructor(options = {}) {
    this.visited = new Set();
    this.maxPages = options.maxPages || 100;
    this.delayMs = options.delayMs || 1000;
    this.maxDepth = options.maxDepth || 3;
    this.userAgent = options.userAgent || 'Mozilla/5.0 WebScanner/1.0';
    this.timeout = options.timeout || 10000;
    this.client = axios.create({
      timeout: this.timeout,
      headers: {
        'User-Agent': this.userAgent
      }
    });
    
    // XSS test payloads
    this.xssPayloads = [
      '<script>alert("XSS")</script>',
      '"><script>alert("XSS")</script>',
      '"><img src=x onerror=alert("XSS")>',
      '\'><img src=x onerror=alert("XSS")>',
      'javascript:alert("XSS")//',
      '${alert("XSS")}',
      '{{constructor.constructor("alert(\'XSS\')")()}}'
    ];
  }

  async crawl(startUrl, maxDepth = 3) {
    this.maxDepth = maxDepth;
    const results = {
      urls: new Set(),
      forms: [],
      issues: [],
      assets: new Set(),
      endpoints: new Set()
    };

    try {
      await this.crawlPage(startUrl, results, 0);
      console.log(`Crawling completed. Visited ${results.urls.size} pages.`);
    } catch (error) {
      console.error('Crawling error:', error.message);
      results.issues.push({
        type: 'Crawling Error',
        url: startUrl,
        error: error.message
      });
    }

    return results;
  }

  async crawlPage(url, results, currentDepth) {
    if (currentDepth >= this.maxDepth || 
        results.urls.size >= this.maxPages || 
        results.urls.has(url)) {
      return;
    }

    await delay(this.delayMs);

    try {
      console.log(`Crawling (depth ${currentDepth}): ${url}`);
      const response = await this.client.get(url);
      results.urls.add(url);

      results.endpoints.add({
        url,
        status: response.status,
        contentType: response.headers['content-type'],
        headers: response.headers
      });

      const $ = cheerio.load(response.data);
      
      // Extract and analyze forms with XSS testing
      await this.extractAndTestForms($, url, results);

      // Extract and store assets
      await this.extractAssets($, url, results);

      // Extract and follow links with depth tracking
      const links = await this.extractLinks($, url);
      
      // Process links in sequence with depth tracking
      for (const link of links) {
        if (!results.urls.has(link)) {
          await this.crawlPage(link, results, currentDepth + 1);
        }
      }

    } catch (error) {
      console.error(`Error crawling ${url}:`, error.message);
      results.issues.push({
        type: 'Crawling Error',
        url,
        error: error.message
      });
    }
  }

  async extractAndTestForms($, baseUrl, results) {
    const forms = $('form');
    
    forms.each(async (_, form) => {
      const $form = $(form);
      const action = new URL($form.attr('action') || '', baseUrl).href;
      const method = ($form.attr('method') || 'get').toLowerCase();
      
      const formData = {
        action,
        method,
        inputs: []
      };

      // Extract form inputs
      $form.find('input, select, textarea').each((_, input) => {
        const $input = $(input);
        formData.inputs.push({
          name: $input.attr('name'),
          type: $input.attr('type') || 'text',
          required: $input.prop('required') || false
        });
      });

      results.forms.push(formData);

      // Perform security checks
      await this.testFormSecurity(formData, results);
    });
  }

  async testFormSecurity(form, results) {
    // CSRF check
    if (form.method === 'post' && 
        !form.inputs.some(input => input.name?.toLowerCase().includes('csrf'))) {
      results.issues.push({
        type: 'Form Security',
        url: form.action,
        issue: 'Missing CSRF protection',
        fix: 'Implement CSRF tokens for all POST forms'
      });
    }

    // Sensitive data in GET
    if (form.method === 'get' && form.inputs.some(input => 
      ['password', 'token', 'secret'].includes(input.name?.toLowerCase()))) {
      results.issues.push({
        type: 'Form Security',
        url: form.action,
        issue: 'Sensitive data being sent via GET method',
        fix: 'Use POST method for forms handling sensitive data'
      });
    }

    // XSS Testing
    await this.testXSSVulnerability(form, results);
  }

  async testXSSVulnerability(form, results) {
    for (const input of form.inputs) {
      if (!input.name) continue;

      for (const payload of this.xssPayloads) {
        try {
          const formData = new URLSearchParams();
          formData.append(input.name, payload);

          const response = await this.client({
            method: form.method,
            url: form.action,
            data: formData,
            headers: { 
              'Content-Type': 'application/x-www-form-urlencoded',
              'Accept': 'text/html,application/xhtml+xml'
            },
            validateStatus: () => true
          });

          if (response.data.includes(payload) && !response.data.includes(this.escapeHtml(payload))) {
            results.issues.push({
              type: 'XSS Vulnerability',
              url: form.action,
              issue: `Potential XSS vulnerability in ${input.name} field`,
              payload,
              fix: 'Implement proper input sanitization and output encoding'
            });
            break; // Found vulnerability, no need to test more payloads
          }
        } catch (error) {
          console.error(`XSS test failed for ${form.action}: ${error.message}`);
        }
      }
    }
  }

  escapeHtml(unsafe) {
    return unsafe
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  async extractLinks($, baseUrl) {
    const links = new Set();
    
    $('a[href]').each((_, element) => {
      const href = $(element).attr('href');
      if (href) {
        try {
          const absoluteUrl = new URL(href, baseUrl).href;
          if (new URL(absoluteUrl).origin === new URL(baseUrl).origin) {
            links.add(absoluteUrl);
          }
        } catch (e) {
          // Skip invalid URLs
        }
      }
    });

    return Array.from(links);
  }

  async extractAssets($, baseUrl, results) {
    // Extract scripts
    $('script[src]').each((_, element) => {
      try {
        const src = new URL($(element).attr('src'), baseUrl).href;
        results.assets.add({ type: 'script', url: src });
      } catch (e) {}
    });

    // Extract stylesheets
    $('link[rel="stylesheet"]').each((_, element) => {
      try {
        const href = new URL($(element).attr('href'), baseUrl).href;
        results.assets.add({ type: 'stylesheet', url: href });
      } catch (e) {}
    });

    // Extract images
    $('img[src]').each((_, element) => {
      try {
        const src = new URL($(element).attr('src'), baseUrl).href;
        results.assets.add({ type: 'image', url: src });
      } catch (e) {}
    });
  }

  async analyzeCrawlResults(results) {
    const issues = [...results.issues];

    results.assets.forEach(asset => {
      if (asset.type === 'script' && !asset.url.startsWith('https://')) {
        issues.push({
          type: 'Asset Security',
          url: asset.url,
          issue: 'Insecure script source',
          fix: 'Load all scripts over HTTPS'
        });
      }
    });

    results.endpoints.forEach(endpoint => {
      const headers = endpoint.headers || {};
      const securityHeaders = {
        'strict-transport-security': 'Missing HSTS header',
        'x-content-type-options': 'Missing X-Content-Type-Options header',
        'x-frame-options': 'Missing X-Frame-Options header',
        'content-security-policy': 'Missing Content Security Policy'
      };

      Object.entries(securityHeaders).forEach(([header, message]) => {
        if (!headers[header]) {
          issues.push({
            type: 'Security Headers',
            url: endpoint.url,
            issue: message,
            fix: `Add ${header} header`
          });
        }
      });
    });

    return issues;
  }
}