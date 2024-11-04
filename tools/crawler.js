import axios from 'axios';
import * as cheerio from 'cheerio';
import { URL } from 'url';
import { CookieJar } from 'tough-cookie';
import { wrapper } from 'axios-cookiejar-support';

export class WebCrawler {
  constructor(options = {}) {
    this.visited = new Set();
    this.queue = [];
    this.baseUrl = '';
    this.maxDepth = options.maxDepth || 3;
    this.maxPages = options.maxPages || 100;
    this.cookieJar = new CookieJar();
    this.client = wrapper(axios.create({ jar: this.cookieJar }));
    this.auth = options.auth || null;
    this.forms = [];
    this.endpoints = [];
    this.assets = [];
  }

  async login() {
    if (!this.auth) return;

    try {
      const { loginUrl, credentials } = this.auth;
      await this.client.post(loginUrl, credentials);
      console.log('Successfully authenticated');
    } catch (error) {
      console.error('Authentication failed:', error.message);
    }
  }

  isValidUrl(url) {
    try {
      const parsedUrl = new URL(url, this.baseUrl);
      return parsedUrl.origin === new URL(this.baseUrl).origin;
    } catch {
      return false;
    }
  }

  async extractLinks($, currentUrl) {
    const links = new Set();
    
    $('a[href]').each((_, element) => {
      const href = $(element).attr('href');
      if (href) {
        try {
          const absoluteUrl = new URL(href, currentUrl).href;
          if (this.isValidUrl(absoluteUrl)) {
            links.add(absoluteUrl);
          }
        } catch (e) {
          // Invalid URL, skip
        }
      }
    });

    return Array.from(links);
  }

  async extractForms($, currentUrl) {
    $('form').each((_, element) => {
      const $form = $(element);
      const method = ($form.attr('method') || 'get').toLowerCase();
      const action = new URL($form.attr('action') || '', currentUrl).href;
      
      const inputs = [];
      $form.find('input, select, textarea').each((_, input) => {
        const $input = $(input);
        inputs.push({
          name: $input.attr('name'),
          type: $input.attr('type') || 'text',
          required: $input.prop('required') || false
        });
      });

      this.forms.push({
        url: action,
        method,
        inputs
      });
    });
  }

  async extractAssets($, currentUrl) {
    // Extract scripts
    $('script[src]').each((_, element) => {
      const src = $(element).attr('src');
      if (src) {
        try {
          const absoluteUrl = new URL(src, currentUrl).href;
          this.assets.push({ type: 'script', url: absoluteUrl });
        } catch (e) {}
      }
    });

    // Extract stylesheets
    $('link[rel="stylesheet"]').each((_, element) => {
      const href = $(element).attr('href');
      if (href) {
        try {
          const absoluteUrl = new URL(href, currentUrl).href;
          this.assets.push({ type: 'stylesheet', url: absoluteUrl });
        } catch (e) {}
      }
    });

    // Extract images
    $('img[src]').each((_, element) => {
      const src = $(element).attr('src');
      if (src) {
        try {
          const absoluteUrl = new URL(src, currentUrl).href;
          this.assets.push({ type: 'image', url: absoluteUrl });
        } catch (e) {}
      }
    });
  }

  async crawl(startUrl) {
    this.baseUrl = startUrl;
    this.queue.push({ url: startUrl, depth: 0 });

    if (this.auth) {
      await this.login();
    }

    while (this.queue.length > 0 && this.visited.size < this.maxPages) {
      const { url, depth } = this.queue.shift();
      
      if (this.visited.has(url) || depth > this.maxDepth) {
        continue;
      }

      try {
        console.log(`Crawling: ${url}`);
        const response = await this.client.get(url);
        this.visited.add(url);
        this.endpoints.push({
          url,
          method: 'GET',
          statusCode: response.status,
          contentType: response.headers['content-type']
        });

        const $ = cheerio.load(response.data);
        
        // Extract and process various elements
        const links = await this.extractLinks($, url);
        await this.extractForms($, url);
        await this.extractAssets($, url);

        // Add new links to the queue
        links.forEach(link => {
          if (!this.visited.has(link)) {
            this.queue.push({ url: link, depth: depth + 1 });
          }
        });

      } catch (error) {
        console.error(`Error crawling ${url}:`, error.message);
      }
    }

    return {
      visitedUrls: Array.from(this.visited),
      forms: this.forms,
      endpoints: this.endpoints,
      assets: this.assets
    };
  }
}

export async function analyzeCrawlResults(results) {
  const issues = [];

  // Analyze forms for security
  results.forms.forEach(form => {
    if (form.method === 'get' && form.inputs.some(input => 
      ['password', 'token', 'secret'].includes(input.name?.toLowerCase()))) {
      issues.push({
        type: 'Form Security',
        issue: `Sensitive data being sent via GET method at ${form.url}`,
        fix: 'Use POST method for forms handling sensitive data'
      });
    }

    // Check for CSRF protection
    if (form.method === 'post' && 
        !form.inputs.some(input => input.name?.toLowerCase().includes('csrf'))) {
      issues.push({
        type: 'Form Security',
        issue: `Missing CSRF protection in form at ${form.url}`,
        fix: 'Implement CSRF tokens for all POST forms'
      });
    }
  });

  // Analyze endpoints for security headers
  results.endpoints.forEach(endpoint => {
    if (endpoint.contentType?.includes('html')) {
      issues.push({
        type: 'Content Security',
        issue: `Endpoint ${endpoint.url} should be analyzed for security headers`,
        fix: 'Implement security headers (HSTS, CSP, X-Frame-Options, etc.)'
      });
    }
  });

  // Analyze assets for security
  results.assets.forEach(asset => {
    if (asset.type === 'script' && !asset.url.startsWith('https://')) {
      issues.push({
        type: 'Asset Security',
        issue: `Insecure script source: ${asset.url}`,
        fix: 'Load all scripts over HTTPS'
      });
    }
  });

  return issues;
}