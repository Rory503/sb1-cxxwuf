import Wappalyzer from 'wappalyzer-core';

export async function detectTechnologies(url, html, headers) {
  const wappalyzer = new Wappalyzer();
  
  const results = await wappalyzer.analyze({
    url,
    html,
    headers
  });

  const technologies = results.technologies.map(tech => ({
    name: tech.name,
    version: tech.version,
    categories: tech.categories
  }));

  const issues = [];
  
  technologies.forEach(tech => {
    if (tech.version) {
      // Check for known vulnerable versions
      issues.push({
        type: 'Technology Stack',
        issue: `Detected ${tech.name} version ${tech.version}`,
        fix: 'Keep all technologies updated to their latest stable versions'
      });
    }
  });

  return { technologies, issues };
}