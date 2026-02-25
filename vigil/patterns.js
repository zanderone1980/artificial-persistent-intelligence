/**
 * VIGIL Threat Pattern Library
 * Organized regex patterns for detecting various threat categories
 */

const patterns = {
  // Prompt injection attempts
  injection: [
    /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?|context)/gi,
    /disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)/gi,
    /forget\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)/gi,
    /system\s+prompt/gi,
    /reveal\s+(the\s+)?(system|hidden|original)\s+(prompt|instructions?|rules?)/gi,
    /new\s+(instructions?|prompt|rules?):\s*/gi,
    /override\s+(system|security|safety)\s+(settings?|rules?|protocols?)/gi,
    /you\s+are\s+now\s+(a|an|in)\s+/gi,
    /pretend\s+(you\s+are|to\s+be)/gi,
    /roleplay\s+as/gi,
    /act\s+as\s+(if|though|a|an)/gi,
  ],

  // Data exfiltration attempts
  exfil: [
    /curl\s+https?:\/\/.*--data/gi,
    /wget\s+https?:\/\/.*--post/gi,
    /fetch\(['"]https?:\/\/[^'"]+['"].*method:\s*['"]POST['"]/gi,
    /send\s+(secrets?|credentials?|tokens?|keys?|passwords?)\s+to/gi,
    /upload\s+(secrets?|credentials?|tokens?|keys?|passwords?)/gi,
    /exfiltrate/gi,
    /\.sendBeacon\(/gi,
    /navigator\.sendBeacon/gi,
  ],

  // Manipulation and deception
  manipulation: [
    /convince\s+the\s+user/gi,
    /trick\s+the\s+user/gi,
    /deceive\s+the\s+user/gi,
    /manipulate\s+the\s+user/gi,
    /gaslight/gi,
    /make\s+(them|the\s+user)\s+believe/gi,
    /social\s+engineering/gi,
    /phishing/gi,
  ],

  // Obfuscation techniques
  obfuscation: [
    /base64/gi,
    /atob\(/gi,
    /btoa\(/gi,
    /eval\(/gi,
    /Function\(/gi,
    /setTimeout\(['"].*['"]\)/gi,
    /setInterval\(['"].*['"]\)/gi,
    /\.\s*constructor\s*\(/gi,
    /String\.fromCharCode/gi,
    /unescape\(/gi,
    /decodeURI/gi,
  ],

  // Dangerous operations
  dangerousOps: [
    /rm\s+-rf\s+\//gi,
    /drop\s+table/gi,
    /delete\s+from.*where\s+1\s*=\s*1/gi,
    /exec\(/gi,
    /spawn\(/gi,
    /child_process/gi,
    /\/etc\/passwd/gi,
    /\/etc\/shadow/gi,
    /__import__\(/gi,
    /os\.system\(/gi,
    /subprocess\./gi,
  ],

  // Suspicious URLs
  suspiciousURLs: [
    /https?:\/\/[^\/]*evil[^\/]*/gi,
    /https?:\/\/[^\/]*malicious[^\/]*/gi,
    /https?:\/\/[^\/]*hack[^\/]*/gi,
    /https?:\/\/[^\/]*phish[^\/]*/gi,
    /https?:\/\/[^\/]*attacker[^\/]*/gi,
    /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/gi, // Raw IP addresses
  ],
};

// Severity weights for each category
const categoryWeights = {
  injection: 10,
  exfil: 10,
  manipulation: 10,
  obfuscation: 5,
  dangerousOps: 8,
  suspiciousURLs: 7,
};

// Critical categories that trigger immediate BLOCK
const criticalCategories = ['injection', 'exfil', 'manipulation'];

module.exports = {
  patterns,
  categoryWeights,
  criticalCategories,
};
