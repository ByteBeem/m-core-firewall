const { 
  logRequestAsync,
  blockIP,
  unblockIP,
  detectSQLInjection,
  detectXSS,
  detectCommandInjection,
  detectFilePathTraversal,
  checkCSRF,
  rateLimit,  
  checkFileInjections,
  checkMaliciousIP,
  checkHoneypot,
  detectMaliciousUserAgent,
  sanitizeRequest,
  detectSQLMap,
  setCSPHeaders 
} = require('./utils');


function applyRules(req, res, clientIP, firewall) {
  sanitizeRequest(req);

  const rules = [
    detectSQLInjection,
    detectXSS,
    detectCommandInjection,
    detectFilePathTraversal,
    rateLimit,  
    checkFileInjections,
    checkMaliciousIP
  ];

  if (firewall.securityPolicy === 'strict') {
    rules.push(checkHoneypot, detectSQLMap, detectMaliciousUserAgent);
  }

  for (const rule of rules) {
    const rulePassed = rule.length === 3 ? rule(req, clientIP, firewall) : rule(req);

    console.log(`Applying rule ${rule.name}: ${rulePassed}`);

    if (!rulePassed) {
      logRequestAsync(req, 403);      
      blockIP(clientIP, firewall);    
      return res.status(403).send('Request blocked'); 
    }
  }

  setCSPHeaders(res);

  return true; 
}


function applyCustomRules(req, customRules) {
  for (const rule of customRules) {
    if (!rule(req)) {
      logRequestAsync(req, 403); 
      return false; 
    }
  }

  return true;
}


function manageUnblockIP(ip, firewall) {
  unblockIP(ip, firewall);
  console.log(`IP ${ip} has been unblocked`);
}

module.exports = { applyRules, applyCustomRules, manageUnblockIP };
