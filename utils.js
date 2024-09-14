const fs = require('fs');
const path = require('path');
const logger = require('./logger');

function logRequestAsync(req, status) {
    const logData = `[${new Date().toISOString()}] ${req.method} ${req.url} - ${status}\n`;
    fs.writeFile('waf.log', logData, { flag: 'a' }, (err) => {
        if (err) {
            console.error('Error writing to log file:', err);
        }
    });
}

function blockIP(ip, firewall) {
    firewall.blockedIPs.add(ip);
}

function unblockIP(ip, firewall) {
    firewall.blockedIPs.delete(ip);
}

function detectSQLInjection(req) {
    const sqlInjectionPatterns = /(\bselect\b|\binsert\b|\bupdate\b|\bdelete\b|\bdrop\b|\balter\b|--|\/\*|\bunion\b|\bexec\b|\bwaitfor\b|\bconvert\b)/i;
    return !(sqlInjectionPatterns.test(req.url) || sqlInjectionPatterns.test(req.body));
}

function detectXSS(req) {
    const xssPatterns = /(<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>|onerror=|onload=)/i;
    return !(xssPatterns.test(req.url) || xssPatterns.test(req.body));
}

function detectCommandInjection(req) {
    const commandPatterns = /(\bping\b|\bcat\b|\bnetstat\b|\bwget\b|\bcurl\b|\bchmod\b|\brm\b|\bwhoami\b|\buname\b)/i;
    return !(commandPatterns.test(req.url) || commandPatterns.test(req.body));
}

function detectFilePathTraversal(req) {
    const pathTraversalPatterns = /(\.\.\/|\/etc\/passwd|\/etc\/shadow|c:\/|\.htaccess|\.bash_history)/i;
    return !(pathTraversalPatterns.test(req.url) || pathTraversalPatterns.test(req.body));
}

function checkCSRF(req) {
    const csrfToken = req.headers['x-csrf-token'];
    return csrfToken && csrfToken === req.session.csrfToken;
}

function rateLimit(req, clientIP, firewall) {
    const now = Date.now();
    if (!firewall.rateLimitMap.has(clientIP)) {
        firewall.rateLimitMap.set(clientIP, { count: 1, firstRequestTime: now });
        return true;
    }

    const clientData = firewall.rateLimitMap.get(clientIP);
    if (now - clientData.firstRequestTime < firewall.rateLimitWindow) {
        if (clientData.count >= firewall.rateLimitThreshold) {
            blockIP(clientIP, firewall);
            return false;
        }
        clientData.count++;
    } else {
        firewall.rateLimitMap.set(clientIP, { count: 1, firstRequestTime: now });
    }

    return true;
}

function checkFileInjections(req) {
    const fileInjectionPatterns = /\.(php|jsp|exe|sh|bin|bash)/i;
    const files = req.files || [];
    for (const file of files) {
        if (fileInjectionPatterns.test(file.name)) {
            return false;
        }
    }
    return true;
}

function checkMaliciousIP(req, clientIP) {
    const maliciousIPs = [
        '192.168.1.100',
        
    ];
    return !maliciousIPs.includes(clientIP);
}

function checkHoneypot(req) {
    return !req.body.honeypotField; 
}

function setCSPHeaders(res) {
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; object-src 'none';");
}

function detectSQLMap(req) {
    const sqlMapPatterns = /(sqlmap|sleep\(|benchmark\()/i;
    return !(sqlMapPatterns.test(req.headers['user-agent']) || sqlMapPatterns.test(req.url) || sqlMapPatterns.test(req.body));
}


function sanitizeRequest(req) {
    req.url = decodeURIComponent(req.url);
    req.body = decodeURIComponent(req.body || '');
}

function detectMaliciousUserAgent(req) {
    const maliciousAgents = /(sqlmap|curl|wget|python-requests|nikto|fuzz|scanner)/i;
    return !maliciousAgents.test(req.headers['user-agent']);
}


module.exports = {
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
};
