const { applyRules, applyCustomRules } = require('./src/rules');
const { logRequestAsync, blockIP, unblockIP, setCSPHeaders } = require('./utils');
const logger = require('./logger');

class Firewall {
    constructor(options = {}) {
        this.blockedIPs = new Set();
        this.rateLimitMap = new Map();
        this.rateLimitThreshold = options.rateLimitThreshold || 100;
        this.rateLimitWindow = options.rateLimitWindow || 60000;
        this.securityPolicy = options.securityPolicy || 'strict'; 
        this.customRules = options.customRules || []; 
        logger.info('Firewall initialized with options: %o', options);
    }

    handleRequest(req, res, next) {
        const clientIP = req.ip || req.connection.remoteAddress;
        
    
        logger.info('Handling request from IP: %s', clientIP);
    
        if (this.isBlocked(clientIP)) {
            logger.warn('Blocked request from IP: %s', clientIP);
            logRequestAsync(req, 'BLOCKED');
            return res.status(403).send('Forbidden: Malicious IP');
        }
    
        const ruleResult = applyRules(req, res, clientIP, this);
        logger.info('Rule result for IP %s: %s', clientIP, ruleResult);
    
        const customRuleResult = applyCustomRules(req, this.customRules);
        logger.info('Custom rule result for IP %s: %s', clientIP, customRuleResult);
    
        if (ruleResult === true && customRuleResult === true) {
            logRequestAsync(req, 'ALLOWED');
            setCSPHeaders(res);
            next();
        } else {
            logger.error('Request rejected from IP: %s due to rule violation', clientIP);
            logRequestAsync(req, 'REJECTED');
            blockIP(clientIP, this);
            res.status(403).send('Forbidden: Security Policy Violation');
        }
    }
    

    isBlocked(clientIP) {
        return this.blockedIPs.has(clientIP);
    }

    unblockIP(clientIP) {
        unblockIP(clientIP, this);
    }
}

module.exports = Firewall;
