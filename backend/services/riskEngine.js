const logger = require('../utils/logger');

/**
 * Mock Risk Engine
 * Simulates risk scoring for token redemptions based on metadata signals.
 */
class RiskEngine {
    /**
     * Evaluate redemption risk dynamically
     * @param {string} accountId 
     * @param {string} agentId 
     * @param {Object} metadata 
     * @returns {Object} { score: number, decision: 'APPROVE' | 'CHALLENGE' | 'REJECT' }
     */
    static evaluateRedemption(accountId, agentId, metadata = {}) {
        let score = 10; // Base score (low risk)

        // Simulate suspicious location / IP
        if (metadata.ip && metadata.ip.startsWith('192.168.100')) {
            score += 40;
        }

        // Simulate known bad agent/device
        if (metadata.deviceId && metadata.deviceId === 'known-bad-device') {
            score += 80;
        }

        let decision = 'APPROVE';
        if (score >= 80) decision = 'REJECT';
        else if (score >= 40) decision = 'CHALLENGE';

        logger.info({ accountId, agentId, score, decision }, 'Risk evaluation completed');
        return { score, decision };
    }
}

module.exports = RiskEngine;
