const TokenController = require('../controllers/tokenController');
const { createRateLimiter } = require('../middleware/rateLimiter');

/**
 * Custom strict rate limiter specifically for redemption to prevent brute force testing.
 * Limits per IP (standard).
 */
const redemptionIpRateLimiter = createRateLimiter({
    windowMs: 60000, // 1 minute
    maxRequests: 5,  // 5 requests per IP
    keyGenerator: (request) => `redeem:ip:${request.ip}`
});

/**
 * Custom limit per agent/machine attempting redemptions
 */
const redemptionAgentRateLimiter = createRateLimiter({
    windowMs: 60000,
    maxRequests: 10,
    keyGenerator: (request) => {
        // If agentId lacks, fallback to IP (though Joi schema rejects missing agentId anyway)
        const agentId = (request.body && request.body.agentId) || request.ip;
        return `redeem:agent:${agentId}`;
    }
});

/**
 * Custom limit per user account attempting redemptions (prevents distributed brute force targeting 1 account)
 */
const redemptionUserRateLimiter = createRateLimiter({
    windowMs: 60000,
    maxRequests: 5,
    keyGenerator: (request) => {
        const accountId = (request.body && request.body.accountId) || request.ip;
        return `redeem:user:${accountId}`;
    }
});

async function tokenRoutes(fastify, options) {
    // We apply the rate limiters explicitly via `preHandler` hooks.
    const rateLimiterHooks = [
        redemptionIpRateLimiter,
        redemptionAgentRateLimiter,
        redemptionUserRateLimiter
    ];

    fastify.post('/redeem-token', {
        preHandler: rateLimiterHooks
    }, TokenController.redeemToken);

    // Exposing token generation as well for testing integration completeness
    fastify.post('/', TokenController.generateToken);
}

module.exports = tokenRoutes;
