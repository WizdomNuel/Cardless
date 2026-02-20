const Joi = require('joi');
const TokenService = require('../services/tokenService');
const RiskEngine = require('../services/riskEngine');
const { getDb } = require('../config/database');
const { logger } = require('../utils/logger');

class TokenController {
    /**
     * Generates a new Token.
     * Assumes `POST /api/v1/tokens`
     */
    static async generateToken(request, reply) {
        // Basic body schema
        const schema = Joi.object({
            accountId: Joi.string().uuid().required(),
            amount: Joi.number().integer().positive().required()
        });

        const { error, value } = schema.validate(request.body);
        if (error) {
            return reply.code(400).send({ error: 'Validation Error', message: error.details[0].message });
        }

        try {
            const db = getDb();
            const tokenService = new TokenService(db);

            const result = await tokenService.generateWithdrawalToken(value.accountId, value.amount);

            return reply.code(201).send({
                success: true,
                data: result
            });
        } catch (err) {
            logger.error('Token generation failed', err);
            return reply.code(500).send({ error: 'Internal Server Error' });
        }
    }

    /**
     * Redeems a token securely.
     * Exposes `POST /api/v1/tokens/redeem` (or `/redeem-token`)
     * Requires strict validation, risk evaluation, and handles single-use DB states.
     */
    static async redeemToken(request, reply) {
        // Strict schema
        const schema = Joi.object({
            token: Joi.string().required(),
            accountId: Joi.string().uuid().required(), // Explicit context cross-check
            agentId: Joi.string().required(),
            metadata: Joi.object({
                ip: Joi.string().optional(),
                deviceId: Joi.string().optional(),
                location: Joi.string().optional()
            }).optional().default({})
        });

        const { error, value } = schema.validate(request.body);
        if (error) {
            // 400 Bad Request
            return reply.code(400).send({ error: 'Validation Error', message: error.details[0].message });
        }

        // Default metadata IP explicitly from Fastify request if not provided
        if (!value.metadata.ip) {
            value.metadata.ip = request.ip || '127.0.0.1'; // Fallback for tests
        }

        try {
            // 1. Synchronous Risk Evaluation Stub
            const riskAssessment = RiskEngine.evaluateRedemption(value.accountId, value.agentId, value.metadata);

            if (riskAssessment.decision === 'REJECT') {
                logger.warn({ accountId: value.accountId, agentId: value.agentId }, 'Redemption rejected by Risk Engine');
                return reply.code(403).send({ error: 'Forbidden', message: 'Redemption declined by risk policy' });
            }

            // If 'CHALLENGE', we might optionally require an MFA step. For now, we log and proceed.
            // E.g. reply.code(401).send({ error: 'Challenge Required', mfaContext: '...' })

            // 2. Perform ACID Token Redemption (Only if not REJECTED)
            const db = getDb();
            const tokenService = new TokenService(db);

            const result = await tokenService.redeemWithdrawalToken(value.token, value.agentId, {
                riskScore: riskAssessment.score,
                ...value.metadata
            });

            // 3. Map service results to HTTP appropriately
            switch (result.result) {
                case 'SUCCESS':
                    return reply.code(200).send({
                        success: true,
                        message: 'Token successfully redeemed',
                        transactionId: result.transactionId
                    });
                case 'INVALID':
                    // Hash mismatch or formatting issue
                    return reply.code(400).send({ error: 'Invalid Token' });
                case 'EXPIRED_OR_USED':
                    // Race condition explicitly caught or token literally expired/used before call
                    return reply.code(409).send({ error: 'Token Expired or Already Used' });
                case 'EXPIRED':
                    return reply.code(400).send({ error: 'Token Expired' });
                case 'USED':
                    return reply.code(409).send({ error: 'Token Already Used' });
                default:
                    return reply.code(500).send({ error: 'Unknown state occurred' });
            }
        } catch (err) {
            logger.error('Redemption endpoint experienced a failure', err);
            return reply.code(500).send({ error: 'Internal Server Error' });
        }
    }
}

module.exports = TokenController;
