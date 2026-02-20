// Mock configurations first
jest.mock('../config/redis', () => ({
    redis: {
        zremrangebyscore: jest.fn().mockResolvedValue(1),
        zcard: jest.fn().mockResolvedValue(1), // Under the limit
        zadd: jest.fn().mockResolvedValue(1),
        expire: jest.fn().mockResolvedValue(1),
        zrem: jest.fn().mockResolvedValue(1),
        ttl: jest.fn().mockResolvedValue(60)
    },
    testConnection: jest.fn().mockResolvedValue({ connected: true })
}));

jest.mock('../config', () => ({
    server: { nodeEnv: 'test', port: 3000, host: '127.0.0.1' },
    rateLimit: { windowMs: 60000, maxRequests: 5, skipSuccessfulRequests: false },
    token: { expirySeconds: 300, pepper: 'test_super_secure_pepper_value_16_chars_plus' },
    cors: { origin: '*' }
}));

jest.mock('../utils/logger', () => ({
    logger: {
        info: jest.fn(),
        warn: jest.fn(),
        error: jest.fn()
    },
    logSecurity: jest.fn(),
    logError: jest.fn(),
    logSystem: jest.fn(),
    EVENT_TYPES: { ERROR: 'ERROR' }
}));

// Mock Database Connection Context
const mockDb = jest.fn();
mockDb.transaction = jest.fn(); // Prevent undefined error in token test
jest.mock('../config/database', () => ({
    getDb: () => mockDb,
    testConnection: jest.fn().mockResolvedValue({ connected: true }),
    close: jest.fn()
}));

// Removing explicit module mock for RiskEngine so we can spy on it properly

const Fastify = require('fastify');
const registerRoutes = require('../routes');
const RiskEngine = require('../services/riskEngine');

describe('POST /api/v1/tokens/redeem-token Endpoint', () => {
    let app;

    beforeAll(async () => {
        app = Fastify();
        await registerRoutes(app);
        await app.ready();
    });

    afterAll(async () => {
        await app.close();
    });

    beforeEach(() => {
        jest.clearAllMocks();
        // Since we clear mocks, we must re-establish the default successful RiskEngine response
        jest.spyOn(RiskEngine, 'evaluateRedemption').mockReturnValue({ score: 10, decision: 'APPROVE' });
    });

    it('rejects completely invalid schemas (400)', async () => {
        const response = await app.inject({
            method: 'POST',
            url: '/api/v1/tokens/redeem-token',
            remoteAddress: '127.0.0.1',
            payload: { token: 'short' } // Missing accountId, agentId
        });

        expect(response.statusCode).toBe(400);
        const body = JSON.parse(response.payload);
        expect(body.error).toBe('Validation Error');
    });

    it('handles Risk Engine REJECT (403)', async () => {
        RiskEngine.evaluateRedemption.mockReturnValue({ score: 95, decision: 'REJECT' });

        const response = await app.inject({
            method: 'POST',
            url: '/api/v1/tokens/redeem-token',
            remoteAddress: '192.168.100.5',
            payload: {
                token: 'TEST-12345678',
                accountId: '123e4567-e89b-12d3-a456-426614174000',
                agentId: 'atm-1',
                metadata: { ip: '192.168.100.5' } // known high risk ip pattern in stub
            }
        });



        expect(response.statusCode).toBe(403);
        const body = JSON.parse(response.payload);
        expect(body.message).toBe('Redemption declined by risk policy');
    });

    it('handles TokenService SUCCESS (200)', async () => {
        RiskEngine.evaluateRedemption.mockReturnValue({ score: 10, decision: 'APPROVE' });

        // We mock TokenService dynamically here since we injected `getDb`
        const TokenService = require('../services/tokenService');
        jest.spyOn(TokenService.prototype, 'redeemWithdrawalToken').mockResolvedValue({
            result: 'SUCCESS',
            transactionId: 'tx-123'
        });

        const response = await app.inject({
            method: 'POST',
            url: '/api/v1/tokens/redeem-token',
            remoteAddress: '127.0.0.1',
            payload: {
                token: 'TEST-12345678',
                accountId: '123e4567-e89b-12d3-a456-426614174000',
                agentId: 'atm-1'
            }
        });

        expect(response.statusCode).toBe(200);
        const body = JSON.parse(response.payload);
        expect(body.success).toBe(true);
        expect(body.transactionId).toBe('tx-123');
    });

    it('handles TokenService EXPIRED_OR_USED (409)', async () => {
        RiskEngine.evaluateRedemption.mockReturnValue({ score: 10, decision: 'APPROVE' });

        const TokenService = require('../services/tokenService');
        jest.spyOn(TokenService.prototype, 'redeemWithdrawalToken').mockResolvedValue({
            result: 'EXPIRED_OR_USED'
        });

        const response = await app.inject({
            method: 'POST',
            url: '/api/v1/tokens/redeem-token',
            remoteAddress: '127.0.0.1',
            payload: {
                token: 'TEST-12345678',
                accountId: '123e4567-e89b-12d3-a456-426614174000',
                agentId: 'atm-2'
            }
        });

        expect(response.statusCode).toBe(409);
        const body = JSON.parse(response.payload);
        expect(body.error).toBe('Token Expired or Already Used');
    });
});

describe('Rate Limiter Hooks in Token Endpoint', () => {
    let app;
    const { redis } = require('../config/redis');

    beforeAll(async () => {
        app = Fastify();
        await registerRoutes(app);
        await app.ready();
    });

    afterAll(async () => {
        await app.close();
    });

    beforeEach(() => {
        jest.clearAllMocks();
        jest.spyOn(RiskEngine, 'evaluateRedemption').mockReturnValue({ score: 10, decision: 'APPROVE' });
    });

    it('blocks request with 429 when max requests exceeded', async () => {
        // The default rate limiter runs globally. We need to mock zcard for all 4 hooks 
        // (default + 3 custom ones on /redeem-token). By forcing `zcard` to 999 
        // repeatedly, one of them will block it.
        redis.zcard.mockResolvedValue(999);
        redis.ttl.mockResolvedValue(30);

        const response = await app.inject({
            method: 'POST',
            url: '/api/v1/tokens/redeem-token',
            remoteAddress: '127.0.0.1', // Ensure fastify request.ip works natively
            payload: {
                token: 'TEST-12345678',
                accountId: '123e4567-e89b-12d3-a456-426614174000',
                agentId: 'atm-1'
            }
        });

        expect(response.statusCode).toBe(429);
        const body = JSON.parse(response.payload);
        expect(body.error.message).toBe('Too many requests');
    });
});
