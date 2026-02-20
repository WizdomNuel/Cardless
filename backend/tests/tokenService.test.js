const TokenService = require('../services/tokenService');
const crypto = require('crypto');

// Mock Config Object
jest.mock('../config', () => ({
    token: {
        expirySeconds: 300,
        pepper: 'test_super_secure_pepper_value_16_chars_plus' // Updated to pepper
    }
}));

// Mock logger
jest.mock('../utils/logger', () => ({
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn()
}));

describe('TokenService Security & Expiry Logic (Hardened)', () => {
    let tokenService;
    let mockDb;
    let mockTrx;

    beforeEach(() => {
        // Reset DB mock state
        mockDb = jest.fn();
        mockDb.insert = jest.fn().mockReturnThis();
        mockDb.returning = jest.fn().mockResolvedValue([{ id: 'mock-token-uuid' }]);

        mockTrx = jest.fn();
        mockTrx.where = jest.fn().mockReturnThis();
        mockTrx.andWhere = jest.fn().mockReturnThis();
        mockTrx.forUpdate = jest.fn().mockReturnThis();
        mockTrx.first = jest.fn();
        mockTrx.update = jest.fn().mockResolvedValue(1);
        mockTrx.insert = jest.fn().mockReturnThis();
        mockTrx.returning = jest.fn().mockResolvedValue([{ id: 'mock-tx-uuid' }]);

        // Make mockDb support both standard knex queries and transactions
        const dbInstance = (table) => {
            // Very basic mimic of Knex chained API
            return {
                insert: mockDb.insert,
                returning: mockDb.returning
            };
        };
        dbInstance.transaction = jest.fn(async (callback, options) => {
            // Validate strict transaction isolation requirement
            expect(options).toEqual({ isolationLevel: 'repeatable read' });

            // Build chainable structure
            const chain = {
                forUpdate: mockTrx.forUpdate,
                first: mockTrx.first,
                update: mockTrx.update,
                insert: mockTrx.insert,
                returning: mockTrx.returning
            };

            chain.andWhere = jest.fn().mockResolvedValue([
                // mock candidate token
                {
                    id: 'token-uuid',
                    prefix: 'ABCD',
                    salt: Buffer.from('mock-salt'),
                    token_hash: crypto.createHash('sha256').update('test_super_secure_pepper_value_16_chars_plus').update('ABCD-12345678').update(Buffer.from('mock-salt')).digest()
                }
            ]);

            chain.where = jest.fn().mockReturnValue(chain);

            const trxInstance = (table) => chain;

            return await callback(trxInstance);
        });
        tokenService = new TokenService(dbInstance);
    });

    afterEach(() => {
        jest.clearAllMocks();
    });

    describe('Token Generation (generateRandomToken)', () => {
        it('should generate requested length token strictly from A-Z, 0-9', () => {
            const token = tokenService.generateRandomToken(100);
            expect(token).toBeDefined();
            expect(typeof token).toBe('string');
            expect(token.length).toBe(100);

            // Enforce uppercase alphanumeric rule ONLY
            const validCharsRegex = /^[A-Z0-9]+$/;
            expect(validCharsRegex.test(token)).toBe(true);
        });
    });

    describe('Token Hashing (hashToken)', () => {
        it('should generate consistent SHA-256 hashes with pepper and salt', () => {
            const plaintext = 'token123';
            const salt = Buffer.from('random-salt');

            const hash1 = tokenService.hashToken(plaintext, salt);
            const hash2 = tokenService.hashToken(plaintext, salt);

            expect(hash1.equals(hash2)).toBe(true);

            const expectedManualHash = crypto.createHash('sha256')
                .update('test_super_secure_pepper_value_16_chars_plus') // from config
                .update(plaintext)
                .update(salt)
                .digest();

            expect(hash1.equals(expectedManualHash)).toBe(true);
        });
    });

    describe('generateWithdrawalToken()', () => {
        it('should enforce STRICTLY positive integer amounts', async () => {
            const accountId = crypto.randomUUID();
            // Floats should fail
            await expect(tokenService.generateWithdrawalToken(accountId, 100.50)).rejects.toThrow();
            await expect(tokenService.generateWithdrawalToken(accountId, -50)).rejects.toThrow();
            await expect(tokenService.generateWithdrawalToken(accountId, 0)).rejects.toThrow();
        });

        it('should successfully store new prefixed token and return it formatted', async () => {
            const accountId = crypto.randomUUID();
            const result = await tokenService.generateWithdrawalToken(accountId, 100);

            expect(result.token).toBeDefined();
            // 4 char prefix + '-' + 8 char core = 13 chars
            expect(result.token.length).toBe(13);
            expect(result.amount).toBe(100);

            expect(mockDb.insert).toHaveBeenCalledTimes(1);
        });

        it('should retry generation if collision occurs (err.code 23505)', async () => {
            const accountId = crypto.randomUUID();

            let callCount = 0;
            mockDb.insert = jest.fn().mockImplementation(() => {
                callCount++;
                if (callCount === 1) {
                    const err = new Error('duplicate key');
                    err.code = '23505';
                    throw err;
                }
                return { returning: jest.fn().mockResolvedValue([{ id: 'mock-token-uuid' }]) };
            });

            const result = await tokenService.generateWithdrawalToken(accountId, 100);
            expect(result.token).toBeDefined();
            expect(callCount).toBe(2); // Retried exactly once
        });
    });

    describe('redeemWithdrawalToken()', () => {
        it('should return INVALID if syntax is wrong or missing ID prefix', async () => {
            const res = await tokenService.redeemWithdrawalToken('12345678', 'agent-1'); // No hyphen
            expect(res.result).toBe('INVALID');

            const res2 = await tokenService.redeemWithdrawalToken('A-123', 'agent-1'); // Wrong length
            expect(res2.result).toBe('INVALID');
        });

        it('should correctly handle successful redemption with O(1) prefix lookup', async () => {
            // The before block mocks the returning of `candidateTokens` simulating the prefix lookup

            // Mock the secondary exact match step (forUpdate.first)
            mockTrx.first.mockResolvedValueOnce({
                id: 'token-uuid',
                account_id: crypto.randomUUID(),
                amount: 200,
                status: 'ACTIVE',
                expires_at: new Date(Date.now() + 10000) // Future expiry
            });

            const fullTokenStr = 'ABCD-12345678';
            const res = await tokenService.redeemWithdrawalToken(fullTokenStr, 'atm-1');

            expect(mockTrx.forUpdate).toHaveBeenCalled(); // Ensure row lock happened
            expect(res.result).toBe('SUCCESS');

            // Verify Transaction Ledger Insert
            expect(mockTrx.insert).toHaveBeenCalledWith(expect.objectContaining({
                type: 'WITHDRAWAL',
                status: 'SUCCESS'
            }));
        });

        it('should reject already USED tokens to prevent double-spend race condition', async () => {
            mockTrx.first.mockResolvedValueOnce({
                id: 'token-uuid',
                status: 'USED' // Race condition: someone already used it
            });

            const res = await tokenService.redeemWithdrawalToken('ABCD-12345678', 'atm-1');

            expect(res.result).toBe('EXPIRED_OR_USED');
            expect(mockTrx.update).not.toHaveBeenCalled(); // No further status update
        });

        it('should return INVALID if hash does not safely compare', async () => {
            // Using the mock from beforeEach, token_hash matches ABCD-12345678
            // We pass ABCD-99999999, so it fails timingSafeEqual
            const res = await tokenService.redeemWithdrawalToken('ABCD-99999999', 'atm-1');
            expect(res.result).toBe('INVALID');
        });
    });
});
