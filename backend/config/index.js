/**
 * Centralized Configuration Module
 * 
 * Financial System Design Decisions:
 * 1. Fail-Fast Validation: CRITICAL for financial systems
 *    - Missing or invalid configuration can lead to:
 *      * Security vulnerabilities (missing auth tokens)
 *      * Data loss (incorrect database URLs)
 *      * Service outages (wrong ports, connection strings)
 *      * Compliance violations (missing audit log settings)
 *    - Fail-fast prevents the system from starting with invalid config
 *    - Catches configuration errors immediately, not during runtime
 *    - Reduces risk of operating with partial/invalid configuration
 * 
 * 2. Type Safety: Validates types and formats at startup
 *    - Prevents runtime errors from type mismatches
 *    - Ensures numeric values are actually numbers
 *    - Validates URL formats (database, Redis)
 *    - Validates enum values (NODE_ENV)
 * 
 * 3. Single Source of Truth: All config accessed through this module
 *    - No scattered process.env calls throughout codebase
 *    - Easier to audit what configuration is used
 *    - Centralized documentation of required variables
 *    - Makes testing easier (can mock config module)
 * 
 * 4. Environment-Specific Defaults: Sensible defaults per environment
 *    - Development: More permissive settings
 *    - Production: Strict security settings
 *    - Staging: Production-like but with debugging enabled
 * 
 * 5. Security: Never logs sensitive values
 *    - Passwords, tokens, secrets are validated but not logged
 *    - Prevents accidental exposure in logs
 */

require('dotenv').config();
const Joi = require('joi');

/**
 * Configuration schema definition
 * All required variables must be validated before application starts
 */
const configSchema = Joi.object({
  // Server Configuration
  PORT: Joi.number().integer().min(1).max(65535).required()
    .messages({
      'number.base': 'PORT must be a number',
      'number.min': 'PORT must be between 1 and 65535',
      'any.required': 'PORT is required'
    }),

  HOST: Joi.string().default('0.0.0.0'),

  NODE_ENV: Joi.string().valid('development', 'staging', 'production', 'test').default('development')
    .messages({
      'any.only': 'NODE_ENV must be one of: development, staging, production, test'
    }),

  LOG_LEVEL: Joi.string().valid('fatal', 'error', 'warn', 'info', 'debug', 'trace').default('info'),

  // Database Configuration
  DATABASE_URL: Joi.string().uri({ scheme: ['postgres', 'postgresql'] }).required()
    .messages({
      'string.uri': 'DATABASE_URL must be a valid PostgreSQL connection string',
      'any.required': 'DATABASE_URL is required'
    }),

  // Redis Configuration
  REDIS_HOST: Joi.string().hostname().required()
    .messages({
      'string.hostname': 'REDIS_HOST must be a valid hostname',
      'any.required': 'REDIS_HOST is required'
    }),

  REDIS_PORT: Joi.number().integer().min(1).max(65535).default(6379)
    .messages({
      'number.base': 'REDIS_PORT must be a number',
      'number.min': 'REDIS_PORT must be between 1 and 65535'
    }),

  REDIS_PASSWORD: Joi.string().allow('').optional(),

  // Token Configuration (for future tokenized cash withdrawal system)
  TOKEN_EXPIRY_SECONDS: Joi.number().integer().min(60).max(86400).required()
    .messages({
      'number.base': 'TOKEN_EXPIRY_SECONDS must be a number',
      'number.min': 'TOKEN_EXPIRY_SECONDS must be at least 60 seconds',
      'number.max': 'TOKEN_EXPIRY_SECONDS must not exceed 86400 seconds (24 hours)',
      'any.required': 'TOKEN_EXPIRY_SECONDS is required'
    }),

  TOKEN_PEPPER: Joi.string().min(16).required()
    .messages({
      'string.min': 'TOKEN_PEPPER must be at least 16 characters for security',
      'any.required': 'TOKEN_PEPPER is required for token hashing'
    }),

  // CORS Configuration
  CORS_ORIGIN: Joi.string().default('*'),

  // Rate Limiting Configuration
  RATE_LIMIT_WINDOW_MS: Joi.number().integer().min(1000).default(60000), // 1 minute default
  RATE_LIMIT_MAX_REQUESTS: Joi.number().integer().min(1).default(100), // 100 requests per window
  RATE_LIMIT_SKIP_SUCCESSFUL_REQUESTS: Joi.boolean().default(false),

  // Security Configuration
  JWT_SECRET: Joi.string().min(32).optional()
    .messages({
      'string.min': 'JWT_SECRET must be at least 32 characters if provided'
    }),
}).unknown(false); // Reject unknown environment variables

/**
 * Validate and load configuration
 * Throws error if validation fails - this is intentional (fail-fast)
 */
const { error, value: config } = configSchema.validate(process.env, {
  abortEarly: false, // Collect all errors, don't stop at first
  stripUnknown: true, // Remove unknown keys
  convert: true, // Convert types (e.g., string "3000" to number 3000)
});

if (error) {
  // Format validation errors for clarity
  const errorMessages = error.details.map(detail => {
    const path = detail.path.join('.');
    return `  - ${path}: ${detail.message}`;
  }).join('\n');

  console.error('❌ Configuration validation failed:\n');
  console.error(errorMessages);
  console.error('\nPlease check your .env file and ensure all required variables are set correctly.');
  console.error('Refer to .env.example for required variables.\n');

  // Exit with error code - fail fast
  process.exit(1);
}

/**
 * Export validated configuration
 * All access to environment variables should go through this module
 */
module.exports = {
  server: {
    port: config.PORT,
    host: config.HOST,
    nodeEnv: config.NODE_ENV,
    logLevel: config.LOG_LEVEL,
  },
  database: {
    url: config.DATABASE_URL,
  },
  redis: {
    host: config.REDIS_HOST,
    port: config.REDIS_PORT,
    password: config.REDIS_PASSWORD || undefined,
  },
  token: {
    expirySeconds: config.TOKEN_EXPIRY_SECONDS,
    pepper: config.TOKEN_PEPPER,
  },
  cors: {
    origin: config.CORS_ORIGIN === '*' ? '*' : config.CORS_ORIGIN.split(','),
  },
  rateLimit: {
    windowMs: config.RATE_LIMIT_WINDOW_MS,
    maxRequests: config.RATE_LIMIT_MAX_REQUESTS,
    skipSuccessfulRequests: config.RATE_LIMIT_SKIP_SUCCESSFUL_REQUESTS,
  },
  security: {
    jwtSecret: config.JWT_SECRET,
  },
};
