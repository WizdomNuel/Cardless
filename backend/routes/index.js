/**
 * Main Routes File
 * 
 * Financial System Design Decisions:
 * 1. Route Organization: Routes organized by feature/domain
 *    - Makes codebase easier to navigate
 *    - Allows teams to work on different features independently
 *    - Better for large financial systems with many endpoints
 * 
 * 2. Route Registration: Centralized route registration
 *    - Easy to see all available endpoints
 *    - Simplifies route management
 *    - Better for API documentation generation
 */

const healthRoutes = require('./health');

/**
 * Register all routes with Fastify instance
 * @param {FastifyInstance} fastify - Fastify instance
 */
const registerRoutes = async (fastify) => {
  // Health check routes
  fastify.get('/health', healthRoutes.healthCheck);
  fastify.get('/ready', healthRoutes.readinessCheck);

  // Example: Register other route modules here
  fastify.register(require('./token'), { prefix: '/api/v1/tokens' });
};

module.exports = registerRoutes;
