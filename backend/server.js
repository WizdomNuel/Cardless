require('dotenv').config();
const fastify = require('fastify')({ logger: true });
const { Client } = require('pg');
const Redis = require('ioredis');

// Database Setup
const pgClient = new Client({
  connectionString: process.env.DATABASE_URL,
});

const redis = new Redis(process.env.REDIS_URL);

// Plugins
fastify.register(require('@fastify/cors'));
fastify.register(require('@fastify/helmet'));

// Health Check
fastify.get('/health', async (request, reply) => {
  try {
    const dbRes = await pgClient.query('SELECT NOW()');
    const redisPing = await redis.ping();
    return { 
      status: 'ok', 
      timestamp: new Date(), 
      db: dbRes.rows[0].now,
      redis: redisPing 
    };
  } catch (err) {
    fastify.log.error(err);
    reply.status(500).send({ status: 'error', message: err.message });
  }
});

// Run Server
const start = async () => {
  try {
    await pgClient.connect();
    fastify.log.info('Connected to PostgreSQL');
    
    await fastify.listen({ port: process.env.PORT || 3000, host: '0.0.0.0' });
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();
