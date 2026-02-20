/**
 * Migration 002: Add salt to tokens table for hardened security.
 *
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.up = async function (knex) {
    await knex.schema.alterTable('tokens', (table) => {
        // Add per-token salt column
        // UUID or simply random binary bytes. We'll store it as binary for space efficiency.
        // If you need more length, binary might constrain. Let's use string/hex for simplicity or binary. 
        // The previous token_hash was binary, let's keep salt binary.
        table.binary('salt').notNullable().defaultTo(knex.raw(`decode('00', 'hex')`));
    });

    // Remove default once initialized to force all future tokens to explicitly provide salt.
    await knex.raw(`ALTER TABLE tokens ALTER COLUMN salt DROP DEFAULT`);

    await knex.raw(`
    COMMENT ON COLUMN tokens.salt IS
      'Per-token random salt used alongside global pepper for SHA-256 hashing. Prevents rainbow table and pre-computation attacks.';
  `);
};

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.down = async function (knex) {
    await knex.schema.alterTable('tokens', (table) => {
        table.dropColumn('salt');
    });
};
