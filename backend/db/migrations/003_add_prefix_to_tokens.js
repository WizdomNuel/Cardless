/**
 * Migration 003: Add prefix to tokens table to allow fast O(1) lookup of secure salted hashes.
 *
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.up = async function (knex) {
    // Add an explicitly indexed prefix column.
    await knex.schema.alterTable('tokens', (table) => {
        // 4 character prefix is sufficient for lookups while preventing table scans.
        table.string('prefix', 8).notNullable().defaultTo('');
    });

    // Remove default once initialized to force all future tokens to explicitly provide prefix.
    await knex.raw(`ALTER TABLE tokens ALTER COLUMN prefix DROP DEFAULT`);

    // Create an index specifically for the prefix and status to speed up redemption
    await knex.schema.alterTable('tokens', (table) => {
        table.index(['prefix', 'status'], 'tokens_prefix_status_idx');
    });

    await knex.raw(`
    COMMENT ON COLUMN tokens.prefix IS
      'Public identifier prefix. Used to locate the token row for hash verification without needing an O(N) scan. Not secret. Forms part of the final user token e.g. ABC-12345678';
  `);
};

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.down = async function (knex) {
    await knex.schema.alterTable('tokens', (table) => {
        table.dropIndex(['prefix', 'status'], 'tokens_prefix_status_idx');
        table.dropColumn('prefix');
    });
};
