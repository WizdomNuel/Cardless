/**
 * Cardless Cash Withdrawal Schema (PostgreSQL)
 *
 * Tables:
 * - accounts
 * - tokens
 * - transactions (append-only ledger)
 * - redemption_attempts
 *
 * Financial/compliance rationale is embedded in constraints + comments:
 * - Strong state machines (ENUMs + CHECKs) prevent inconsistent rows that can enable fraud.
 * - Immutable ledger (no UPDATE/DELETE on transactions) supports auditability and tamper-evidence.
 * - Token hashing: never store raw tokens; store only salted hashes to reduce breach impact.
 * - Redemption is designed to be ACID-safe under row locks to prevent double-spend.
 */

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.up = async function (knex) {
  // UUID generation for non-enumerable primary keys.
  await knex.raw('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');

  // Constrained state machines reduce fraud surface area by preventing illegal values at rest.
  await knex.raw(`
    DO $$ BEGIN
      CREATE TYPE account_status AS ENUM ('ACTIVE', 'INACTIVE');
    EXCEPTION WHEN duplicate_object THEN NULL; END $$;

    DO $$ BEGIN
      CREATE TYPE token_status AS ENUM ('ACTIVE', 'USED', 'EXPIRED');
    EXCEPTION WHEN duplicate_object THEN NULL; END $$;

    DO $$ BEGIN
      CREATE TYPE transaction_type AS ENUM ('WITHDRAWAL', 'REVERSAL');
    EXCEPTION WHEN duplicate_object THEN NULL; END $$;

    DO $$ BEGIN
      CREATE TYPE transaction_status AS ENUM ('PENDING', 'SUCCESS', 'FAILED', 'REVERSED');
    EXCEPTION WHEN duplicate_object THEN NULL; END $$;

    DO $$ BEGIN
      CREATE TYPE redemption_result AS ENUM ('SUCCESS', 'INVALID', 'EXPIRED', 'USED');
    EXCEPTION WHEN duplicate_object THEN NULL; END $$;
  `);

  // updated_at trigger for mutable tables (accounts only; tokens/transactions are controlled separately).
  await knex.raw(`
    CREATE OR REPLACE FUNCTION set_updated_at()
    RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    BEGIN
      NEW.updated_at = now();
      RETURN NEW;
    END;
    $$;
  `);

  // Immutable ledger enforcement: forbid UPDATE/DELETE on transactions.
  await knex.raw(`
    CREATE OR REPLACE FUNCTION ledger_immutable()
    RETURNS trigger
    LANGUAGE plpgsql
    AS $$
    BEGIN
      RAISE EXCEPTION 'transactions is append-only (immutable ledger): UPDATE/DELETE are not permitted';
    END;
    $$;
  `);

  // 1) accounts
  await knex.schema.createTable('accounts', (table) => {
    table.uuid('id').primary().defaultTo(knex.raw('uuid_generate_v4()'));
    table.text('account_ref').notNullable().unique();
    table.specificType('status', 'account_status').notNullable().defaultTo('ACTIVE');
    table.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp('updated_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());

    table.index(['account_ref'], 'accounts_account_ref_idx');
  });

  await knex.raw(`
    CREATE TRIGGER trg_accounts_set_updated_at
    BEFORE UPDATE ON accounts
    FOR EACH ROW
    EXECUTE FUNCTION set_updated_at();
  `);

  await knex.raw(`
    COMMENT ON TABLE accounts IS
      'Accounts eligible for cardless cash withdrawals. Keep identifiers non-enumerable (UUID). Status gates risk controls.';
    COMMENT ON COLUMN accounts.account_ref IS
      'Unique external account reference (e.g., core banking ID). Uniqueness prevents ambiguity and reduces fraud via reference collisions.';
    COMMENT ON COLUMN accounts.status IS
      'ACTIVE accounts may issue/redeem tokens. INACTIVE disables operations after compromise, sanctions, or KYC/AML holds.';
  `);

  // 2) tokens
  await knex.schema.createTable('tokens', (table) => {
    table.uuid('id').primary().defaultTo(knex.raw('uuid_generate_v4()'));

    // Store hashed+salted token material only (never plaintext).
    // Use BYTEA to store raw hash bytes (e.g., 32 bytes for SHA-256).
    table.binary('token_hash').notNullable();

    table
      .uuid('account_id')
      .notNullable()
      .references('id')
      .inTable('accounts')
      .onDelete('RESTRICT')
      .onUpdate('CASCADE');

    table.numeric('amount', 15, 2).notNullable();
    table.specificType('status', 'token_status').notNullable().defaultTo('ACTIVE');
    table.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());
    table.timestamp('expires_at', { useTz: true }).notNullable();
    table.timestamp('used_at', { useTz: true });

    // Required indexes
    table.unique(['token_hash'], { indexName: 'tokens_token_hash_uq' });
    table.index(['account_id'], 'tokens_account_id_idx');

    // Operational index for expiry sweeps + monitoring
    table.index(['status', 'expires_at'], 'tokens_status_expires_at_idx');
  });

  await knex.raw(`
    ALTER TABLE tokens
      ADD CONSTRAINT tokens_amount_positive CHECK (amount > 0),
      ADD CONSTRAINT tokens_expires_after_created CHECK (expires_at > created_at),
      ADD CONSTRAINT tokens_used_at_consistency CHECK (
        (status = 'USED' AND used_at IS NOT NULL)
        OR (status <> 'USED' AND used_at IS NULL)
      );

    COMMENT ON TABLE tokens IS
      'Withdrawal tokens. Only salted hashes are stored to reduce breach impact. Status+constraints prevent replay and inconsistent rows.';
    COMMENT ON COLUMN tokens.token_hash IS
      'Hashed+salted token. Unique to prevent replay and ensure deterministic lookup during redemption without storing plaintext tokens.';
    COMMENT ON COLUMN tokens.expires_at IS
      'Hard expiry. Must be enforced under row lock at redemption time to prevent TOCTOU races.';
  `);

  // 3) transactions (immutable ledger, append-only)
  await knex.schema.createTable('transactions', (table) => {
    table.uuid('id').primary().defaultTo(knex.raw('uuid_generate_v4()'));

    table
      .uuid('account_id')
      .notNullable()
      .references('id')
      .inTable('accounts')
      .onDelete('RESTRICT')
      .onUpdate('CASCADE');

    table
      .uuid('token_id')
      .notNullable()
      .references('id')
      .inTable('tokens')
      .onDelete('RESTRICT')
      .onUpdate('CASCADE');

    table.specificType('type', 'transaction_type').notNullable();
    table.numeric('amount', 15, 2).notNullable();
    table.specificType('status', 'transaction_status').notNullable();
    table.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());

    table.index(['account_id'], 'transactions_account_id_idx');
    table.index(['token_id'], 'transactions_token_id_idx');
    table.index(['created_at'], 'transactions_created_at_idx');
  });

  await knex.raw(`
    ALTER TABLE transactions
      ADD CONSTRAINT transactions_amount_positive CHECK (amount > 0);

    CREATE TRIGGER trg_transactions_immutable
    BEFORE UPDATE OR DELETE ON transactions
    FOR EACH ROW
    EXECUTE FUNCTION ledger_immutable();

    COMMENT ON TABLE transactions IS
      'Immutable (append-only) ledger. No UPDATE/DELETE. Corrections are new rows (REVERSAL) to preserve tamper-evidence and auditability.';
    COMMENT ON COLUMN transactions.status IS
      'Recorded at insertion time. Do not mutate; emit new ledger entries instead (e.g., REVERSAL) to keep a full forensic trail.';
  `);

  // 4) redemption_attempts
  await knex.schema.createTable('redemption_attempts', (table) => {
    table.uuid('id').primary().defaultTo(knex.raw('uuid_generate_v4()'));

    table
      .uuid('token_id')
      .notNullable()
      .references('id')
      .inTable('tokens')
      .onDelete('RESTRICT')
      .onUpdate('CASCADE');

    table.text('agent_id').notNullable();
    table.specificType('result', 'redemption_result').notNullable();
    table.jsonb('metadata').notNullable().defaultTo(knex.raw(`'{}'::jsonb`));
    table.timestamp('created_at', { useTz: true }).notNullable().defaultTo(knex.fn.now());

    table.index(['token_id'], 'redemption_attempts_token_id_idx');
    table.index(['agent_id'], 'redemption_attempts_agent_id_idx');
    table.index(['created_at'], 'redemption_attempts_created_at_idx');
  });

  await knex.raw(`
    COMMENT ON TABLE redemption_attempts IS
      'Append-only record of token redemption attempts. Supports fraud analytics (velocity, geo anomalies) and compliance investigations.';
    COMMENT ON COLUMN redemption_attempts.metadata IS
      'Risk metadata (IP/device/location). Ensure retention controls and PII minimization to meet compliance requirements.';
  `);

  // Optional ACID-safe redemption helper (application can also implement the same transaction pattern).
  await knex.raw(`
    CREATE OR REPLACE FUNCTION redeem_token(
      p_token_hash bytea,
      p_agent_id text,
      p_metadata jsonb DEFAULT '{}'::jsonb
    )
    RETURNS TABLE (
      out_token_id uuid,
      out_transaction_id uuid,
      out_result redemption_result
    )
    LANGUAGE plpgsql
    AS $$
    DECLARE
      v_token tokens%ROWTYPE;
    BEGIN
      /*
        ACID redemption:
        - Lock token row (FOR UPDATE) to serialize concurrent attempts.
        - Validate ACTIVE + not expired.
        - Mark token USED (used_at set) exactly once.
        - Append ledger transaction (immutable).
        - Append redemption_attempt for forensic evidence.
      */

      SELECT * INTO v_token
      FROM tokens
      WHERE token_hash = p_token_hash
      FOR UPDATE;

      IF NOT FOUND THEN
        out_token_id := NULL;
        out_transaction_id := NULL;
        out_result := 'INVALID';
        RETURN NEXT;
        RETURN;
      END IF;

      IF v_token.status = 'USED' THEN
        INSERT INTO redemption_attempts(token_id, agent_id, result, metadata)
        VALUES (v_token.id, p_agent_id, 'USED', p_metadata);

        out_token_id := v_token.id;
        out_transaction_id := NULL;
        out_result := 'USED';
        RETURN NEXT;
        RETURN;
      END IF;

      IF now() >= v_token.expires_at OR v_token.status = 'EXPIRED' THEN
        UPDATE tokens SET status = 'EXPIRED'
        WHERE id = v_token.id AND status <> 'USED';

        INSERT INTO redemption_attempts(token_id, agent_id, result, metadata)
        VALUES (v_token.id, p_agent_id, 'EXPIRED', p_metadata);

        out_token_id := v_token.id;
        out_transaction_id := NULL;
        out_result := 'EXPIRED';
        RETURN NEXT;
        RETURN;
      END IF;

      UPDATE tokens
      SET status = 'USED',
          used_at = now()
      WHERE id = v_token.id AND status = 'ACTIVE';

      INSERT INTO transactions(account_id, token_id, type, amount, status)
      VALUES (v_token.account_id, v_token.id, 'WITHDRAWAL', v_token.amount, 'SUCCESS')
      RETURNING id INTO out_transaction_id;

      INSERT INTO redemption_attempts(token_id, agent_id, result, metadata)
      VALUES (v_token.id, p_agent_id, 'SUCCESS', p_metadata);

      out_token_id := v_token.id;
      out_result := 'SUCCESS';
      RETURN NEXT;
    END;
    $$;

    COMMENT ON FUNCTION redeem_token(bytea, text, jsonb) IS
      'ACID-safe redemption helper: row locks + constrained states prevent double-spend; emits append-only ledger + attempt evidence for compliance.';
  `);
};

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.down = async function (knex) {
  await knex.raw('DROP FUNCTION IF EXISTS redeem_token(bytea, text, jsonb)');

  await knex.schema.dropTableIfExists('redemption_attempts');
  await knex.schema.dropTableIfExists('transactions');
  await knex.schema.dropTableIfExists('tokens');

  await knex.raw('DROP TRIGGER IF EXISTS trg_accounts_set_updated_at ON accounts');
  await knex.schema.dropTableIfExists('accounts');

  await knex.raw('DROP FUNCTION IF EXISTS ledger_immutable()');
  await knex.raw('DROP FUNCTION IF EXISTS set_updated_at()');

  await knex.raw('DROP TYPE IF EXISTS redemption_result');
  await knex.raw('DROP TYPE IF EXISTS transaction_status');
  await knex.raw('DROP TYPE IF EXISTS transaction_type');
  await knex.raw('DROP TYPE IF EXISTS token_status');
  await knex.raw('DROP TYPE IF EXISTS account_status');
};
