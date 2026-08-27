import type { Db } from "../db.js";
import type {
  OAuthAuthorizationCodeIssuance,
  OAuthAuthorizationTransactionRecord
} from "./types.js";

function mapTransaction(row: Record<string, unknown>): OAuthAuthorizationTransactionRecord {
  return {
    id: String(row.id),
    oauthClientId: String(row.oauth_client_id),
    oauthResourceId: String(row.oauth_resource_id),
    redirectUri: String(row.redirect_uri),
    requestedScopes: Array.isArray(row.requested_scopes) ? row.requested_scopes.map(String) : [],
    codeChallenge: String(row.code_challenge),
    codeChallengeMethod: "S256",
    protectedDownstreamState: (row.protected_downstream_state as Record<string, unknown> | null) ?? null,
    upstreamStateHash: String(row.upstream_state_hash),
    upstreamNonceHash: String(row.upstream_nonce_hash),
    correlationId: String(row.correlation_id),
    status: row.status as OAuthAuthorizationTransactionRecord["status"],
    expiresAt: row.expires_at as Date,
    claimedAt: (row.claimed_at as Date | null) ?? null,
    completedAt: (row.completed_at as Date | null) ?? null,
    createdAt: row.created_at as Date
  };
}

export class OAuthAuthorizationFlowRepository {
  constructor(private readonly db: Db) {}

  withDb(db: Db): OAuthAuthorizationFlowRepository {
    return new OAuthAuthorizationFlowRepository(db);
  }

  async createAuthorizationTransaction(input: {
    id: string;
    oauthClientId: string;
    oauthResourceId: string;
    redirectUri: string;
    requestedScopes: string[];
    codeChallenge: string;
    protectedDownstreamState: Record<string, unknown>;
    upstreamStateHash: string;
    upstreamNonceHash: string;
    correlationId: string;
    createdAt: Date;
    expiresAt: Date;
  }): Promise<void> {
    await this.db.query(
      `INSERT INTO oauth_authorization_transactions (
        id, oauth_client_id, oauth_resource_id, redirect_uri, requested_scopes,
        code_challenge, code_challenge_method, protected_downstream_state,
        upstream_state_hash, upstream_nonce_hash, correlation_id, status,
        created_at, expires_at
      ) VALUES ($1,$2,$3,$4,$5,$6,'S256',$7::jsonb,$8,$9,$10,'pending',$11,$12)`,
      [
        input.id,
        input.oauthClientId,
        input.oauthResourceId,
        input.redirectUri,
        input.requestedScopes,
        input.codeChallenge,
        JSON.stringify(input.protectedDownstreamState),
        input.upstreamStateHash,
        input.upstreamNonceHash,
        input.correlationId,
        input.createdAt,
        input.expiresAt
      ]
    );
  }

  async expireStaleAuthorizationTransactions(completedAt: Date): Promise<number> {
    const result = await this.db.query(
      `WITH stale AS (
         SELECT id
         FROM oauth_authorization_transactions
         WHERE status IN ('pending', 'claimed')
           AND expires_at <= $1
         ORDER BY expires_at, id
         FOR UPDATE SKIP LOCKED
         LIMIT 100
       )
       UPDATE oauth_authorization_transactions AS transactions
       SET status = 'expired', completed_at = $1, protected_downstream_state = NULL
       FROM stale
       WHERE transactions.id = stale.id
         AND transactions.status IN ('pending', 'claimed')
         AND transactions.expires_at <= $1`,
      [completedAt]
    );
    return result.rowCount ?? 0;
  }

  async claimAuthorizationTransaction(upstreamStateHash: string, claimedAt: Date): Promise<OAuthAuthorizationTransactionRecord | null> {
    const result = await this.db.query<Record<string, unknown>>(
      `UPDATE oauth_authorization_transactions
       SET status = 'claimed', claimed_at = $2
       WHERE upstream_state_hash = $1
         AND status = 'pending'
         AND expires_at > $2
       RETURNING *`,
      [upstreamStateHash, claimedAt]
    );
    return result.rows[0] ? mapTransaction(result.rows[0]) : null;
  }

  async denyClaimedTransaction(transactionId: string, completedAt: Date): Promise<boolean> {
    const result = await this.db.query(
      `UPDATE oauth_authorization_transactions
       SET status = 'denied', completed_at = $2, protected_downstream_state = NULL
       WHERE id = $1 AND status = 'claimed'`,
      [transactionId, completedAt]
    );
    return result.rowCount === 1;
  }

  async issueAuthorizationCode(input: OAuthAuthorizationCodeIssuance): Promise<{ authorizationId: string }> {
    return this.db.transaction(async (transactionDb) => {
      const authorization = await transactionDb.query<{ id: string }>(
        `INSERT INTO oauth_authorizations (
          oauth_authorization_transaction_id, user_id, oauth_client_id, oauth_resource_id,
          granted_scopes, legacy_authorization_grant_id, correlation_id, status,
          created_at, updated_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,'active',$8,$8)
        RETURNING id`,
        [
          input.transactionId,
          input.userId,
          input.oauthClientId,
          input.oauthResourceId,
          input.grantedScopes,
          input.legacyAuthorizationGrantId,
          input.correlationId,
          input.issuedAt
        ]
      );
      const authorizationId = authorization.rows[0]?.id;
      if (!authorizationId) throw new Error("OAuth authorization creation failed");

      await transactionDb.query(
        `INSERT INTO oauth_authorization_codes (
          code_hash, oauth_authorization_transaction_id, oauth_authorization_id,
          oauth_client_id, oauth_resource_id, user_id, redirect_uri, granted_scopes,
          code_challenge, code_challenge_method, correlation_id, issued_at, expires_at
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'S256',$10,$11,$12)`,
        [
          input.codeHash,
          input.transactionId,
          authorizationId,
          input.oauthClientId,
          input.oauthResourceId,
          input.userId,
          input.redirectUri,
          input.grantedScopes,
          input.codeChallenge,
          input.correlationId,
          input.issuedAt,
          input.expiresAt
        ]
      );
      const completed = await transactionDb.query(
        `UPDATE oauth_authorization_transactions
         SET status = 'completed', completed_at = $2, protected_downstream_state = NULL
         WHERE id = $1 AND status = 'claimed' AND expires_at > $2`,
        [input.transactionId, input.issuedAt]
      );
      if (completed.rowCount !== 1) throw new Error("OAuth authorization transaction completion failed");
      return { authorizationId };
    });
  }
}
