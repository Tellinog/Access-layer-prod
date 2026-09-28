import type { Db } from "../db.js";
import { isCanonicalOAuthScope } from "./validation.js";

export type NativeEntitlementResult =
  | { kind: "invalid_scope" | "not_entitled" }
  | { kind: "allowed"; grants: Array<{ scope: string; grantId: string }> };

/** Locks the exact registration and linked grants until the surrounding transaction ends. */
export async function evaluateNativeEntitlement(
  db: Db,
  input: { userId: string; oauthClientId: string; oauthResourceId: string; scopes: string[]; now: Date }
): Promise<NativeEntitlementResult> {
  const { scopes } = input;
  if (!scopes.length || new Set(scopes).size !== scopes.length ||
      scopes.some((scope) => !isCanonicalOAuthScope(scope))) return { kind: "invalid_scope" };

  const registration = await db.query<{ scope: string; scope_id: string }>(
    `SELECT scope.scope, scope.id AS scope_id
     FROM oauth_client_resource_scopes allowance
     JOIN oauth_clients client ON client.id = allowance.oauth_client_id
     JOIN oauth_resources resource ON resource.id = allowance.oauth_resource_id
     JOIN oauth_resource_scopes resource_scope
       ON resource_scope.oauth_resource_id = allowance.oauth_resource_id
      AND resource_scope.oauth_scope_id = allowance.oauth_scope_id
     JOIN oauth_scopes scope ON scope.id = allowance.oauth_scope_id
     JOIN users human ON human.id = $3
     WHERE allowance.oauth_client_id = $1 AND allowance.oauth_resource_id = $2
       AND scope.scope = ANY($4::text[])
       AND client.status = 'active' AND resource.status = 'active'
       AND resource.entitlement_mode = 'native' AND resource.audience_policy = 'exact_single_resource'
       AND human.status = 'active' AND allowance.status = 'active'
       AND resource_scope.status = 'active' AND scope.status = 'active'
     ORDER BY scope.scope
     FOR SHARE OF allowance, client, resource, resource_scope, scope, human`,
    [input.oauthClientId, input.oauthResourceId, input.userId, scopes]
  );
  if (registration.rows.length !== scopes.length ||
      new Set(registration.rows.map((row) => row.scope)).size !== scopes.length) {
    return { kind: "invalid_scope" };
  }

  const grants = await db.query<{ scope: string; grant_id: string; valid_from: Date; valid_until: Date | null }>(
    `SELECT scope.scope, native_grant.id AS grant_id,
            native_grant.valid_from, native_grant.valid_until
     FROM oauth_native_human_grants native_grant
     JOIN oauth_scopes scope ON scope.id = native_grant.oauth_scope_id
     WHERE native_grant.user_id = $1 AND native_grant.oauth_resource_id = $2
       AND scope.scope = ANY($3::text[]) AND native_grant.status = 'active'
       AND native_grant.revoked_at IS NULL AND native_grant.revoked_by_user_id IS NULL
     ORDER BY scope.scope
     FOR SHARE OF native_grant, scope`,
    [input.userId, input.oauthResourceId, scopes]
  );
  // Observe time after acquiring SHARE locks. A revocation/update that commits first
  // is visible here; one that follows waits until this transaction completes.
  const dbTime = await db.query<{ evaluated_at: Date }>("SELECT clock_timestamp() AS evaluated_at");
  const evaluatedAt = Math.max(input.now.getTime(), dbTime.rows[0]?.evaluated_at.getTime() ?? Number.NaN);
  if (grants.rows.length !== scopes.length ||
      new Set(grants.rows.map((row) => row.scope)).size !== scopes.length ||
      !Number.isFinite(evaluatedAt) ||
      grants.rows.some((row) => row.valid_from.getTime() > evaluatedAt ||
        (row.valid_until !== null && evaluatedAt >= row.valid_until.getTime()))) {
    return { kind: "not_entitled" };
  }
  return { kind: "allowed", grants: grants.rows.map((row) => ({ scope: row.scope, grantId: row.grant_id })) };
}
