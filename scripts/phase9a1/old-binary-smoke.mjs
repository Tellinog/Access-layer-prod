import { randomBytes, randomUUID } from "node:crypto";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const databaseUrl = process.env.PHASE9A1_SOURCE_DATABASE_URL;
const oldDistRoot = process.env.PHASE9A1_OLD_DIST_ROOT;
if (!databaseUrl || !oldDistRoot) throw new Error("Missing old-binary smoke inputs");
const target = new URL(databaseUrl);
if (target.hostname !== "127.0.0.1" || !target.pathname.includes("phase9a1") || !target.pathname.includes("test")) {
  throw new Error("Unsafe old-binary smoke target");
}
const oldDbModule = await import(pathToFileURL(resolve(oldDistRoot, "src/db.js")).href);
const oldFlowModule = await import(pathToFileURL(resolve(oldDistRoot, "src/oauth/flow-repository.js")).href);
const oldFoundationModule = await import(pathToFileURL(resolve(oldDistRoot, "src/oauth/repository.js")).href);
const db = new oldDbModule.PostgresDb(databaseUrl);

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

try {
  const user = (await db.query("SELECT id FROM users WHERE google_sub = 'phase9a1-synthetic-sub'")).rows[0]?.id;
  const client = (await db.query("SELECT id FROM oauth_clients WHERE client_id = 'phase9a1-test-bff'")).rows[0]?.id;
  const legacyResourceUri = "https://legacy.phase9a1.example.test/api";
  const nativeResourceUri = "https://native.phase9a1.example.test/api";
  const foundation = new oldFoundationModule.OAuthFoundationRepository(db);
  const legacyResource = await foundation.resolveResourceByResourceId(legacyResourceUri);
  const nativeResource = await foundation.resolveResourceByResourceId(nativeResourceUri);
  const legacyGrant = (await db.query("SELECT id FROM authorization_grants WHERE user_id = $1", [user])).rows[0]?.id;
  assert(user && client && legacyResource && nativeResource && legacyGrant, "old-binary fixture absent");
  assert((await foundation.resolveActiveLegacyEntitlement(legacyResource.id)) !== null,
    "old binary cannot read legacy entitlement");
  assert((await foundation.resolveActiveLegacyEntitlement(nativeResource.id)) === null,
    "old binary saw an entitlement for native resource");

  const oldFlow = new oldFlowModule.OAuthAuthorizationFlowRepository(db);
  async function prepareTransaction(resourceId) {
    return (await db.query(`INSERT INTO oauth_authorization_transactions
      (oauth_client_id, oauth_resource_id, redirect_uri, requested_scopes, code_challenge,
       protected_downstream_state, upstream_state_hash, upstream_nonce_hash,
       correlation_id, status, claimed_at, expires_at)
      VALUES ($1, $2, 'https://client.phase9a1.example.test/callback',
        ARRAY['synthetic:records:read']::text[], $3, '{}'::jsonb, $4, $5,
        $6, 'claimed', now(), now() + interval '600 seconds') RETURNING id`,
    [client, resourceId, "a".repeat(43), randomBytes(32).toString("base64url"),
      randomBytes(32).toString("base64url"), randomUUID()])).rows[0].id;
  }
  async function issue(resourceId, transactionId) {
    const issuedAt = new Date();
    return oldFlow.issueAuthorizationCode({
      transactionId,
      userId: user,
      oauthClientId: client,
      oauthResourceId: resourceId,
      legacyAuthorizationGrantId: legacyGrant,
      grantedScopes: ["synthetic:records:read"],
      redirectUri: "https://client.phase9a1.example.test/callback",
      codeChallenge: "a".repeat(43),
      codeHash: randomBytes(32).toString("base64url"),
      correlationId: randomUUID(),
      issuedAt,
      expiresAt: new Date(issuedAt.getTime() + 60_000)
    });
  }
  const legacyTx = await prepareTransaction(legacyResource.id);
  const issued = await issue(legacyResource.id, legacyTx);
  const legacySource = (await db.query("SELECT entitlement_source FROM oauth_authorizations WHERE id = $1",
    [issued.authorizationId])).rows[0]?.entitlement_source;
  assert(legacySource === "legacy_bridge", "old binary did not preserve P0 authorization source");
  const nativeTx = await prepareTransaction(nativeResource.id);
  let nativeDenied = false;
  try {
    await issue(nativeResource.id, nativeTx);
  } catch {
    nativeDenied = true;
  }
  const nativeInserted = (await db.query("SELECT count(*) AS count FROM oauth_authorizations WHERE oauth_authorization_transaction_id = $1",
    [nativeTx])).rows[0]?.count;
  assert(nativeDenied && Number(nativeInserted) === 0, "old binary did not fail closed on native resource");
  console.log(JSON.stringify({
    qualification: "phase9a1-previous-binary",
    legacyRead: "passed",
    legacyAuthorizationIssuance: "passed",
    nativeAuthorizationFailClosed: "passed"
  }));
} finally {
  await db.close();
}
