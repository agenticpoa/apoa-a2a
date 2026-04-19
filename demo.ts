/**
 * @apoa/a2a Demo -- Travel Agent Scenario
 *
 * Jane authorizes a Travel Planner agent, which delegates to a Flight Booker.
 * Shows: token creation, attachment, verification, delegation, revocation.
 */

import * as jose from 'jose';
import {
  apoaExtension,
  apoaSkillRequirement,
  attachToken,
  extractToken,
  createA2AGuard,
  apoaHeaders,
  APOA_EXTENSION_URI,
} from './src/index.js';

async function main() {
  // --- Setup: generate keys ---
  console.log('='.repeat(60));
  console.log('SETUP');
  console.log('='.repeat(60));

  const janeKeys = await jose.generateKeyPair('EdDSA', { extractable: true });
  console.log('Generated Ed25519 key pair for Jane\n');

  // --- Step 1: Jane creates an APOA token ---
  console.log('='.repeat(60));
  console.log('STEP 1: Jane Creates Authorization Token');
  console.log('='.repeat(60));

  const now = Math.floor(Date.now() / 1000);
  const tokenPayload = {
    jti: `jane-token-${crypto.randomUUID().slice(0, 8)}`,
    iss: 'did:apoa:jane',
    sub: 'did:apoa:travel-planner',
    iat: now,
    exp: now + 86400, // 24 hours
    definition: {
      principal: { id: 'did:apoa:jane', name: 'Jane Doe' },
      agent: { id: 'did:apoa:travel-planner', name: 'Travel Planner' },
      agentProvider: { name: 'TravelBot Inc.' },
      services: [
        { service: 'flights', scopes: ['search', 'book', 'cancel'], constraints: { firstClass: false } },
        { service: 'hotels', scopes: ['search', 'reserve'] },
      ],
      rules: [
        { id: 'no-firstClass', enforcement: 'hard', description: 'No first class bookings' },
        { id: 'budget-alert', enforcement: 'soft', description: 'Alert if total exceeds $1000' },
      ],
      expires: new Date((now + 86400) * 1000).toISOString(),
      delegatable: true,
      maxDelegationDepth: 3,
    },
  };

  const janeToken = await new jose.CompactSign(
    new TextEncoder().encode(JSON.stringify(tokenPayload)),
  ).setProtectedHeader({ alg: 'EdDSA' }).sign(janeKeys.privateKey);

  console.log(`Token ID:    ${tokenPayload.jti}`);
  console.log(`Principal:   Jane Doe`);
  console.log(`Agent:       Travel Planner`);
  console.log(`Services:    flights (search, book, cancel), hotels (search, reserve)`);
  console.log(`Constraints: { firstClass: false }`);
  console.log(`Rules:       no-firstClass (hard), budget-alert (soft)`);
  console.log(`Expires:     24 hours`);
  console.log(`JWT:         ${janeToken.slice(0, 50)}...\n`);

  // --- Step 2: Agent Card declares APOA support ---
  console.log('='.repeat(60));
  console.log('STEP 2: Flight Booker Agent Card');
  console.log('='.repeat(60));

  const flightBookerCard = {
    name: 'Flight Booking Agent',
    version: '1.0.0',
    capabilities: {
      extensions: [apoaExtension()],
    },
    skills: [
      {
        id: 'book-flight',
        name: 'Book a Flight',
        description: 'Books flights on behalf of authorized users',
        securityRequirements: [apoaSkillRequirement(['flights:book'])],
      },
      {
        id: 'search-flights',
        name: 'Search Flights',
        description: 'Searches for available flights',
        securityRequirements: [apoaSkillRequirement(['flights:search'])],
      },
    ],
  };

  console.log(`Agent:       ${flightBookerCard.name}`);
  console.log(`Extension:   ${flightBookerCard.capabilities.extensions[0].uri}`);
  console.log(`Required:    ${flightBookerCard.capabilities.extensions[0].required}`);
  console.log(`Skills:      ${flightBookerCard.skills.map(s => s.id).join(', ')}`);
  console.log();

  // --- Step 3: Travel Planner sends message to Flight Booker ---
  console.log('='.repeat(60));
  console.log('STEP 3: Travel Planner -> Flight Booker (with APOA token)');
  console.log('='.repeat(60));

  const message = {
    messageId: `msg-${crypto.randomUUID().slice(0, 8)}`,
    role: 'user' as const,
    parts: [{ kind: 'text' as const, text: 'Book SFO to HEL, May 15, economy class' }],
    metadata: undefined as Record<string, unknown> | undefined,
  };

  attachToken(message, janeToken);

  const headers = apoaHeaders();
  console.log(`Message:     "${message.parts[0].text}"`);
  console.log(`Token:       attached in metadata[${APOA_EXTENSION_URI.slice(0, 40)}...]`);
  console.log(`Headers:     ${JSON.stringify(headers)}`);
  console.log();

  // --- Step 4: Flight Booker verifies the token ---
  console.log('='.repeat(60));
  console.log('STEP 4: Flight Booker Verifies Authorization');
  console.log('='.repeat(60));

  const auditLog: Array<{ action: string; result: string; details?: Record<string, unknown> }> = [];
  const revokedTokens = new Map<string, { tokenId: string; revokedAt: Date; revokedBy: string }>();

  const guard = createA2AGuard({
    key: janeKeys.publicKey,
    mappings: {
      'book-flight': 'flights:book',
      'search-flights': 'flights:search',
      'cancel-flight': 'flights:cancel',
      'reserve-hotel': 'hotels:reserve',
    },
    revocationStore: {
      async check(id) { return revokedTokens.get(id) ?? null; },
      async checkAny(ids) { for (const id of ids) { const r = revokedTokens.get(id); if (r) return r; } return null; },
    },
    auditStore: {
      async append(entry) { auditLog.push(entry as any); },
    },
  });

  const checks = [
    { skill: 'search-flights', desc: 'Search for flights' },
    { skill: 'book-flight', desc: 'Book a flight (economy)' },
    { skill: 'reserve-hotel', desc: 'Reserve a hotel' },
    { skill: 'cancel-flight', desc: 'Cancel a flight' },
  ];

  for (const { skill, desc } of checks) {
    const result = await guard.authorize(message, skill);
    const status = result.authorized ? 'ALLOWED' : 'DENIED';
    console.log(`  [${status.padEnd(7)}] ${desc.padEnd(30)} | ${result.service}:${result.scope}`);
    if (!result.authorized) {
      console.log(`            Reason: ${result.reason}`);
    }
  }
  console.log();

  // --- Step 5: Test denied actions ---
  console.log('='.repeat(60));
  console.log('STEP 5: Denied Actions');
  console.log('='.repeat(60));

  // No token
  const noTokenResult = await guard.authorize({}, 'book-flight');
  console.log(`  [${noTokenResult.authorized ? 'ALLOWED' : 'DENIED'.padEnd(7)}] No token provided`);
  console.log(`            Reason: ${noTokenResult.reason}`);

  // Wrong key
  const wrongKeys = await jose.generateKeyPair('EdDSA', { extractable: true });
  const wrongGuard = createA2AGuard({ key: wrongKeys.publicKey, mappings: { 'book-flight': 'flights:book' } });
  const wrongKeyResult = await wrongGuard.authorize(message, 'book-flight');
  console.log(`  [${wrongKeyResult.authorized ? 'ALLOWED' : 'DENIED'.padEnd(7)}] Wrong verification key`);
  console.log(`            Reason: ${wrongKeyResult.reason}`);

  // Unmapped skill (autoMapping off)
  const strictGuard = createA2AGuard({ key: janeKeys.publicKey, autoMapping: false, denyUnmapped: true });
  const unmappedResult = await strictGuard.authorize(message, 'unknown-skill');
  console.log(`  [${unmappedResult.authorized ? 'ALLOWED' : 'DENIED'.padEnd(7)}] Unmapped skill (strict mode)`);
  console.log(`            Reason: ${unmappedResult.reason}`);

  // Hard rule: firstClass
  const firstClassGuard = createA2AGuard({
    key: janeKeys.publicKey,
    mappings: { 'book-first': 'flights:firstClass' },
  });
  const firstClassResult = await firstClassGuard.authorize(message, 'book-first');
  console.log(`  [${firstClassResult.authorized ? 'ALLOWED' : 'DENIED'.padEnd(7)}] Book first class (hard rule)`);
  console.log(`            Reason: ${firstClassResult.reason}`);
  console.log();

  // --- Step 6: Revocation ---
  console.log('='.repeat(60));
  console.log('STEP 6: Jane Revokes the Token');
  console.log('='.repeat(60));

  const preRevoke = await guard.authorize(message, 'book-flight');
  console.log(`  Before revoke: book-flight = ${preRevoke.authorized ? 'ALLOWED' : 'DENIED'}`);

  revokedTokens.set(tokenPayload.jti, {
    tokenId: tokenPayload.jti,
    revokedAt: new Date(),
    revokedBy: 'did:apoa:jane',
  });

  const postRevoke = await guard.authorize(message, 'book-flight');
  console.log(`  After revoke:  book-flight = ${postRevoke.authorized ? 'ALLOWED' : 'DENIED'}`);
  console.log(`            Reason: ${postRevoke.reason}`);
  console.log();

  // --- Step 7: Audit trail ---
  console.log('='.repeat(60));
  console.log('STEP 7: Audit Trail');
  console.log('='.repeat(60));

  for (const entry of auditLog) {
    console.log(`  ${entry.action.padEnd(20)} | ${entry.result.padEnd(10)} | ${JSON.stringify(entry.details ?? {})}`);
  }
  console.log();

  console.log('='.repeat(60));
  console.log('Done. APOA authorization for A2A in action.');
  console.log('='.repeat(60));
}

main().catch(console.error);
