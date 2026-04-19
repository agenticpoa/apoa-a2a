import { describe, it, expect, beforeEach } from 'vitest';
import * as jose from 'jose';
import {
  APOA_EXTENSION_URI,
  A2A_EXTENSIONS_HEADER,
  apoaExtension,
  apoaSkillRequirement,
  attachToken,
  extractToken,
  extractDelegationChain,
  apoaHeaders,
  createA2AGuard,
} from '../src/index.js';

// Helper: create a signed APOA-style JWT
async function createToken(
  privateKey: CryptoKey,
  overrides?: {
    services?: Array<{ service: string; scopes: string[]; constraints?: Record<string, unknown> }>;
    rules?: Array<{ id: string; enforcement: string; description: string }>;
    exp?: number;
  },
) {
  const now = Math.floor(Date.now() / 1000);
  const payload: Record<string, unknown> = {
    jti: `test-${crypto.randomUUID()}`,
    iss: 'test-principal',
    sub: 'test-agent',
    iat: now,
    exp: overrides?.exp ?? now + 3600,
    definition: {
      principal: { id: 'test-principal' },
      agent: { id: 'test-agent' },
      services: overrides?.services ?? [
        { service: 'flights', scopes: ['book', 'search', 'cancel'] },
        { service: 'hotels', scopes: ['search', 'reserve'] },
      ],
      rules: overrides?.rules,
    },
  };

  return new jose.CompactSign(
    new TextEncoder().encode(JSON.stringify(payload)),
  )
    .setProtectedHeader({ alg: 'EdDSA' })
    .sign(privateKey);
}

describe('Extension declaration', () => {
  it('creates default extension declaration', () => {
    const ext = apoaExtension();
    expect(ext.uri).toBe(APOA_EXTENSION_URI);
    expect(ext.required).toBe(true);
    expect(ext.params.tokenFormat).toBe('JWT');
    expect(ext.params.algorithms).toEqual(['EdDSA', 'ES256']);
    expect(ext.params.wildcardSupport).toBe(true);
  });

  it('creates extension with custom options', () => {
    const ext = apoaExtension({
      required: false,
      algorithms: ['EdDSA'],
      revocationEndpoint: 'https://example.com/revoke',
    });
    expect(ext.required).toBe(false);
    expect(ext.params.algorithms).toEqual(['EdDSA']);
    expect(ext.params.revocationEndpoint).toBe('https://example.com/revoke');
  });

  it('creates skill security requirement', () => {
    const req = apoaSkillRequirement(['flights:book', 'flights:read']);
    expect(req[APOA_EXTENSION_URI]).toEqual(['flights:book', 'flights:read']);
  });
});

describe('Client utilities', () => {
  it('attaches token to message metadata', () => {
    const message: { metadata?: Record<string, unknown> } = {};
    attachToken(message, 'my-jwt-token');
    expect(message.metadata?.[APOA_EXTENSION_URI]).toEqual({ token: 'my-jwt-token' });
  });

  it('attaches token with delegation chain', () => {
    const message: { metadata?: Record<string, unknown> } = {};
    attachToken(message, 'child-jwt', ['parent-id-1', 'root-id-0']);
    const meta = message.metadata?.[APOA_EXTENSION_URI] as { token: string; delegationChain: string[] };
    expect(meta.token).toBe('child-jwt');
    expect(meta.delegationChain).toEqual(['parent-id-1', 'root-id-0']);
  });

  it('preserves existing metadata', () => {
    const message = { metadata: { 'other-ext': { foo: 'bar' } } };
    attachToken(message, 'jwt');
    expect(message.metadata['other-ext']).toEqual({ foo: 'bar' });
    expect(message.metadata[APOA_EXTENSION_URI]).toBeDefined();
  });

  it('extracts token from message metadata', () => {
    const message = { metadata: { [APOA_EXTENSION_URI]: { token: 'my-jwt' } } };
    expect(extractToken(message)).toBe('my-jwt');
  });

  it('returns null when no token', () => {
    expect(extractToken({})).toBeNull();
    expect(extractToken({ metadata: {} })).toBeNull();
    expect(extractToken({ metadata: { other: 'value' } })).toBeNull();
  });

  it('extracts delegation chain', () => {
    const message = {
      metadata: {
        [APOA_EXTENSION_URI]: { token: 'jwt', delegationChain: ['parent-1'] },
      },
    };
    expect(extractDelegationChain(message)).toEqual(['parent-1']);
  });

  it('returns empty array when no chain', () => {
    expect(extractDelegationChain({})).toEqual([]);
    expect(extractDelegationChain({ metadata: { [APOA_EXTENSION_URI]: { token: 'jwt' } } })).toEqual([]);
  });

  it('creates APOA headers', () => {
    const headers = apoaHeaders('my-token');
    expect(headers[A2A_EXTENSIONS_HEADER]).toBe(APOA_EXTENSION_URI);
    expect(headers['Authorization']).toBe('Bearer my-token');
  });

  it('creates headers without token', () => {
    const headers = apoaHeaders();
    expect(headers[A2A_EXTENSIONS_HEADER]).toBe(APOA_EXTENSION_URI);
    expect(headers['Authorization']).toBeUndefined();
  });
});

describe('A2A Guard', () => {
  let privateKey: CryptoKey;
  let publicKey: CryptoKey;

  beforeEach(async () => {
    const keyPair = await jose.generateKeyPair('EdDSA', { extractable: true });
    privateKey = keyPair.privateKey as CryptoKey;
    publicKey = keyPair.publicKey as CryptoKey;
  });

  it('authorizes valid token with matching scope', async () => {
    const guard = createA2AGuard({
      key: publicKey,
      mappings: { 'book-flight': 'flights:book' },
    });

    const token = await createToken(privateKey);
    const message: { metadata?: Record<string, unknown> } = {};
    attachToken(message, token);

    const result = await guard.authorize(message, 'book-flight');
    expect(result.authorized).toBe(true);
    expect(result.service).toBe('flights');
    expect(result.scope).toBe('book');
  });

  it('denies when no token present', async () => {
    const guard = createA2AGuard({ key: publicKey });
    const result = await guard.authorize({}, 'book-flight');
    expect(result.authorized).toBe(false);
    expect(result.reason).toContain('No APOA token');
  });

  it('denies when scope not authorized', async () => {
    const guard = createA2AGuard({
      key: publicKey,
      mappings: { 'delete-flight': 'flights:delete' },
    });

    const token = await createToken(privateKey);
    const message: { metadata?: Record<string, unknown> } = {};
    attachToken(message, token);

    const result = await guard.authorize(message, 'delete-flight');
    expect(result.authorized).toBe(false);
    expect(result.reason).toContain('not in authorized scopes');
  });

  it('denies when service not in token', async () => {
    const guard = createA2AGuard({
      key: publicKey,
      mappings: { 'order-food': 'restaurant:order' },
    });

    const token = await createToken(privateKey);
    const message: { metadata?: Record<string, unknown> } = {};
    attachToken(message, token);

    const result = await guard.authorize(message, 'order-food');
    expect(result.authorized).toBe(false);
    expect(result.reason).toContain("Service 'restaurant' not found");
  });

  it('denies with invalid signature', async () => {
    const guard = createA2AGuard({ key: publicKey });
    const otherKey = await jose.generateKeyPair('EdDSA', { extractable: true });
    const token = await createToken(otherKey.privateKey as CryptoKey);
    const message: { metadata?: Record<string, unknown> } = {};
    attachToken(message, token);

    const result = await guard.authorize(message, 'book-flight');
    expect(result.authorized).toBe(false);
    expect(result.reason).toContain('signature verification failed');
  });

  it('denies when constraint blocks action', async () => {
    const guard = createA2AGuard({
      key: publicKey,
      mappings: { 'book-flight': 'flights:book' },
    });

    const token = await createToken(privateKey, {
      services: [{ service: 'flights', scopes: ['book', 'search'], constraints: { book: false } }],
    });
    const message: { metadata?: Record<string, unknown> } = {};
    attachToken(message, token);

    const result = await guard.authorize(message, 'book-flight');
    expect(result.authorized).toBe(false);
    expect(result.reason).toContain("Constraint 'book'");
  });

  it('denies when hard rule blocks action', async () => {
    const guard = createA2AGuard({
      key: publicKey,
      mappings: { 'book-flight': 'flights:book' },
    });

    const token = await createToken(privateKey, {
      services: [{ service: 'flights', scopes: ['book'] }],
      rules: [{ id: 'no-book', enforcement: 'hard', description: 'No booking' }],
    });
    const message: { metadata?: Record<string, unknown> } = {};
    attachToken(message, token);

    const result = await guard.authorize(message, 'book-flight');
    expect(result.authorized).toBe(false);
    expect(result.reason).toContain("Hard rule 'no-book'");
  });

  it('auto-maps unmapped skills to skill_id:invoke', async () => {
    const guard = createA2AGuard({ key: publicKey });

    const token = await createToken(privateKey, {
      services: [{ service: 'custom-skill', scopes: ['custom-skill:invoke'] }],
    });
    const message: { metadata?: Record<string, unknown> } = {};
    attachToken(message, token);

    const result = await guard.authorize(message, 'custom-skill');
    expect(result.authorized).toBe(true);
  });

  it('denies unmapped skill when autoMapping is false and denyUnmapped is true', async () => {
    const guard = createA2AGuard({ key: publicKey, autoMapping: false, denyUnmapped: true });

    const token = await createToken(privateKey);
    const message: { metadata?: Record<string, unknown> } = {};
    attachToken(message, token);

    const result = await guard.authorize(message, 'unknown-skill');
    expect(result.authorized).toBe(false);
    expect(result.reason).toContain('no APOA mapping');
  });

  it('checks revocation', async () => {
    const revokedTokens = new Map<string, { tokenId: string; revokedAt: Date; revokedBy: string }>();
    const guard = createA2AGuard({
      key: publicKey,
      mappings: { 'book-flight': 'flights:book' },
      revocationStore: {
        async check(tokenId) { return revokedTokens.get(tokenId) ?? null; },
        async checkAny(tokenIds) {
          for (const id of tokenIds) {
            const r = revokedTokens.get(id);
            if (r) return r;
          }
          return null;
        },
      },
    });

    const token = await createToken(privateKey);
    const decoded = jose.decodeJwt(token);
    const message: { metadata?: Record<string, unknown> } = {};
    attachToken(message, token);

    // Before revocation
    const r1 = await guard.authorize(message, 'book-flight');
    expect(r1.authorized).toBe(true);

    // Revoke
    revokedTokens.set(decoded.jti!, { tokenId: decoded.jti!, revokedAt: new Date(), revokedBy: 'admin' });

    const r2 = await guard.authorize(message, 'book-flight');
    expect(r2.authorized).toBe(false);
    expect(r2.reason).toContain('revoked');
  });

  it('logs audit entries', async () => {
    const entries: Array<{ tokenId: string; action: string; result: string }> = [];
    const guard = createA2AGuard({
      key: publicKey,
      mappings: { 'book-flight': 'flights:book' },
      auditStore: {
        async append(entry) { entries.push(entry as any); },
      },
    });

    const token = await createToken(privateKey);
    const message: { metadata?: Record<string, unknown> } = {};
    attachToken(message, token);

    await guard.authorize(message, 'book-flight');
    expect(entries).toHaveLength(1);
    expect(entries[0].result).toBe('allowed');
    expect(entries[0].action).toBe('book');
  });
});
