/**
 * Server-side APOA authorization guard for A2A agents.
 *
 * Verifies APOA tokens attached to incoming A2A messages and authorizes
 * actions based on skill-to-scope mappings.
 */

import {
  matchScope,
  type APOAToken,
  type AuthorizationResult,
} from '@apoa/core';
import * as jose from 'jose';
import { APOA_METADATA_KEY } from './constants.js';
import { extractToken } from './client.js';
import type {
  A2AAuthorizationResult,
  SimpleSkillMappings,
  SkillMapping,
} from './types.js';

export interface A2AGuardOptions {
  /** Public key for token verification. */
  key: Parameters<typeof jose.jwtVerify>[1];

  /** Skill-to-scope mappings. Simple: { "book-flight": "flights:book" }
   *  Or full: [{ skillId: "book-flight", service: "flights", scope: "book" }] */
  mappings?: SimpleSkillMappings | SkillMapping[];

  /** Deny messages targeting skills with no mapping (default: true). */
  denyUnmapped?: boolean;

  /** Auto-map unmapped skills to skill_id -> skill_id:invoke (default: true). */
  autoMapping?: boolean;

  /** Clock skew tolerance in seconds (default: 30). */
  clockSkewSeconds?: number;

  /** Revocation store for checking revoked tokens. */
  revocationStore?: {
    check(tokenId: string): Promise<{ tokenId: string; revokedAt: Date; revokedBy: string } | null>;
    checkAny?(tokenIds: string[]): Promise<{ tokenId: string; revokedAt: Date; revokedBy: string } | null>;
  };

  /** Audit store for logging authorization decisions. */
  auditStore?: {
    append(entry: {
      tokenId: string;
      timestamp: Date;
      action: string;
      service: string;
      result: 'allowed' | 'denied' | 'escalated';
      details?: Record<string, unknown>;
    }): Promise<void>;
  };
}

function normalizeSkillMappings(mappings?: SimpleSkillMappings | SkillMapping[]): SkillMapping[] {
  if (!mappings) return [];
  if (Array.isArray(mappings)) return mappings;

  return Object.entries(mappings).map(([skillId, mapping]) => {
    const firstColon = mapping.indexOf(':');
    if (firstColon === -1) {
      return { skillId, service: mapping, scope: 'invoke' };
    }
    return { skillId, service: mapping.slice(0, firstColon), scope: mapping.slice(firstColon + 1) };
  });
}

/**
 * Create an APOA authorization guard for A2A messages.
 *
 * @example
 * ```typescript
 * const guard = createA2AGuard({
 *   key: publicKey,
 *   mappings: {
 *     'book-flight': 'flights:book',
 *     'search-flights': 'flights:search',
 *   },
 * });
 *
 * // In your A2A agent's message handler:
 * const result = await guard.authorize(message, 'book-flight');
 * if (!result.authorized) {
 *   // Return AUTH_REQUIRED or reject
 * }
 * ```
 */
export function createA2AGuard(options: A2AGuardOptions) {
  const skillMappings = normalizeSkillMappings(options.mappings);
  const denyUnmapped = options.denyUnmapped ?? true;
  const autoMapping = options.autoMapping ?? true;
  const clockSkew = options.clockSkewSeconds ?? 30;

  function resolveSkillMapping(skillId: string): { service: string; scope: string } | null {
    const mapping = skillMappings.find(m => m.skillId === skillId);
    if (mapping) return { service: mapping.service, scope: mapping.scope };

    // Auto-mapping: skill_id -> skill_id:invoke
    if (autoMapping) {
      return { service: skillId, scope: `${skillId}:invoke` };
    }

    return null;
  }

  async function authorize(
    message: { metadata?: Record<string, unknown> },
    skillId: string,
  ): Promise<A2AAuthorizationResult> {
    // 1. Extract token
    const rawToken = extractToken(message);
    if (!rawToken) {
      return { authorized: false, reason: 'No APOA token in message metadata', skillId };
    }

    // 2. Resolve skill -> service:scope
    const mapping = resolveSkillMapping(skillId);
    if (!mapping) {
      if (denyUnmapped) {
        return { authorized: false, reason: `Skill '${skillId}' has no APOA mapping and denyUnmapped is enabled`, skillId };
      }
      return { authorized: true, reason: `Skill '${skillId}' has no mapping but denyUnmapped is disabled`, skillId };
    }

    // 3. Verify JWT signature
    let payload: jose.JWTPayload;
    try {
      const { payload: p } = await jose.jwtVerify(rawToken, options.key, {
        clockTolerance: clockSkew,
      });
      payload = p;
    } catch {
      return { authorized: false, reason: 'Token signature verification failed', skillId };
    }

    const tokenId = payload.jti;
    if (!tokenId) {
      return { authorized: false, reason: 'Token has no jti claim', skillId };
    }

    // 4. Check revocation
    if (options.revocationStore) {
      const apoaData = message.metadata?.[APOA_METADATA_KEY] as { delegationChain?: string[] } | undefined;
      const tokenIdsToCheck = [tokenId, ...(apoaData?.delegationChain ?? [])];

      const revRecord = options.revocationStore.checkAny
        ? await options.revocationStore.checkAny(tokenIdsToCheck)
        : await options.revocationStore.check(tokenId);

      if (revRecord) {
        const ancestorNote = revRecord.tokenId !== tokenId ? ` (ancestor ${revRecord.tokenId})` : '';
        await logAudit(tokenId, skillId, mapping, 'denied', `Token revoked${ancestorNote}`);
        return {
          authorized: false,
          reason: `Token has been revoked${ancestorNote}`,
          tokenId, service: mapping.service, scope: mapping.scope, skillId,
        };
      }
    }

    // 5. Check scope
    const definition = payload.definition as Record<string, unknown> | undefined;
    if (!definition) {
      await logAudit(tokenId, skillId, mapping, 'denied', 'No definition in token');
      return { authorized: false, reason: 'Token has no definition claim', tokenId, skillId };
    }

    const services = definition.services as Array<{ service: string; scopes: string[]; constraints?: Record<string, unknown> }> | undefined;
    if (!services) {
      await logAudit(tokenId, skillId, mapping, 'denied', 'No services in definition');
      return { authorized: false, reason: 'Token definition has no services', tokenId, skillId };
    }

    const serviceAuth = services.find(s => s.service === mapping.service);
    if (!serviceAuth) {
      await logAudit(tokenId, skillId, mapping, 'denied', 'Service not authorized');
      return {
        authorized: false,
        reason: `Service '${mapping.service}' not found in token`,
        tokenId, service: mapping.service, scope: mapping.scope, skillId,
      };
    }

    const scopeAllowed = serviceAuth.scopes.some(s => matchScope(s, mapping.scope));
    if (!scopeAllowed) {
      await logAudit(tokenId, skillId, mapping, 'denied', 'Scope not authorized');
      return {
        authorized: false,
        reason: `Scope '${mapping.scope}' not in authorized scopes [${serviceAuth.scopes.join(', ')}]`,
        tokenId, service: mapping.service, scope: mapping.scope, skillId,
      };
    }

    // 6. Check constraints
    if (serviceAuth.constraints) {
      const actionSegments = mapping.scope.split(':');
      for (const [key, value] of Object.entries(serviceAuth.constraints)) {
        if (value === false && actionSegments.includes(key)) {
          await logAudit(tokenId, skillId, mapping, 'denied', `Constraint '${key}' blocked`);
          return {
            authorized: false,
            reason: `Constraint '${key}' is set to false`,
            tokenId, service: mapping.service, scope: mapping.scope, skillId,
          };
        }
      }
    }

    // 7. Check hard rules
    const rules = definition.rules as Array<{ id: string; enforcement: string }> | undefined;
    if (rules) {
      for (const rule of rules) {
        if (rule.enforcement === 'hard') {
          const ruleKey = rule.id.startsWith('no-') ? rule.id.slice(3) : rule.id;
          const actionSegments = mapping.scope.toLowerCase().split(':');
          if (actionSegments.includes(ruleKey.toLowerCase())) {
            await logAudit(tokenId, skillId, mapping, 'denied', `Hard rule '${rule.id}' violated`);
            return {
              authorized: false,
              reason: `Hard rule '${rule.id}' violated`,
              tokenId, service: mapping.service, scope: mapping.scope, skillId,
            };
          }
        }
      }
    }

    // Authorized
    await logAudit(tokenId, skillId, mapping, 'allowed');
    return {
      authorized: true,
      reason: `Authorized: skill '${skillId}' -> ${mapping.service}:${mapping.scope}`,
      tokenId, service: mapping.service, scope: mapping.scope, skillId,
    };
  }

  async function logAudit(
    tokenId: string,
    skillId: string,
    mapping: { service: string; scope: string },
    result: 'allowed' | 'denied' | 'escalated',
    details?: string,
  ): Promise<void> {
    if (!options.auditStore) return;
    await options.auditStore.append({
      tokenId,
      timestamp: new Date(),
      action: mapping.scope,
      service: mapping.service,
      result,
      details: details ? { skillId, reason: details } : { skillId },
    });
  }

  return { authorize, resolveSkillMapping };
}
