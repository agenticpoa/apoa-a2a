/**
 * APOA extension declaration for A2A Agent Cards.
 */

import { APOA_EXTENSION_URI } from './constants.js';
import type { APOAExtensionDeclaration } from './types.js';

/**
 * Create an APOA extension declaration for an A2A Agent Card.
 *
 * Add this to your Agent Card's `capabilities.extensions` array to signal
 * that your agent requires or supports APOA authorization tokens.
 *
 * @example
 * ```typescript
 * const agentCard = {
 *   name: 'My Agent',
 *   capabilities: {
 *     extensions: [apoaExtension()],
 *   },
 *   // ...
 * };
 * ```
 */
export function apoaExtension(options?: {
  required?: boolean;
  algorithms?: string[];
  revocationEndpoint?: string;
  auditEndpoint?: string;
}): APOAExtensionDeclaration {
  return {
    uri: APOA_EXTENSION_URI,
    description: 'Agentic Power of Attorney: scoped, time-bounded, revocable authorization tokens for agent actions',
    required: options?.required ?? true,
    params: {
      tokenFormat: 'JWT',
      algorithms: options?.algorithms ?? ['EdDSA', 'ES256'],
      scopeDelimiter: ':',
      wildcardSupport: true,
      revocationEndpoint: options?.revocationEndpoint,
      auditEndpoint: options?.auditEndpoint,
    },
  };
}

/**
 * Create a per-skill security requirement referencing APOA.
 * Add this to an A2A skill's `securityRequirements` to indicate
 * it requires APOA authorization with specific scopes.
 *
 * @example
 * ```typescript
 * const skill = {
 *   id: 'book-flight',
 *   name: 'Flight Booking',
 *   securityRequirements: [apoaSkillRequirement(['flights:book', 'flights:read'])],
 * };
 * ```
 */
export function apoaSkillRequirement(scopes: string[]): Record<string, string[]> {
  return { [APOA_EXTENSION_URI]: scopes };
}
