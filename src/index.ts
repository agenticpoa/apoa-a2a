/**
 * @apoa/a2a — APOA authorization for A2A agent-to-agent communication.
 */

// Constants
export { APOA_EXTENSION_URI, A2A_EXTENSIONS_HEADER, APOA_METADATA_KEY } from './constants.js';

// Extension declaration for Agent Cards
export { apoaExtension, apoaSkillRequirement } from './extension.js';

// Client utilities (attach/extract tokens, create headers)
export { attachToken, extractToken, extractDelegationChain, apoaHeaders } from './client.js';

// Server guard (authorize incoming A2A messages)
export { createA2AGuard, type A2AGuardOptions } from './guard.js';

// Types
export type {
  APOAExtensionDeclaration,
  APOAMessageMetadata,
  SkillMapping,
  SimpleSkillMappings,
  A2AAuthorizationResult,
} from './types.js';
