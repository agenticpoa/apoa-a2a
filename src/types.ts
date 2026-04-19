/**
 * Types for APOA A2A integration.
 * These are minimal A2A-compatible types so we don't depend on @a2a-js/sdk at runtime.
 */

/** APOA extension declaration for an A2A Agent Card. */
export interface APOAExtensionDeclaration {
  uri: string;
  description: string;
  required: boolean;
  params: {
    tokenFormat: 'JWT';
    algorithms: string[];
    scopeDelimiter: ':';
    wildcardSupport: boolean;
    revocationEndpoint?: string;
    auditEndpoint?: string;
  };
}

/** APOA metadata attached to an A2A message. */
export interface APOAMessageMetadata {
  /** The signed APOA JWT token. */
  token: string;
  /** Parent token IDs in the delegation chain (for quick cascade revocation lookup). */
  delegationChain?: string[];
}

/** Skill-to-scope mapping for A2A agents. */
export interface SkillMapping {
  /** A2A skill ID. */
  skillId: string;
  /** APOA service identifier. */
  service: string;
  /** APOA scope string. */
  scope: string;
}

/** Simple skill mapping format: { "skill-id": "service:scope" }. */
export type SimpleSkillMappings = Record<string, string>;

/** Result of authorizing an A2A message. */
export interface A2AAuthorizationResult {
  authorized: boolean;
  reason: string;
  tokenId?: string;
  service?: string;
  scope?: string;
  skillId?: string;
}
