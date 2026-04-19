/**
 * Client-side utilities for attaching APOA tokens to A2A messages.
 */

import { APOA_EXTENSION_URI, A2A_EXTENSIONS_HEADER, APOA_METADATA_KEY } from './constants.js';
import type { APOAMessageMetadata } from './types.js';

/**
 * Attach an APOA token to an A2A message's metadata.
 *
 * Call this before sending a message to an A2A agent that requires APOA authorization.
 * The token is placed in `message.metadata` keyed by the APOA extension URI.
 *
 * @example
 * ```typescript
 * const message = {
 *   messageId: 'msg-001',
 *   role: 'user',
 *   parts: [{ kind: 'text', text: 'Book me a flight' }],
 * };
 *
 * attachToken(message, apoaToken.raw);
 * await client.sendMessage({ message });
 * ```
 */
export function attachToken(
  message: { metadata?: Record<string, unknown> },
  token: string,
  delegationChain?: string[],
): void {
  if (!message.metadata) {
    message.metadata = {};
  }

  const apoaMetadata: APOAMessageMetadata = { token };
  if (delegationChain && delegationChain.length > 0) {
    apoaMetadata.delegationChain = delegationChain;
  }

  message.metadata[APOA_METADATA_KEY] = apoaMetadata;
}

/**
 * Extract an APOA token from an A2A message's metadata.
 *
 * @returns The raw JWT string, or null if no APOA token is present.
 */
export function extractToken(message: { metadata?: Record<string, unknown> }): string | null {
  const apoaData = message.metadata?.[APOA_METADATA_KEY] as APOAMessageMetadata | undefined;
  if (apoaData?.token && typeof apoaData.token === 'string') {
    return apoaData.token;
  }
  return null;
}

/**
 * Extract the delegation chain from an A2A message's APOA metadata.
 *
 * @returns Array of parent token IDs, or empty array.
 */
export function extractDelegationChain(message: { metadata?: Record<string, unknown> }): string[] {
  const apoaData = message.metadata?.[APOA_METADATA_KEY] as APOAMessageMetadata | undefined;
  return apoaData?.delegationChain ?? [];
}

/**
 * Create HTTP headers for APOA-enabled A2A requests.
 *
 * Adds the APOA extension URI to the `A2A-Extensions` header and optionally
 * sets the `Authorization` header with the APOA token as a Bearer credential.
 *
 * @example
 * ```typescript
 * const headers = apoaHeaders(token.raw);
 * // { 'A2A-Extensions': 'https://apoa-protocol.org/extensions/authorization/v1',
 * //   'Authorization': 'Bearer eyJ...' }
 *
 * fetch('https://agent.example.com/message:send', {
 *   method: 'POST',
 *   headers: { 'Content-Type': 'application/json', ...headers },
 *   body: JSON.stringify(request),
 * });
 * ```
 */
export function apoaHeaders(token?: string): Record<string, string> {
  const headers: Record<string, string> = {
    [A2A_EXTENSIONS_HEADER]: APOA_EXTENSION_URI,
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}
