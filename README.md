[![APOA on A2A](https://github.com/agenticpoa/apoa-a2a/blob/main/assets/banner.png?raw=true)](https://github.com/agenticpoa/apoa)

# @apoa/a2a

APOA authorization for [A2A](https://github.com/a2aproject/A2A) agent-to-agent communication. Scoped delegation tokens, capability attenuation, audit trails.

A2A handles authentication (who are you?). This package adds authorization (what can you do, on whose behalf, for how long?).

## Install

```bash
npm install @apoa/a2a
```

## Quick Start

### Client: attach an APOA token to an A2A message

```typescript
import { attachToken, apoaHeaders } from '@apoa/a2a';

const message = {
  messageId: 'msg-001',
  role: 'user',
  parts: [{ kind: 'text', text: 'Book me a flight to Helsinki' }],
};

// Attach token to message metadata (keyed by APOA extension URI)
attachToken(message, apoaToken.raw);

// Send with APOA extension header
await fetch('https://agent.example.com/message:send', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', ...apoaHeaders() },
  body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'SendMessage', params: { message } }),
});
```

### Server: verify APOA tokens on incoming messages

```typescript
import { createA2AGuard } from '@apoa/a2a';

const guard = createA2AGuard({
  key: publicKey,
  mappings: {
    'book-flight':    'flights:book',
    'search-flights': 'flights:search',
    'cancel-flight':  'flights:cancel',
  },
});

// In your A2A agent's message handler:
const result = await guard.authorize(incomingMessage, 'book-flight');
if (!result.authorized) {
  // Transition task to AUTH_REQUIRED or reject
}
```

### Agent Card: declare APOA support

```typescript
import { apoaExtension, apoaSkillRequirement } from '@apoa/a2a';

const agentCard = {
  name: 'Travel Agent',
  version: '1.0.0',
  capabilities: {
    extensions: [apoaExtension()],
  },
  skills: [
    {
      id: 'book-flight',
      name: 'Flight Booking',
      description: 'Books flights on behalf of the user',
      securityRequirements: [apoaSkillRequirement(['flights:book'])],
    },
  ],
  // ...
};
```

## How It Works

1. Client attaches an APOA token to the A2A message's `metadata`, keyed by the APOA extension URI
2. Client sends the `A2A-Extensions` header to activate the APOA extension
3. Server extracts the token from message metadata
4. Server maps the target skill to an APOA `service:scope` pair
5. Server verifies: signature, expiration, revocation, scope, constraints, rules
6. If authorized, the skill executes. If not, the task transitions to `AUTH_REQUIRED` or is rejected

## Skill Mappings

**Simple format:**
```typescript
createA2AGuard({
  key: publicKey,
  mappings: {
    'book-flight':    'flights:book',
    'search-flights': 'flights:search',
  },
});
```

**Auto-mapping (no config):**
```typescript
createA2AGuard({ key: publicKey });
// book-flight -> book-flight:invoke
```

## Delegation Across A2A Hops

When Agent A delegates a task to Agent B, it can include an attenuated APOA token:

```typescript
import { delegate } from '@apoa/core';
import { attachToken } from '@apoa/a2a';

// Agent A delegates narrower permissions to Agent B
const childToken = await delegate(parentToken, {
  agent: { id: 'agent-b' },
  services: [{ service: 'flights', scopes: ['search'] }], // narrower than parent
}, signingOptions);

// Attach to the A2A message with the delegation chain
const message = { messageId: 'msg-002', role: 'user', parts: [{ kind: 'text', text: 'Search for flights' }] };
attachToken(message, childToken.raw, [parentToken.jti]);
```

Agent B's server verifies the token and checks the delegation chain for revocation.

## What This Adds to A2A

| Capability | A2A Native | @apoa/a2a |
|---|---|---|
| Transport auth (OAuth, API keys) | Yes | N/A (complementary) |
| Per-task scoped authorization | No ("implementation-specific") | Yes |
| Delegation chains with attenuation | No | Yes |
| Constraint checking | No | Yes |
| Hard/soft rules | No | Yes |
| Cascade revocation | No | Yes |
| Audit trail | No (recommended, not specified) | Yes |

## Part of the APOA Standard

- [APOA Spec](https://github.com/agenticpoa/apoa/blob/main/SPEC.md)
- [@apoa/core](https://www.npmjs.com/package/@apoa/core) (TypeScript SDK)
- [@apoa/mcp](https://www.npmjs.com/package/@apoa/mcp) (MCP integration)
- [apoa](https://pypi.org/project/apoa/) (Python SDK)

## License

Apache-2.0
