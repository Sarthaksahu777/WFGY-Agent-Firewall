# SPEC_PHASE1

## Goal

Build a minimal pre-execution firewall for autonomous agents.

The firewall must intercept tool calls before execution, classify risky actions, block clearly dangerous operations, pause high-risk operations for human approval, and produce a readable audit trail.

## Scope

Phase 1 includes:

- interception at `before_tool_call`
- rule-based Security Critic
- lightweight Alignment Critic
- synchronous terminal approval flow
- structured audit logging
- 3 reproducible demos

## Non-goals

Phase 1 does not include:

- full WFGY semantic engine
- full Scar Ledger potential field
- OOC override path
- full Atlas telemetry integration
- multi-channel HITL integrations
- automatic policy learning
- any in-band text-triggered bypass mechanism
- any master-key-style override mechanism
- any privileged admin override path inside the normal agent conversation or tool flow

## Security boundary clarification

Phase 1 must not include any text-triggered override, hidden master key, or in-band bypass path.

Human approval in Phase 1 is limited to the explicit terminal review flow for `REVIEW` actions.
It must not function as a privileged override channel that bypasses the firewall decision process.

Any future admin or privileged override design is out of scope for Phase 1 and must be specified separately with its own authentication and security model.

## Decision contract

Every intercepted tool call must resolve to one of:

- `ALLOW`
- `REVIEW`
- `DENY`

### Required decision fields

Each decision object must include:

- `decision`
- `category`
- `reason`
- `toolName`
- `toolCallId`
- `timestamp`

Optional reserved fields for later phases:

- `riskScore`
- `semanticDriftScore`
- `scarPressure`
- `expectedEffect`
- `observedEffect`
- `failureCode`

## Interception contract

### Input

The firewall receives at least:

- `toolName`
- `toolCallId`
- `params`
- `sessionKey` if available
- `agentId` if available
- current task summary if available

### Output

The firewall returns one of:

- allow the tool call
- block the tool call
- pause and request human review

No Phase 1 output path may bypass the firewall by means of a text trigger, embedded phrase, or hidden override token.

## Security Critic requirements

Phase 1 must implement deterministic checks for at least:

- recursive delete
- delete targeting critical directories
- secret and credential access
- outbound access to non-allowlisted domains
- obviously dangerous shell execution
- production config write escalation

## Alignment Critic requirements

Phase 1 Alignment Critic can remain lightweight.

Minimum requirement:

- compare current requested action against current task scope
- escalate obvious scope mismatch
- provide a short human-readable reason

## Human review requirements

For `REVIEW` actions:

- execution must pause synchronously
- operator must see a short readable summary
- operator can return approve or reject
- final operator decision must be logged

The Phase 1 human review flow is a narrow approval step for flagged actions only.
It must not be treated as a general privileged control channel.

## Audit log requirements

Every intercepted tool call must be logged.

Minimum fields:

- timestamp
- session or agent identifiers
- tool metadata
- raw or summarized params
- firewall decision
- decision reason
- human outcome if any
- final execution result

## Demo acceptance criteria

### Demo 1
Bulk delete attempt is denied before execution.

### Demo 2
Secret read or exfil attempt is denied before execution.

### Demo 3
Risky config write is paused for human approval and can be approved or rejected.

## Reserved extension points for Phase 2

The Phase 1 code structure should keep placeholders for:

- `tool_result_persist`
- semantic drift scoring
- WFGY parameter config
- simplified scar memory
- residue validation
- structured failure tagging

Any future privileged admin control, override channel, or out-of-band authorization model must be designed as a separate Phase 2 or later extension and must not be merged implicitly into the Phase 1 firewall path.
