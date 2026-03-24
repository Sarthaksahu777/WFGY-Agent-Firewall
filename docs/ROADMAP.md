# ROADMAP

## Phase 1

Build a small, working pre-execution firewall MVP.

Target outcomes:

- intercept tool calls before execution
- deny clearly dangerous operations
- require human approval for high-risk actions
- leave a readable audit log
- ship 3 reproducible demos

## Phase 2

Add lightweight WFGY-based stabilization features.

Candidate additions:

- semantic drift scoring
- reserved WFGY config activation
- simplified scar memory
- post-execution residue checks
- structured failure tagging

## Phase 3

Explore broader governance features.

Possible future work:

- richer policy layers
- per-session policy control
- Atlas-linked diagnostics
- broader agent runtime compatibility
- stronger observability and admin tooling

## Rule for now

Do not expand Phase 1 scope unless it directly helps ship the first working firewall gate.
