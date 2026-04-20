# VANTIX Architecture

This document expands on the main README and explains how VANTIX is structured as an operator-facing offensive security control plane.

## High-level layers

### UI shell
The frontend is a React + Vite application that centers the operator around:
- orchestrator chat
- run selection
- agent timeline
- terminal stream
- vectors
- memory
- CVE intel
- approvals
- results
- runtime settings

### Control plane
The FastAPI backend exposes the main product surface:
- chat entrypoint
- run review
- vectors
- attack chains
- skills
- providers
- tools
- system status
- install status

### Durable workflow layer
The workflow layer gives execution structure:
- workflow execution records
- phase runs
- checkpoints
- worker leases
- run metrics

### Worker runtime
The worker claims work and updates:
- completion
- retry
- blocked
- failure

### Reporting and output
Results are synthesized into:
- findings
- artifacts
- vectors
- terminal summary
- report path
- handoff state

## Why the design matters

The point of this architecture is not complexity for its own sake.

It gives VANTIX a better shape for:
- long-running work
- operator intervention
- state continuity
- evidence-backed review
- repeatable benchmarking

## Runtime storage

Runtime data is stored under a user-owned local state root by default. That makes local deployment simpler and reduces common permission problems.

## Core design goals

1. Chat-first orchestration
2. Durable execution
3. Reviewable action selection
4. Compact agent prompts through skill packs
5. Machine-readable handoffs
6. Evidence-first reporting
