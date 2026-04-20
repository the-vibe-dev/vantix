# VANTIX Benchmarking Direction

VANTIX should be evaluated as an autonomous pentest framework first, and a broader offensive security operating platform second.

## Core benchmark modes

### Black-box
Only externally visible access:
- URL / hostname / IP
- no source
- no hints

### Gray-box
Externally visible access plus:
- standard user credentials
- normal application access
- still no source

### White-box
Target plus:
- repo or source tree
- configuration context
- deeper correlation and exploit planning

## Good target classes

- OWASP Juice Shop
- OWASP crAPI
- c{api}tal API
- modified forks of public labs
- internal seeded applications

## What to measure

- validated findings
- exploit success rate
- false positives
- time to first valid finding
- coverage
- evidence quality
- score by severity

## Suggested scoring

- Critical: 10
- High: 7
- Medium: 4
- Low: 1
- False positive: -5

## Practical rollout

1. Start with black-box on a small target set
2. Add gray-box where auth is meaningful
3. Add white-box for source-aware comparison
4. Run nightly regression suites
5. Publish benchmark deltas by version

## Why this matters

Benchmarking should reflect how VANTIX is intended to operate:
- with durable runs
- with specialist roles
- with operator review
- with evidence-backed outputs
