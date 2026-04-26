"""Execution-time concerns extracted from secops.services.execution.

V2.5 Phase 1 decomposes the monolithic ExecutionManager into a set of
mixin classes, one per cohesive responsibility. Each module here is a
``...Mixin`` that ExecutionManager inherits; the extraction is purely
mechanical (no behavior change) so that subsequent v2.5 phases (replay
engine, resume, verifier fabric) can target a smaller surface.
"""
