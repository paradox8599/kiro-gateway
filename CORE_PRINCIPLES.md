# Kiro Gateway - Core Principles

> **Note**: This file preserves the project philosophy in case AGENTS.md is regenerated.

**Kiro Gateway is a transparent proxy with minimal, purposeful modifications.**

## Core Principles

1. **Transparency First**
   - The gateway preserves the user's original intent and request structure
   - Modifications are made only when necessary to work around Kiro API limitations or to add opt-in enhancements
   - We fix API quirks, not user decisions

2. **Minimal Intervention**
   - Changes to requests are surgical and well-justified
   - We add capabilities (like extended thinking) but never remove user content
   - Every modification must serve a clear purpose: fixing validation issues, adding optional features, or improving compatibility

3. **User Control**
   - All optional enhancements must be configurable
   - Users can disable features to get native Kiro API behavior
   - The gateway respects user choices about conversation structure and content

4. **Clear Boundaries**
   - ✅ **We fix**: API validation quirks, format incompatibilities, authentication flows
   - ✅ **We add (optionally)**: Enhanced features that Kiro API doesn't provide natively
   - ❌ **We don't modify**: User's conversation content, context decisions, message priorities
   - ❌ **We don't decide**: What messages to keep, what to trim, what's "important"

5. **Responsibility Separation**
   - Gateway handles API-level issues
   - Client handles content-level decisions
   - Model handles capacity limitations

6. **Systems Over Patches**
   - When solving a problem, we build systems that handle entire classes of issues, not one-off fixes
   - Even if a quick if-else would work, we invest time in creating proper abstractions and dedicated modules
   - Solutions should be easily extensible without modifying core logic
   - We prefer spending a few extra minutes on architecture that scales over quick hacks that accumulate technical debt
   - Every fix is an opportunity to create infrastructure that prevents similar problems in the future

7. **Paranoid Testing Philosophy**
   - Every commit must include tests - no exceptions
   - Tests exist to break code, not to confirm it works
   - Happy path alone is worthless - we test edge cases, error scenarios, boundary conditions, and malformed inputs
   - If you can't think of ways to break your code, you haven't thought hard enough
   - Two basic tests are not testing - comprehensive coverage means testing every logical branch and failure mode
   - Tests are both documentation and a safety net - they should clearly show what the code does and prevent regressions

8. **Code Quality Standards**
   - Comprehensive docstrings for all functions (Google style with Args/Returns/Raises)
   - Type hints are mandatory - every function parameter and return value must be typed
   - Logging at key decision points using loguru (INFO for business logic, DEBUG for technical details, ERROR for failures)
   - Never use bare `except:` or `except Exception:` - catch specific exceptions and add context
   - Proactive tech debt cleanup - if you see hardcoded values or duplicated code, extract it immediately (constants, functions, modules)
   - No placeholders - every function must be complete and production-ready when committed

9. **User Experience First**
   - Error messages must be actionable and user-friendly, not technical jargon
   - When something fails, explain what went wrong and how to fix it
   - Configuration should be intuitive with sensible defaults
   - Debug logging exists to help users troubleshoot, not just for developers
   - Documentation is part of the feature - if users can't figure it out, it doesn't work
   - Every error should guide the user toward a solution, not leave them confused

## About "Improperly formed request" Errors

**Important**: Kiro API's "Improperly formed request" error is notoriously vague due to poor documentation from Amazon. This single error message can indicate many different validation issues:

- Message structure problems (wrong role order, missing required fields)
- Tool definition issues (invalid schemas, name length violations)
- Content format problems (malformed JSON, unsupported content types)
- Authentication or permission issues
- Undocumented API constraints

When debugging this error, systematic testing is required to identify the actual cause. The gateway fixes known validation quirks, but new edge cases may emerge as Kiro API evolves.
