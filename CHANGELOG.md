# Changelog

## 1.1.0

### Security fixes
- **Audit log:** rewriting the whole hash chain was undetectable because anyone could recompute
  the hashes. Every record is now signed with the manufacturer key and sequence gaps are detected.
- **Persistence:** all state was held in memory and a new signing key was generated at every start, so a
  restart invalidated every token and forgot every scanned nonce. State now lives in SQLite and the
  signing key is loaded from a key file (created with mode 0600).
- **Race condition:** "burn the nonce" and "write the audit record" are now one atomic transaction;
  16 simultaneous scans of one token yield exactly one success.
- **Information leak:** rejection messages exposed the batch's expected region. Clients now get a generic
  code and message; details are logged server-side only.
- **Response replay:** signed responses had no freshness. They now include a timestamp and the client's `challenge`.
- **API:** token schema is strict (types, lengths, no unknown fields); added the missing rate limiting
  that the threat model claimed; `/health` no longer reports log internals.
- **Region check** ignores case and surrounding whitespace.

### Added
- Admin API (`/admin/batches`, `/admin/issue`, `/admin/audit`) protected by `X-Admin-Token`; before this
  the HTTP API had no way to issue a token at all.
- `GET /public-key` so clients can verify signed responses.
- Hardened container: non-root user, read-only filesystem, dropped capabilities, localhost-only port,
  healthcheck, `.dockerignore`, `.env.example`.
- CI workflow, MIT `LICENSE`, 47 tests (was 14), eight-scenario attack simulator.

### Documentation
- Honest positioning: AegisID is *clone-resistant* (duplicates are detected), not "unclonable".
  The README and threat model now state what it cannot do (identify the original label, trust a
  client-supplied region, protect against signing-key theft).
- Fixed README rendering (the first lines were indented and displayed as a code block).

### Breaking changes
- Audit-log format changed (canonical JSON plus signatures); logs from 1.0.0 are not compatible.
- `/scan` request body requires the strict token schema; error bodies changed to
  `{"detail": {"status", "code", "message"}}`.
- `AegisVerifier(...)` accepts an optional `store`; `verifier.log._entries` no longer exists.

## 1.0.0
- Initial release.
