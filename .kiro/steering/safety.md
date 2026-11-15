# Safety Rules

These rules are non-negotiable and apply to every part of the codebase.

## Authorization

- Every scan requires an explicit authorization checkbox. The API rejects scan requests without `authorized: true`.
- The UI must present the checkbox with clear language confirming the user owns the target or has written permission to test it.

## Target validation

- Accept only valid public domain names or hostnames.
- Reject private/reserved IP ranges (RFC 1918: 10.x, 172.16-31.x, 192.168.x), loopback (127.x), link-local (169.254.x), and IPv6 loopback (::1).
- Reject `localhost` and any hostname resolving to a private address.
- Validation must run in the backend, not only in the frontend.

## No active exploitation

- Never invoke `--validate`, sqlmap, dalfox, or any active-exploitation tool.
- The pipeline covers discovery and passive/active scanning (nuclei templates) only.
- No fuzzing payloads, no credential stuffing, no brute-force modules.

## Concurrency and timeouts

- Maximum 1 concurrent scan at any time. The API returns an error if a scan is already running.
- Every scan subprocess has a hard timeout; when it expires the subprocess is killed and the scan is marked failed.

## Audit logging

- Every scan is written to SQLite with: target domain, timestamp, scan profile, and final status.
- Logs are never deleted by the application.
