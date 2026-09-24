# CyberRevision

A full-stack study hub: flashcards, quizzes, focus timer, revision planner and community chat. Plain JavaScript frontend, Cloudflare Worker API, and D1 SQLite database. The frontend and API run on the same origin.

## Run locally

Requires Node.js 22 or newer.

```sh
npm ci
npm run dev
```

Open the localhost URL printed by Wrangler. `dev` builds the public assets and applies migrations to a **local** D1 database before starting the server. Re-run `npm run build:assets` after frontend edits; Worker changes reload automatically. Local data stays in `.wrangler/state`. Secure cookies work on localhost in modern browsers; use localhost rather than a plain-HTTP LAN address.

## Commands

```sh
npm run build       # Build frontend and Worker; dry run, no deployment
npm run check       # JavaScript syntax checks
npm test            # Build and run backend integration/security tests
npm run types       # Generate Cloudflare bindings/runtime types
npm run db:migrate  # Apply local D1 migrations
```

Build output is `dist/public` and `dist/worker`. Only index.html, styles.css and app.js are copied to public assets. CI installs dependencies, checks syntax, builds, and tests every push and pull request.

## Deploy to Cloudflare

This has not been deployed. Use a **new** D1 database; the earlier API schema and account ownership are unknown. Existing browser-only guest identities are not migrated to trusted accounts.

1. Run `npx wrangler login`.
2. Run `npx wrangler d1 create cyberrevision`.
3. Copy the returned `database_id` into the DB entry in `wrangler.jsonc`.
4. Run `npm run db:migrate:remote` to initialise that database.
5. Run `npm run deploy` to publish frontend and backend together.

The default Worker name is `cyberrevision`; change it or configure a custom domain before deploying if desired. No API keys or passwords belong in source control. The app does not require an application secret: passwords are salted and derived using PBKDF2-HMAC-SHA256 (600,000 iterations), and random opaque sessions are stored only as SHA-256 hashes in D1. Password derivation consumes CPU; choose an appropriate Workers CPU budget and load-test before a broad rollout.

## Security model

- Registration, sign-in and sign-out UI; passwords are 12–128 characters, usernames are 3–24 letters/numbers/underscores.
- Seven-day `__Host-` session cookies use Secure, HttpOnly, SameSite=Strict and Path=/; logout revokes the server session.
- All writes require an exact same-origin Origin header. No wildcard CORS. Scripts/styles are same-origin, with a restrictive CSP and security headers on assets and API responses.
- Publishing/chat require a server session. Author, ID and timestamp come from the server. No client-provided admin or ownership flags are trusted.
- Set deletion is owner-only and enforced in SQL. Shared chat deletion and client moderation are not exposed. An operator can set `users.muted=1` directly in D1 to disable publishing/chat.
- Parameterised SQL, 128 KiB streaming body limit, field limits, maximum 100 cards per set, bounded reads (50 sets/page, latest 100 chat messages), and database-backed account/IP write rate limits.
- Daily cleanup deletes expired sessions/rate limits and chat older than 30 days. Local plans/sets remain browser-only; clearing browser data removes them.

Public sets and chat are visible to all visitors. The library displays the newest 50 community sets; `/api/sets?offset=50` retrieves the next page. Public account signup is rate-limited, but this is not a substitute for edge DDoS/bot controls. Password recovery, email verification, moderation UI and account deletion are not implemented. Preserve passwords with a password manager. Do not reuse the old unauthenticated backend: deploy this Worker with its matching frontend.

The security tests exercise the real local Workers/D1 runtime: session cookies, password hashing, impersonation attempts, owner-only deletion, server-side mutes, invalid/oversized data, cross-origin writes, logout/expiry and throttling.
