# Validation

The repository's tests use synthetic fixtures and fake network transports.
Production credentials, site names, queries, analytics and integration artifacts
are intentionally outside the repository.

| Area | Automated coverage |
|---|---|
| Metrics | Missing, zero, invalid numbers, CTR units, position sentinels |
| Storage | Idempotence, rollback, raw integrity, SQLite online backup/restore |
| URL decisions | Raw variants, historical positive clicks, later failures/zeros, scope validation |
| Google | 25,000-row interruption/resume, compatible comparison, withheld rows, finality metadata |
| Bing | Correct position fields, dates, unsupported metrics, partial failures, repeated history |
| Transport | Retry-After, retry deadlines, permanent errors, quota errors, redacted exceptions, size limit |
| Inspection | Local attempt reservation, Google indexed verdict, unknown Bing indexing |
| Content | Claims, fenced code, duplicate bodies, date errors, preserving both duplicate URLs |
| Live checks | Public DNS/host restrictions, path traversal, content/schema/robots changes, soft 404, aliases |
| Reports | HTML escaping, CSP, raw evidence in JSON |
| Interfaces | MCP schemas/annotations, error envelopes, actual subprocess stdio, CLI/MCP parity |

Run the suite and lint checks from the README. CI covers Linux and macOS with
Python 3.12/3.13. Fake transports test failure paths without consuming API quotas.

## Private integration procedure

1. Create a private profile referencing existing credential files without copying
   them or changing their permissions.
2. Import the previous captures. Reconcile every known clicked raw URL against
   the new protection table, including history beyond the most recent period.
3. Check actual Google/Bing property access and collect a stable, matched Google
   window. Compare raw counters against independent previous captures. Provider
   revisions are possible; record differences rather than overwriting history.
4. Check Bing normalized counters directly against fresh raw response fields.
5. Register a reviewed local HTML build. Verify all intended URLs, including
   explicit aliases and their destination content.
6. Inspect a small quota-bounded sample. Keep live content verification distinct
   from indexed-record observations.
7. Reconcile protected URLs again after fresh collection. Generate private reports.
8. Compare hashes of preexisting collector/configuration files and confirm the
   new application has not changed publication or scheduling configuration.
9. Build a wheel, install it in a clean environment and execute the offline demo.
10. Inspect tracked public files for credentials, private paths, analytics,
    accidental copied source, and required license material before publishing.

## Remaining validation limits

An automated content finding does not establish factual correctness, original
research, advertising-policy compliance or human interest. There is no AdSense
acceptance test. HTML comparison does not prove the production Git revision,
JavaScript-rendered state, robots.txt accessibility, or indexed content identity.
Desktop OAuth requires an interactive user and is not exercised by credential-free
CI. Platform CI results must be checked on the actual hosting repository after push.
