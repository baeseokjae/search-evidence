# Security and private data

Search Evidence runs locally, with a stdio MCP interface and read-only remote API
operations. Treat all state, reports, captures and credential files as private.

- Use a dedicated state directory with mode `0700`. New files written atomically
  are mode `0600`. Google/Bing credential files are referenced, never copied into
  a repository, logged or rewritten by a collection.
- Google uses `webmasters.readonly`. Bing's key is transported only to fixed,
  allowlisted official API methods. It appears in the provider's required query
  parameter; raw request URLs and server error text are never logged.
- HTTP failures expose controlled error codes. Reports and MCP output may contain
  queries, URLs and analytics, but never intentionally contain credentials.
- Live fetching accepts only configured hosts, HTTP(S), ports 80/443 and public
  unicast DNS answers. Multicast, reserved and IPv6 transition/translation
  destinations are rejected. Every redirect is checked again, and HTTPS cannot
  redirect to plaintext HTTP. Connections pin a validated IP
  while TLS verifies the original host. Cookies, credentials and environment proxy
  settings are not attached to live checks.
- Responses, requests and retries have explicit limits. Live sockets are shut
  down at the read deadline, including during headers and chunk framing. DNS
  resolution uses the operating system resolver and can outlast the application
  deadline; expired budgets reject its results before connecting. Google
  inspection attempts reserve local quota before calling the provider. Other
  clients can consume the same provider quota; local counters cannot observe them.
- MCP arguments cannot change profiles, read arbitrary files, register arbitrary
  paths, invoke a shell, or run SQL. Schema validation rejects extra arguments.
- Saved artifact reads require an exact match with the profile's property.
  Knowing an artifact ID does not authorize a different property's read.
  Legacy audits and verification results without a property must be regenerated;
  they are retained on disk but are not exposed through these interfaces.
- A configured build/content root is an explicit trust boundary. Resolved paths
  cannot escape it through `..` or symlinks. A profile is trusted local configuration.
- HTML exports escape remote text and use a restrictive content security policy.
  CSV exports prefix spreadsheet formula-like text with an apostrophe.

Do not run the MCP server as a public network service. No multi-user authorization
or remote transport is provided. Read-only search access still reveals private
analytics to the MCP client you choose. Use separate profiles and state directories
for separate trust boundaries. A client with local filesystem access already has
access to the state; property checks do not provide operating system isolation.

API clients use idle socket timeouts and check budgets between chunks and retries;
they do not provide a hard deadline around operating system DNS or every provider
SDK operation. Large local audits and concurrent MCP requests also consume local
resources. Do not grant this stdio interface to untrusted clients.

CI audits every registry dependency pinned in `uv.lock`, including platform-specific
packages, against the vulnerability database. A clean audit covers published
advisories at the time of the check, not unknown vulnerabilities.

Do not put credentials, raw API responses, private profiles, state databases or
real analytics fixtures into issues or pull requests. Reproduce problems with
synthetic example data and redact sensitive fields.

For a suspected vulnerability, use the hosting repository's private vulnerability
reporting feature if enabled. Avoid posting exploit details or credentials in a
public issue.
