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
  DNS answers. Every redirect is checked again. Connections pin a validated IP
  while TLS verifies the original host. Cookies, credentials and environment proxy
  settings are not attached to live checks.
- Responses, requests, retries and elapsed time have explicit limits. Google
  inspection attempts reserve local quota before calling the provider. Other
  clients can consume the same provider quota; local counters cannot observe them.
- MCP arguments cannot change profiles, read arbitrary files, register arbitrary
  paths, invoke a shell, or run SQL. Schema validation rejects extra arguments.
- A configured build/content root is an explicit trust boundary. Resolved paths
  cannot escape it through `..` or symlinks. A profile is trusted local configuration.
- HTML exports escape remote text and use a restrictive content security policy.
  CSV exports prefix spreadsheet formula-like text with an apostrophe.

Do not run the MCP server as a public network service. No multi-user authorization
or remote transport is provided. Read-only search access still reveals private
analytics to the MCP client you choose.

Do not put credentials, raw API responses, private profiles, state databases or
real analytics fixtures into issues or pull requests. Reproduce problems with
synthetic example data and redact sensitive fields.

For a suspected vulnerability, use the hosting repository's private vulnerability
reporting feature if enabled. Avoid posting exploit details or credentials in a
public issue.
