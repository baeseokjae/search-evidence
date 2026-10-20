# Search Evidence

Keep search traffic evidence close to the content decisions it informs.

Search Evidence is a local CLI and stdio MCP server for Google Search Console,
Bing Webmaster Tools, URL protection, editorial review, and comparison of a
reviewed HTML build with a live website. It uses official read-only search APIs
and stores observations in a private SQLite database.

**Missing data stays unknown. A URL with historical clicks stays protected.**

## What it does

- Collect Google totals, pages, queries and dates, with resumable pagination,
  daily partitions, optional selected-page queries and explicit finality metadata.
- Collect Bing rank/traffic, page and query records without inventing date ranges
  or mapping Bing position fields to Google semantics.
- Import historical JSON collections and page CSVs. Reimporting the same capture
  is idempotent. GA4 JSON reports can be retained as raw, separate evidence.
- Compare compatible Google periods. Withheld or absent queries are never given
  fabricated zero counts.
- Protect every raw URL with any observed positive clicks; manually protected URLs
  are also retained. Case, trailing slashes, query strings and fragments are not collapsed.
- Flag unfinished prose, exact duplicate bodies, date inconsistencies, missing
  internal build targets, numeric claims and firsthand testing claims for review.
- Compare live content, metadata, canonical URLs, robots directives, links,
  navigation, images and structured data with registered build fingerprints.
  Explicit reviewed HTML aliases include a check of the destination page.
- Generate private JSON, spreadsheet-safe CSV and escaped HTML reports.
- Expose the same core operations through ten typed MCP tools.

It does not write to Google/Bing, publish articles, alter an existing collector,
request indexing, delete URLs, or predict AdSense approval.

## Install

Requires Python 3.12+ and Linux or macOS. Development and integration checks run
on Linux; macOS is included in CI. Windows is not supported because collection
leases use POSIX file locks.

```bash
uv sync --locked
uv run search-evidence --help
```

Alternatively, install the package in a dedicated virtual environment:

```bash
python3 -m venv .venv
.venv/bin/pip install .
.venv/bin/search-evidence --help
```

For development, `uv sync --locked` also installs test and lint dependencies.
The package does not need Node.js, Docker, a browser server, or a database service.

## Try it without credentials

All example data is synthetic and uses reserved example domains.

```bash
uv run search-evidence --profile examples/demo.toml import-csv \
  examples/pages.csv --start 2026-01-01 --end 2026-01-28 \
  --observed-at 2026-02-01T00:00:00Z
uv run search-evidence --profile examples/demo.toml protect
uv run search-evidence --profile examples/demo.toml audit
uv run search-evidence --profile examples/demo.toml report
```

The demo profile creates `.state/demo` with private directory permissions. Reports
are written under that directory and ignored by Git.

## Connect your own site

Copy `examples/profile.toml` to a private location **outside this repository**.
Use absolute paths or `~` paths. Relative paths resolve from the profile directory.

```toml
site = "https://example.com/"
state_dir = "~/.local/state/search-evidence"
google_credentials = "~/.config/search-evidence/google.json"
bing_key = "~/.config/search-evidence/bing-key.txt"
content_root = "/path/to/blog/content/posts"
build_root = "/path/to/reviewed-public-build"
allowed_hosts = ["example.com"]
body_selector = ".post-content, main, article"
max_calls = 200
max_seconds = 180
```

Google supports a service account authorized for the property, an authorized-user
OAuth credential file, or Application Default Credentials when `google_credentials`
is omitted. The API scope is `webmasters.readonly`. Enable the Search Console API
in your Google Cloud project and grant the credential access to the exact property.
Bing uses the owner's Webmaster API key stored as plain text in a private file.
Credentials remain local. Keep credential files mode `0600` and the state directory
mode `0700`; the application refuses a state directory readable by other users.

Optional desktop OAuth setup, from a machine with a local browser:

```bash
search-evidence --profile /private/profile.toml auth-login \
  --client-secrets /private/oauth-client.json \
  --token-output /private/google.json
```

The loopback login is explicit and times out after 180 seconds. An existing token
output is never overwritten. A Google OAuth app in testing mode may require
periodic reauthorization; the CLI does not promise indefinite token validity.

```bash
export SEARCH_EVIDENCE_PROFILE=/private/profile.toml
search-evidence status --remote
search-evidence finality --start 2026-01-20 --end 2026-01-29
search-evidence collect --start 2026-01-01 --end 2026-01-28
```

`collect` defaults to daily Google partitions. A whole-period report is useful
for totals and compatibility checks:

```bash
search-evidence collect --start 2026-01-01 --end 2026-01-28 --aggregate
search-evidence traffic --source gsc --table totals
search-evidence traffic --source bing --table pages --limit 50
```

Each `traffic` response identifies **one snapshot and its exact request window**.
It never implicitly adds daily, overlapping, imported or repeated observations.
Use `--snapshot-id` to pin a result. Daily collection is suitable for archival
and resumable backfills; choose `--aggregate` for a whole-window view.

To resume an incomplete collection, repeat its original options and add
`--resume JOB_ID` from its response. Changed request conditions are rejected.
Bing endpoints return their own available window and do not accept these Google
start/end dates.

## Preserve URLs and inspect changes

```bash
search-evidence protect
search-evidence protect --urls https://example.com/posts/article/
search-evidence protect-add --url https://example.com/posts/article/ \
  --reason "Editorial commitment"
search-evidence inspect --urls https://example.com/posts/article/
search-evidence audit
search-evidence prioritize --audit-id AUDIT_ID
```

Audit and priority results default to 50 rows. To continue, pass the returned
`--audit-id`, `--cursor` and optionally `--limit` (maximum 500). Verification
results similarly accept `--verification-id` with a cursor; this reads the saved
result without repeating HTTP requests.

Protection survives failed collections and later zero-click observations.
Unobserved URLs receive `review_required`; there is no `safe_to_delete` state.
Duplicate articles with traffic on both URLs retain protection on both.
Claim findings identify evidence that a reviewer should check; they do not
declare a claim false or establish that its citation is trustworthy.

## Verify a reviewed build

Build the site with your existing process first. Point `build_root` at that
reviewed output, then register its expected fingerprints:

```bash
search-evidence manifest --urls-file /private/reviewed-urls.json \
  --revision SOURCE_COMMIT
search-evidence verify --manifest-id MANIFEST_ID
search-evidence verify --manifest-id MANIFEST_ID --cache-check
search-evidence report --audit-id AUDIT_ID --verification-id VERIFICATION_ID
```

`reviewed-urls.json` is a JSON array of raw absolute URLs. HTML aliases are
recognized only when a zero-delay refresh and canonical agree on an in-property
target present in the reviewed build. An alias does not remove any protected URL.
Multiple alias hops require explicit review.

HTTP 200 alone is insufficient. A changed body, description, schema, canonical,
redirect destination, relevant robots directive, or meaningful link fails the
comparison. Whitespace outside code is normalized. Reports distinguish a live
content match from the **unverified** Git deployment revision and search index
version. `--revision` records an owner-supplied claim; it is not provenance proof.

The report directory contains `report.json`, `traffic.csv`,
`protected-urls.csv`, and `report.html`. CSV keeps snapshots and provider/date
boundaries explicit and leaves unknown values blank. Reports contain private
analytics and should not be committed.

## MCP

Configure your MCP client to launch this command over **stdio**:

```bash
uv --directory /absolute/path/to/search-evidence run --locked \
  search-evidence --profile /private/profile.toml mcp
```

There is no HTTP listener. Standard output is reserved for MCP protocol messages.
Clients receive input/output schemas, structured results and consistent error
envelopes. Tools that persist local state are marked as mutating even though the
remote APIs are read-only.

| Tool | Purpose |
|---|---|
| `search_status` | Availability, last good observations, optional property access check |
| `search_collect` | Bounded, resumable Google/Bing collection |
| `search_traffic` | Paginated snapshot rows |
| `search_compare` | Compatible Google period comparison |
| `search_protect_urls` | Conservative raw-URL decisions and evidence |
| `search_prioritize` | Audit priorities that preserve URLs with traffic |
| `search_inspect_urls` | Bounded indexed-record inspection |
| `search_audit_content` | Review candidates from configured local content |
| `search_verify_live` | Registered reviewed-build comparison |
| `search_render_report` | Private JSON/CSV/HTML report |

MCP callers cannot supply arbitrary filesystem roots, API endpoints, SQL or shell
commands. Importing files, registering manifests, changing profiles and creating
manual protection entries are explicit CLI operations.

## Import and backup

```bash
search-evidence import-json /private/collection-v2.json
search-evidence import-json /private/history-request-response.json
search-evidence import-csv /private/pages.csv --start 2026-01-01 --end 2026-01-28 \
  --observed-at 2026-02-01T00:00:00Z
search-evidence backup
```

Canonical CSV columns: `url,clicks,impressions,position`. Blank cells are unknown.
The JSON importer accepts version-2 collections with a `sources` object and
historical Google `request`/`response` tables. Property and capture timestamp must
be explicit. See [data semantics](docs/data-semantics.md).

Backups use SQLite's online backup API and copy referenced compressed raw files.
Restore to a new private directory, validate it, then select it in a separate
profile. No existing operational state is replaced.

## Development and scope

```bash
uv run pytest
uv run ruff check src tests
uv run ruff format --check src tests
uv build
```

See [architecture](docs/architecture.md), [security](SECURITY.md), and
[validation](docs/validation.md).

Current boundaries:

- GA4 imports retain raw responses and timezone/threshold metadata. A GA4 live
  collector, GA4-derived attribution, and cross-provider metric joins are not implemented.
- Bing period comparison is intentionally unavailable because the recorded
  bucket semantics are insufficient for a comparable Google-style date window.
- Internal Markdown targets are checked against a local build. External link
  crawling and proof of factual claims require separate editorial verification.
- Content URL inference assumes `posts/slug/`, unless frontmatter supplies `url`.
  Custom permalink layouts should provide explicit URLs.
- No scheduler, browser dashboard, publishing integration or automated deletions.
- Verification does not establish robots.txt access, full rendered JavaScript
  behavior, deployed Git provenance, or what content Google/Bing currently indexed.

## License

Apache-2.0. See [LICENSE](LICENSE). Third-party dependencies retain their own
licenses and notices as distributed by their packages.
