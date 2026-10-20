# Contributing

Use Python 3.12+ on Linux or macOS. Run `uv sync --locked`, then the test and lint
commands in the README. Keep fixtures synthetic and deterministic.

Changes to data normalization must include tests for missing values, provider
semantics and historical URL protection. Network tests must use fake transports
by default; CI never receives production credentials.

Preserve these boundaries:

1. No absent/failed metric becomes zero.
2. No source totals are joined across incompatible windows or semantics.
3. No URL protection is removed by a later failure, lower traffic, duplicate-content
   finding or inferred canonical relationship.
4. No raw HTTP exception, authentication header or API key enters output.
5. Every mutating MCP tool declares its local side effects.
6. Site and content operations remain observational.

Use ASCII branch names containing lowercase letters, numbers, hyphens and slashes.
Contributions are licensed under the project's Apache-2.0 license.
