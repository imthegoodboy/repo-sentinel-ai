# RepoSentinel AI

RepoSentinel AI is a read-only GitHub repository auditing workspace for Anna. It combines a deterministic, bounded static scanner with an Anna-generated remediation brief. The scanner supplies compact evidence; the model does not receive the repository archive or credential values.

## User flow

1. Connect GitHub in Anna Settings → Authorizations to browse repositories, including private repositories explicitly granted to the credential. Public repositories can also be scanned by URL without connecting.
2. Choose a repository and optional branch or tag.
3. Review the risk overview, exact finding evidence, repository map, and honest coverage report.
4. Ask Anna follow-up questions grounded only in the bounded report or export a complete PDF or machine-readable JSON report.

## Tool and permission architecture

The App bundles the `repo-auditor` Executa (`tool-dev-repo-sentinel-ai` in local development). The App UI is granted only:

- `tools.invoke` for the bundled auditor;
- `llm.complete` for bounded evidence prioritization and grounded report questions;
- `storage.read` / `storage.write` for up to eight recent reports and one UI preference.

The Executa optionally declares the canonical `GITHUB_TOKEN` credential. Anna stores that value encrypted and injects it into the tool's request context. It is not a tool argument, browser field, report property, model prompt, or log value. The credential should be fine-grained with read-only Metadata and Contents access and limited to repositories the user wants audited. Without it, the public-URL audit path remains functional.

Tool methods:

- `github.connection_status` returns connection metadata only;
- `github.repositories` returns a bounded list of repository metadata only;
- `repository.audit` downloads a bounded snapshot and returns evidence.

No repository code, package manager, build script, test command, or hook is executed.

## Safety and scale budgets

- 25 MB compressed archive;
- 80 MB expanded archive;
- 10,000 inventoried files;
- 750 KB per inspected text file;
- 35 MB total inspected text;
- 120 internal candidate findings and 40 returned findings.

Dependencies, build output, binaries, generated bundles, unsupported formats, and oversized files are inventoried as exclusions. A clean result is not a guarantee of security.

## Local verification

```bash
npm run check
anna-app dev --port 5191
```

`npm run check` runs the JavaScript behavior tests, Python scanner/protocol tests, and strict Anna manifest validation.
