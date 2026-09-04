# RepoSentinel AI Privacy

RepoSentinel AI reads only repositories the user explicitly selects or supplies. Public repositories can be audited without a GitHub connection. Private repository access uses an optional Anna-managed GitHub credential with read-only repository permissions.

GitHub credential values never enter the browser interface, saved reports, model prompts, or tool output. The bundled auditor downloads a bounded repository snapshot for static analysis and never executes repository code, package managers, hooks, builds, or tests.

Saved audit reports are stored through Anna Storage for the current user. Reports contain repository metadata, bounded code-location evidence, and remediation guidance. Users can export or remove their saved App data through the available Anna controls.

Repository content is sent only to the bundled read-only auditor. The Anna model receives a compact report containing metadata and finding explanations, not repository archives or credential values. Coverage limits and exclusions remain visible in every report.

For support or privacy questions, open an issue at https://github.com/imthegoodboy/repo-sentinel-ai/issues.
