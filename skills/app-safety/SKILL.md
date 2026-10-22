---
name: app-safety
description: Use when building, reviewing, or changing a JavaScript or TypeScript web application with AI assistance and safety, security, privacy, or accessibility concerns.
---

# App Safety

Use this workflow while working on a JavaScript or TypeScript web app. Keep checks local by default, preserve accessibility as a core quality requirement, and treat automated findings as evidence to investigate rather than certification.

## Workflow

1. **Map trust boundaries before editing.** Identify user-controlled input, authentication and authorization checks, browser-to-server and service-to-service calls, secrets, uploaded files, persistence, third-party scripts, AI prompts/tools, and data leaving the app. Note which processes can access credentials or modify external systems.
2. **Make the requested change.** Keep existing accessibility behavior in scope: semantic structure, keyboard interaction, focus, labels, contrast, and status/error announcements. Do not remove accessibility checks to make a build pass.
3. **Run a quick local check after meaningful edits.** From the project root, run `accessibility-regression check` (optionally `--url URL` and `--output DIR`). If the CLI is not installed, use `node /absolute/path/to/accessibility-regression-bot/dist/cli.js check`. For a broader pass, use the app's configured `scan` mode with its required preview URLs or build refs plus `--security-check`.
4. **Triage results.** Review the generated report and relevant source. Treat scanner output as a lead: confirm whether the finding applies, identify the trust boundary and impact, and note coverage gaps. A clean or incomplete scan does not establish safety or accessibility.
5. **Suggest targeted fixes.** Prefer the smallest change that addresses the identified cause. Explain the risk and affected boundary. Avoid broad rewrites or claims that a single scan proves the application safe.
6. **Rerun relevant checks.** After a fix, rerun the focused check and any directly affected project checks. Report commands and outcomes, including failures, skipped checks, and unresolved findings.
7. **State unverified risks.** Call out areas the check cannot validate, such as deployed configuration, live credentials, production authorization policy, third-party behavior, assistive-technology usability, or untested routes.

## Local data and secrets

- Keep analysis local unless the user explicitly requests another destination. Do not upload application source, scan artifacts, or environment data to external services as part of this workflow.
- Never print, copy, or test a discovered credential against a live service. Do not request or expose secrets to make a scan work.
- A high-confidence secret finding is a gate: stop further execution that could expose or use the value, do not include it in output, and report only the file/location and secret type with the value redacted. Recommend revocation/rotation through the owner's normal process, then verify the repository and history without revealing the secret.
- Keep reports redacted. Exclude secret values, authorization headers, cookies, personal data, and sensitive prompt contents. If a tool emits them, do not quote or forward that output; use a sanitized summary.
- Do not use live production accounts or privileged credentials for local checks. Run untrusted project scripts in an isolated environment without write-capable tokens.

## Tools and interpretation

The broader security pass may use Gitleaks for exposed secrets, OSV-Scanner for known dependency vulnerabilities, and Semgrep for source patterns. Install these tools before relying on their checks; if one is absent, say it was not run. Dependency databases and rules have limits, so a clean result is not proof of security.

Map relevant findings to the applicable OWASP ASVS control areas and version when known. State the mapping as a review aid, not evidence of conformance or certification. Prioritize concrete, high-impact issues and reachable attack paths over raw finding counts.

Never describe the app publicly as “secure” or “fully accessible” based on automated checks. Accessibility requires human review, including keyboard and assistive-technology use; security also depends on configuration and runtime behavior.
