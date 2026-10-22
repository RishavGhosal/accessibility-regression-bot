# App Safety Skill

`app-safety` is a portable workflow for AI agents working on JavaScript and TypeScript web applications. It helps agents identify trust boundaries, run local accessibility and security checks, suggest focused fixes, and report what remains unverified. It does not certify an application as safe or accessible.

## Install

Copy the `skills/app-safety` directory into `.codex/skills/app-safety` in the target repository. Codex and compatible agents that support the Agent Skills format can then discover `SKILL.md` from that location. Keep the skill in version control if it should apply to the whole team.

The workflow assumes Node.js and the `accessibility-regression` CLI are available. Until the package is published, build this repository with `npm ci` and `npm run build`, then invoke `node /absolute/path/to/accessibility-regression-bot/dist/cli.js` from the target app directory in place of `accessibility-regression`. The broader security pass also requires [Gitleaks](https://github.com/gitleaks/gitleaks), [OSV-Scanner](https://github.com/google/osv-scanner), and [Semgrep](https://semgrep.dev/). If a prerequisite is missing, the agent should report that check as not run rather than implying coverage.

## Commands

From the application repository root, the focused local check is:

```sh
accessibility-regression check [--url URL] [--output DIR]
```

Use the broader security pass when the app has an accessibility regression config and both preview URLs or build refs available:

```sh
accessibility-regression scan --config .a11y-regression.json --base-ref origin/main --head-ref HEAD --security-check
```

The focused check supports quick feedback. The broader pass can include the configured accessibility regression scan and local security tooling. Review the produced report and scanner output; automated results need source-level triage and do not cover every route or runtime condition.

## Safety behavior

Checks run locally by default. The skill does not upload source code, reports, environment data, or prompts, and it does not validate discovered credentials against live services. Run untrusted scripts without production credentials or write-capable tokens.

A high-confidence secret finding is a stop gate. The agent should halt follow-on execution that might expose or use the value, omit the value from logs and reports, and report only a redacted location and secret type. The owner should revoke or rotate it through the normal process. Reports must also redact authorization headers, cookies, personal data, and sensitive prompt contents.

Security findings should be mapped to relevant OWASP ASVS control areas (including version when known) as a prioritization aid. A mapping does not establish that the app conforms to ASVS. State which tools and checks ran, what they found, what was skipped, and what remains unverified.

Accessibility remains part of the app safety workflow. Keep semantic HTML, keyboard access, focus management, labels, contrast, and status/error announcements in scope. Automated scans cover only a subset of accessibility requirements; they cannot replace keyboard, screen-reader, zoom, and expert review. Public descriptions must not claim “secure” or “fully accessible” based on these checks.

## Prioritized follow-up areas

When broader coverage is needed, work through these areas in order and keep findings tied to the app's actual architecture:

1. **Authorization fixtures:** exercise roles, ownership boundaries, tenant isolation, and denied access in deterministic tests.
2. **Privacy in logs, analytics, and errors:** prevent sensitive data from entering telemetry, client-visible errors, or diagnostic output.
3. **Abuse and browser boundaries:** review rate limits, CSRF protections, debug endpoints, and production configuration.
4. **AI-specific boundaries:** test prompt injection paths, limit tool permissions, and protect API keys and other credentials.
5. **Performance and reliability:** check timeouts, resource limits, failure handling, and accessibility under slow or partial responses.

These are roadmap areas for targeted review, not checks that a clean scanner run has already verified.
