# Accessibility Regression

An open-source GitHub Action and local CLI that compares automated accessibility findings between two previews or two builds of your application. It uses Node.js 24, Playwright Chromium, and axe-core. The project is distributed under the MIT License.

The comparison helps prioritize changes. Axe checks only a subset of accessibility requirements; results can contain false positives and do not replace keyboard, screen-reader, zoom, or expert review. A scan failure or an empty result is not evidence that a page is accessible.

## Choose a mode

Both modes read `.a11y-regression.json`. `pages` is a list of root-relative paths, and `viewport` is optional (default 1280 × 800).

### Compare preview URLs

Use this when your deployment system gives you a base and pull request preview URL:

```json
{
  "mode": "previews",
  "pages": ["/", "/pricing"],
  "viewport": { "width": 1280, "height": 800 }
}
```

Pass `--base-url` and `--pr-url` to the CLI, or `base-url` and `pr-url` to the Action. Both URLs must be HTTP(S) and must not contain credentials.

### Build and compare two refs

Use this when the repository can install, build, and serve either revision with the same commands. Build commands are arrays of executable and arguments (not shell strings). The checked-in config runs a tiny deterministic fixture at `examples/site.mjs` so this repository's sample workflow can run end to end:

```json
{
  "mode": "builds",
  "pages": ["/", "/pricing"],
  "viewport": { "width": 1280, "height": 800 },
  "builds": {
    "install": ["npm", "ci"],
    "build": ["npm", "run", "build"],
    "start": ["node", "examples/site.mjs"],
    "readyPath": "/"
  }
}
```

The fixture serves `/` and `/pricing`. For your own project, replace the `pages` list and command arrays with your app's documented install/build/start steps and a ready path. Do not place shell operators in the arrays expecting shell evaluation.

## Local use

Install Node.js 24 and Git. From a clone of this repository:

```sh
npm ci
npx playwright install chromium
npm run build
```

For preview mode:

```sh
node dist/cli.js scan --config examples/previews.config.json \
  --base-url https://main.example.test \
  --pr-url https://change.example.test
```

For builds mode (both refs must be available locally):

```sh
node dist/cli.js scan --config .a11y-regression.json \
  --base-ref origin/main --head-ref HEAD
```

The command writes `a11y-regression-report/report.json`, `report.html`, `summary.md`, and any evidence screenshots. Use `--output DIR` to choose another directory. `--fail-on-new` opts into a nonzero exit when new findings are present; by default findings are informational. When running against untrusted code, use an isolated environment and do not expose secrets or write-capable tokens to the scan process.

## App safety checks and agent skill

The security check is a separate, local-first addition for JavaScript and TypeScript web apps. It uses Gitleaks for possible exposed credentials, OSV-Scanner for known vulnerabilities in JavaScript lockfiles, and a small bundled Semgrep rule set for risky code patterns. An optional URL check reviews HTTP response headers, cookie flags, and CORS. Results are leads for review, not a security certification. See the [app safety guide](docs/app-safety.md) and portable [agent skill](skills/app-safety/SKILL.md).

Install Gitleaks, OSV-Scanner v2, and Semgrep Community Edition on your `PATH` before relying on a complete local result. The CLI records a missing or failed tool as incomplete; it never treats that as a clean scan. The dependency checker may query an advisory service with dependency identifiers. The bundled Semgrep rules run locally with metrics off, and credentials are never validated against a live service.

```sh
node dist/cli.js check --output app-safety-report
node dist/cli.js check --url http://127.0.0.1:3000 --output app-safety-report
node dist/cli.js scan --config .a11y-regression.json --base-ref origin/main --head-ref HEAD --security-check
```

`check` scans the current working tree and writes `security-report.json` and `security-summary.md`. `scan --security-check` also checks the head preview while it is running and writes those files beside the existing accessibility report. In this mode, accessibility reports omit raw DOM snippets and screenshots from CI artifacts. Security reports contain rule identifiers, severity, safe locations, and general fix guidance; they never contain matched secret values or source excerpts. Only high-confidence provider-token and private-key patterns fail the security gate by default. If Gitleaks cannot complete, the gate fails with an incomplete status. Other findings are informational.

## GitHub Action

The action entrypoint is `action.yml`. In another repository, pin a released tag (or preferably a full commit SHA) and configure your mode:

```yaml
name: Accessibility regression
on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: owner/accessibility-regression-bot@v1
        with:
          config: .a11y-regression.json
          base-ref: ${{ github.event.pull_request.base.sha }}
          head-ref: ${{ github.event.pull_request.head.sha }}
          output: a11y-regression-report
      - if: always()
        uses: actions/upload-artifact@v4
        with:
          name: a11y-regression-report
          path: a11y-regression-report/
          if-no-files-found: warn
```

For preview configuration, replace the two ref inputs with `base-url` and `pr-url`. The Action builds its own CLI dependencies, installs Chromium, and reads the config and writes the output in the checked-out caller workspace. `fail-on-new` defaults to `false`. The checked-in default config tests this repository's fixture; replace it for your app.

Set `security-check: 'true'` to enable the app safety check. Existing Action users remain on accessibility-only behavior unless they opt in. The Action installs pinned Gitleaks, OSV-Scanner, and Semgrep versions for this mode. Its PR comment shows a bounded, redacted list of security findings and never copies scanner output, source excerpts, or secret values. Scanner setup failures appear as incomplete checks; a secret-scanner failure fails the gate.

The repository includes two example workflows. The scan workflow runs on `pull_request` with `contents: read`; it executes the pull request's code, so keep credentials out of that job. The separate `workflow_run` workflow receives write permission only to post a comment. It checks that the completed run belongs to this repository and workflow, that the associated pull request still has the run's head SHA, and downloads the artifact by the exact run ID. It checks out comment tooling from the repository's default branch and parses the report only as data. It does not check out or execute the pull request revision. Missing artifacts and failed validation skip the comment.

The comment workflow can handle fork pull requests when GitHub provides the report artifact. It confirms the API's base repository, head repository, and SHA match the workflow run before commenting. Do not switch the scanner to `pull_request_target` or give PR-executed code a write token. Restrict `workflow_run` to the named scan workflow and retain the API validation when adapting it. Pin third-party Actions to full commit SHAs for hardened supply-chain use.

## Report and interpretation

`report.json` uses schema version 1. It records `status` (`complete` or `incomplete`), counts for new, existing, resolved, and uncertain findings, per-finding rule/page/target/evidence/rationale, scan failures, and revision/tool metadata. `report.html` and `summary.md` are convenient renderings. Screenshots are evidence for review; they do not decide whether a finding is valid. Classification is heuristic: inspect uncertain items and the underlying pages before making a release or conformance decision.

The optional `security-report.json` has its own version 1 schema and check-completion statuses. Its findings describe the current head workspace; they are not classified as newly introduced or pre-existing. A clean, skipped, or incomplete security result does not establish that the app is secure.

The PR comment lists only findings classified as new and includes scan failures and uncertainty caveats. The complete artifact is the source for reviewing existing, resolved, and uncertain findings. It is informational by default; opt into `fail-on-new` only after deciding that behavior fits your CI policy.

## Troubleshooting

- **Preview is unavailable:** confirm the preview is reachable from the GitHub-hosted runner and that it serves the configured page paths.
- **Build mode cannot start the app:** verify the argument arrays work from the project root, the server binds to `0.0.0.0`, and `readyPath` responds over HTTP.
- **A ref cannot be resolved:** fetch full history (`fetch-depth: 0`) and pass valid base/head refs.
- **Chromium dependencies fail:** use a supported Ubuntu runner and allow Playwright's install step to install its browser system dependencies.
- **No PR comment appears:** inspect the scan run and ensure the `a11y-regression-report` artifact contains valid `report.json`. The trusted workflow also skips a comment if the PR head changed after the scan or the run cannot be matched to the PR.
- **The scan is incomplete:** inspect `failures` in `report.json`; inaccessible pages, timeouts, and application errors can leave the comparison partial.

## Development

```sh
npm ci
npm run build
npm run lint
npm test
npm run smoke
```

`npm run smoke` runs both CLI modes against disposable local fixtures and requires installed Playwright Chromium and loopback networking. The tests cover report comparison, comment escaping, and workflow privilege boundaries. Automated scanner results still need manual accessibility review.
