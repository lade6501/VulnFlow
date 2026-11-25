<!--
docs/ci-integration.md
Details integration patterns for GitHub Actions, Jenkins, and GitLab CI pipelines.
-->

# CI integration

## GitHub Actions

The [GitHub Actions template](../ci-templates/github-actions.yml) includes a Python runner job and
a container job. The [VulnFlow composite action](../action.yml) accepts an existing scanner report.
For the full scan, approval, and verified PR flow, use the CLI on the runner as shown below.
VulnFlow starts its own offline Docker container for build and test, using a temporary Git checkout
of the patched commit. The runner needs Docker access and must be able to mount that checkout.

### Run the CLI on the runner

The example below installs the CLI from VulnFlow source and installs a checksum-pinned Trivy
binary from [GitHub Releases](https://github.com/aquasecurity/trivy/releases/tag/v0.76.2).
It targets an x64 Ubuntu runner and an npm project with a committed lockfile and a test script.
Copy the workflow to `.github/workflows/vulnflow.yml` in the repository you want to scan.

- Start in `report` mode. This can analyze findings without a build image.
- Use `dry-run` to apply and verify a local patch without publishing a PR, or `pr` to
  publish after verification succeeds. Both modes need the sandbox image.
- For an approval-only test, enter the plan ID and turn off `resume`. To resume remediation,
  leave `resume` enabled and dispatch against the same target repository ref.
- Leave `vulnflow_ref` blank or use `latest` for the latest commit on the VulnFlow default branch.
  A Git branch, tag, or full SHA also works. For example, use
  `feat/campaign-prs-and-code-refactoring` for that source branch. The scan summary records
  the exact SHA. Use it for approval if you want to resume with the same engine revision.

Use the same Supabase project and repository identity for scan and approval. Put
`SUPABASE_URL` and `SUPABASE_SECRET_KEY` in Actions secrets. If the VulnFlow source repository
is private, set `VULNFLOW_SOURCE_TOKEN` to a token with read access. The example uses the
workflow token for pushing the remediation branch and opening a PR. Allow that operation in
your repository settings when testing `pr` mode.

```yaml
name: VulnFlow CLI

on:
  workflow_dispatch:
    inputs:
      mode:
        description: Mode for a new scan
        type: choice
        default: report
        options: [report, dry-run, pr]
      vulnflow_ref:
        description: VulnFlow Git ref. Blank or latest uses the default branch.
        type: string
        default: ''
      plan_id:
        description: Plan ID to approve. Leave blank for a new scan.
        type: string
        default: ''
      resume:
        description: Resume after approval
        type: boolean
        default: true

permissions:
  contents: write
  pull-requests: write
  issues: write

jobs:
  vulnflow:
    runs-on: ubuntu-latest
    env:
      MODE: ${{ inputs.mode }}
      PLAN_ID: ${{ inputs.plan_id }}
      RESUME: ${{ inputs.resume }}
      VULNFLOW_BUILD_SANDBOX_IMAGE: vulnflow-npm-sandbox:ci
    steps:
      - name: Check out the target repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Check out VulnFlow
        uses: actions/checkout@v4
        with:
          repository: lade6501/vulnflow
          ref: ${{ inputs.vulnflow_ref != 'latest' && inputs.vulnflow_ref || '' }}
          token: ${{ secrets.VULNFLOW_SOURCE_TOKEN || github.token }}
          path: .vulnflow-engine
          persist-credentials: false

      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install the CLI and record its revision
        run: |
          python -m pip install ./.vulnflow-engine
          printf 'VulnFlow revision: `%s`\n' \
            "$(git -C .vulnflow-engine rev-parse HEAD)" >> "$GITHUB_STEP_SUMMARY"

      - name: Install Trivy
        if: env.PLAN_ID == '' || inputs.resume
        run: |
          release=0.76.2
          sha256=bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf
          dir=$(mktemp -d "$RUNNER_TEMP/trivy.XXXXXX")
          archive="trivy_${release}_Linux-64bit.tar.gz"
          curl --fail --silent --show-error --location --retry 3 \
            --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 180 \
            --output "$dir/$archive" \
            "https://github.com/aquasecurity/trivy/releases/download/v$release/$archive"
          printf '%s  %s\n' "$sha256" "$dir/$archive" | sha256sum --check -
          tar -xzf "$dir/$archive" -C "$dir" trivy
          "$dir/trivy" --version
          printf '%s\n' "$dir" >> "$GITHUB_PATH"

      - name: Prepare the npm sandbox image
        if: (env.PLAN_ID == '' && env.MODE != 'report') || (env.PLAN_ID != '' && inputs.resume)
        env:
          NPM_CACHE_SPECS: ${{ vars.VULNFLOW_NPM_CACHE_SPECS }}
        run: |
          context=$(mktemp -d "$RUNNER_TEMP/vulnflow-npm.XXXXXX")
          cp package.json package-lock.json Dockerfile.vulnflow-sandbox "$context/"
          docker build --tag "$VULNFLOW_BUILD_SANDBOX_IMAGE" \
            --file "$context/Dockerfile.vulnflow-sandbox" \
            --build-arg "NPM_CACHE_SPECS=$NPM_CACHE_SPECS" "$context"

      - name: Scan or approve
        shell: bash
        env:
          GITHUB_TOKEN: ${{ github.token }}
          REVIEWER: ${{ github.actor }}
          SUPABASE_URL: ${{ secrets.SUPABASE_URL }}
          SUPABASE_SECRET_KEY: ${{ secrets.SUPABASE_SECRET_KEY }}
          VULNFLOW_REPOSITORY: ${{ github.repository }}
          VULNFLOW_ORG_SLUG: ${{ github.repository_owner }}
        run: |
          if [[ -n "$PLAN_ID" || "$MODE" != "report" ]]; then
            : "${SUPABASE_URL:?Set the SUPABASE_URL Actions secret}"
            : "${SUPABASE_SECRET_KEY:?Set the SUPABASE_SECRET_KEY Actions secret}"
            export VULNFLOW_SUPABASE_REQUIRED=true
          fi

          result=0
          if [[ -n "$PLAN_ID" ]]; then
            flags=()
            if [[ "$RESUME" == "true" ]]; then flags+=(--resume); fi
            vulnflow approve --repo "$GITHUB_WORKSPACE" --plan-id "$PLAN_ID" \
              --reviewer "$REVIEWER" "${flags[@]}" || result=$?
          else
            vulnflow scan --repo "$GITHUB_WORKSPACE" --scanner trivy \
              --mode "$MODE" --no-llm --out-dir "$RUNNER_TEMP/vulnflow-reports" || result=$?
          fi

          case "$result" in
            0) ;;
            10) echo "::notice::Awaiting approval. Find the plan ID in the CLI output." ;;
            20) echo "::warning::Remediation blocked by policy. See the CLI output." ;;
            30) echo "::error::Remediation verification failed."; exit "$result" ;;
            *) exit "$result" ;;
          esac
```

The approval command defaults to the `security` reviewer group. If your deployment requires
multiple groups, supply the appropriate `--reviewer-group` when recording each decision.
VulnFlow resumes only after the required approvals are recorded. Use `--reject` in place of
`--resume` to record a rejection. Neither CLI command needs an HTTP API token or webhook signature.

### Prepare the offline npm image

Save this file at the target repository root as `Dockerfile.vulnflow-sandbox`. The workflow tags
the image `vulnflow-npm-sandbox:ci` and VulnFlow uses that tag through
`VULNFLOW_BUILD_SANDBOX_IMAGE`. Dependency downloads happen while building the image.
VulnFlow installs dependencies from that cache and runs tests with networking disabled.

```dockerfile
FROM node:22-bookworm-slim

ARG NPM_CACHE_SPECS=""
WORKDIR /tmp/npm-cache-fixture
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund --cache /opt/npm-cache \
    && rm -rf node_modules \
    && set -f \
    && for spec in $NPM_CACHE_SPECS; do npm cache add --cache /opt/npm-cache -- "$spec" || exit 1; done
```

If a plan needs a version outside the lockfile, add its exact package version and any additional
dependencies to the `VULNFLOW_NPM_CACHE_SPECS` Actions variable as space-separated
`package@version` entries before resuming. Use a real test script. Missing packages, failed tests,
or residual findings leave verification unsuccessful. VulnFlow pushes only the verified commit when
publication succeeds.

If you already maintain a sandbox image, replace the image build step with a pull for that
image and set `VULNFLOW_BUILD_SANDBOX_IMAGE` to its local tag or digest. The image needs the
project's toolchain and offline dependencies. You do not need a custom image to run an assessment.

## Jenkins and GitLab CI

See the [Jenkinsfile](../ci-templates/Jenkinsfile) and [GitLab CI template](../ci-templates/gitlab-ci.yml)
for their container-based examples.
