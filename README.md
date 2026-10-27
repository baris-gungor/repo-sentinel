# 🛡️ repo-sentinel

**Point it at your project, get a report of its weak spots.**

repo-sentinel scans any project on your machine with a single command. It finds forgotten passwords in the code, libraries with known vulnerabilities, risky Docker and CI settings, and dangerous code patterns, and collects them all in a readable report.

It installs nothing into your project and leaves no files behind. When the scan finishes, all that remains is the report.

```powershell
.\security-scan.cmd C:\Repos\my-project
```

---

## What does it catch?

| | What it looks for | Example |
|---|---|---|
| 🔑 **Leaked secrets** | API keys, tokens and private keys that ended up in the code or git history | An AWS key starting with `AKIA...`, a committed GitHub token |
| 📦 **Vulnerable dependencies** | Known security vulnerabilities and malicious packages in the packages you use | An old `lodash` version with a high-risk CVE |
| 🧩 **Insecure code patterns** | Dangerous usage such as SQL injection, command injection, XSS | `shell=True` in Python, `v-html` in Vue |
| 🐳 **Infrastructure misconfigurations** | Risky configuration in Dockerfile, Kubernetes, Terraform and docker-compose | A container running as root |
| ⚙️ **CI/CD risks** | Settings in GitHub Actions workflows that are open to attack | Misuse of `pull_request_target`, an action not pinned to a version |
| 🧹 **Basic hygiene** | Files that should not be in the repo and missing protective settings | A committed `.env` or `id_rsa`, a dependency list without a lockfile |

Each finding falls into one of two classes: **❌ blocking** (needs attention now) or **⚠️ warning** (worth reviewing).

The scanning is done by widely used open-source tools such as Gitleaks, OSV-Scanner, Semgrep, Trivy, actionlint and zizmor. They all run in Docker; you don't need to install anything else.

---

## Quick start

### 1. Requirements

- **Docker Desktop** (must be running)
- **Git** (Git for Windows on Windows)

### 2. First-time setup (once)

Downloads the scanning tools (~1 GB):

```powershell
.\security-scan.cmd pull
.\security-scan.cmd doctor     # is everything ready?
```

### 3. Scan

```powershell
.\security-scan.cmd C:\Repos\my-project
```

That's it. You can follow the scan live in the console; when it finishes, the report path is printed:

```
Report: C:\Repos\repo-sentinel\reports\my-project-20261027-143012.md
```

> 💡 **macOS / Linux / Git Bash:** use `bash security-scan.sh` instead of `.\security-scan.cmd`.

> ⚠️ **Don't type plain `bash` in PowerShell.** On Windows this usually opens WSL and fails with `execvpe(/bin/bash) failed`. `security-scan.cmd` finds Git Bash by itself; no per-machine setup is needed.

---

## When and how to scan

By default the scan looks at **the entire current state** of the project. For other needs, add a mode at the end:

| Command | What it does | When to use it |
|---|---|---|
| `.\security-scan.cmd C:\Repos\my-project` | Scans all files on disk | "What state is my project in right now?" |
| `... history` | Also looks for leaked passwords in **the whole git history** | When taking over a project, before open-sourcing it |
| `... changes` | Looks only at what changed since the last commit | To check your own work before committing |
| `... base --ref origin/main` | Looks at the changes made since `main` | Before opening a PR |

A few useful options:

```powershell
.\security-scan.cmd C:\Repos\api C:\Repos\web            # several projects, summary table at the end
.\security-scan.cmd C:\Repos\my-project --only secrets,deps # only the checks you choose
.\security-scan.cmd C:\Repos\my-project --lang tr           # write the .md report in Turkish
```

Check names: `hygiene`, `secrets`, `deps`, `iac`, `workflows`, `sast`.

---

## The report

Every scan writes two files to the `reports/` folder:

- **`.md`**: for people. Easy to read, easy to share. English by default; `--lang tr` writes it in Turkish.
- **`.json`**: for automation. The same information in machine-readable form, always in English.

The console output is always in English.

The report is layered so anyone from a manager to a developer can read it. A non-technical reader can stop after the first three sections:

1. **Result:** the status in one sentence, e.g. "❌ 5 issue(s) need immediate attention".
2. **🎯 Do these first:** what to do, in priority order. For vulnerable packages it also says which version to upgrade to (e.g. `lodash 4.17.15 → 4.18.0`).
3. **📊 Overview:** a plain description of each area, its result, and the number of blocking issues and warnings.
4. **🔍 Findings:** for each area, "what does this check do", "why does it matter", a findings table sorted by severity (where, what was found, what to do) and the steps to fix. The raw tool output for developers sits in a collapsible "Technical details" section.
5. **🩺 Scan reliability:** if something went wrong with the scan itself (a tool could not run, no internet), it says so here, with the file and line where relevant. This keeps "no findings" and "could not be checked" from being confused.
6. **ℹ️ Scan information** and **📖 Glossary:** branch, commit, duration, tool versions, and short explanations of terms such as CVSS and lockfile.

In the JSON report each finding is a separate record (`findings`: severity, location, title, recommendation, ID, link).

---

## It doesn't touch your project

- The scanning tools see a **temporary copy** of your project, not the project itself. The copy is deleted as soon as the scan ends, even if the scan is interrupted (Ctrl+C).
- Most tools run **offline**. Your code is never sent anywhere. The dependency check only queries the public database (OSV) with package names and versions.
- No files are added to your project and no files are changed.

---

## False alarm?

Sometimes a finding is not a real risk (for example a fake key in test data). You can silence these:

| Check | How |
|---|---|
| Secret | Add a `gitleaks:allow` comment at the end of the line |
| Code pattern | Add a `nosemgrep: <rule-id>` comment to the line |
| Dependency | Add a time-limited exception to `osv-scanner.toml` in the project |
| Infrastructure | Add a time-limited exception to `.trivyignore.yaml` in the project |

Always give an exception a reason and an expiry date, so it doesn't get forgotten and become a permanent blind spot.

You can change the thresholds for all projects (for example which CVSS score counts as blocking) in `template/.security/config.env`.

---

## Extra: automatic protection at commit time (optional)

If you want the scan to run by itself on every `git commit` and `git push` in a project, you can install repo-sentinel into that project:

```bash
bash install.sh C:/Repos/my-project --with-ci
```

This adds the hooks and an optional GitHub Actions workflow to the project. For example, a commit containing a password is stopped before it is even created. This also requires [lefthook](https://github.com/evilmartians/lefthook).

---

## Good to know

- repo-sentinel finds known patterns and known vulnerabilities. **It does not find authorization flaws or business-logic vulnerabilities**; those need code review and tests.
- The dependency check needs internet access. Without a connection the check is skipped and the report says so clearly.
- On large projects a scan can take a few minutes. For example, it took about 3 minutes on a monorepo of ~860 files.
