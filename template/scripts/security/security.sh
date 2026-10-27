#!/usr/bin/env bash
# repo-sentinel — runs the SAME security checks in git hooks and in CI.
# Scanners run in Docker and only see a copy of the files being checked.
#
# Usage:
#   security.sh <check> [mode]
#     checks: hygiene | secrets | deps | iac | workflows | sast | check (all)
#   Commit/CI modes:
#     --staged     files added to the commit (default, pre-commit)
#     --base REF   changes between REF and HEAD (pre-push / CI). "auto": upstream
#     --full       all files at HEAD (nightly scan)
#   On demand (independent of commits, state on disk):
#     --worktree   all files on disk (.gitignore excluded; also works outside git)
#     --history    --worktree + secret scan over the whole git history
#     --changes    files changed or added since the last commit
#   security.sh scan      = check --full
#   security.sh doctor    environment check
#   security.sh pull      pre-download the Docker images
#
# Environment variables (used by the central runner security-scan.sh):
#   SEC_TARGET          directory to scan (default: the current repo)
#   SEC_WORK            temporary working directory (default: .git/repo-sentinel)
#   SEC_DEFAULTS_DIR    directory of config/exception files used when the target has none
#   SEC_REPORT_DIR      if set, each check's output and status are written here
#   SEC_CHECKS          checks run by the 'check' command (default: all)
set -euo pipefail

# Startup spawns as few subprocesses as possible: hooks run in parallel and
# every process is expensive on Windows (a single git call + bash builtins).
if [[ -n "${SEC_TARGET:-}" ]]; then
  cd "$SEC_TARGET" 2>/dev/null || { echo "Target directory not found: $SEC_TARGET" >&2; exit 2; }
fi

IS_GIT=false GIT_TOP="" GIT_PREFIX="" GIT_DIR_=""
if info=$(git rev-parse --show-toplevel --show-prefix --git-dir 2>/dev/null); then
  IS_GIT=true
  GIT_TOP=${info%%$'\n'*}
  info=${info#*$'\n'}
  GIT_PREFIX=${info%%$'\n'*}
  GIT_DIR_=${info#*$'\n'}
fi
if [[ -z "${SEC_TARGET:-}" ]]; then
  $IS_GIT || { echo "Not a git repository (set SEC_TARGET to scan another directory)" >&2; exit 2; }
  case $GIT_DIR_ in /* | ?:/*) ;; *) GIT_DIR_="$PWD/$GIT_DIR_" ;; esac
  cd "$GIT_TOP"
  GIT_PREFIX=""
fi
ROOT=$PWD

# cfg_file <name> — writes the first match to CFG_PATH, in order: target dir → repo root → built-in default
cfg_file() {
  local d
  for d in "$ROOT" "$GIT_TOP" "${SEC_DEFAULTS_DIR:-}"; do
    if [[ -n $d && -f "$d/$1" ]]; then CFG_PATH="$d/$1"; return 0; fi
  done
  return 1
}

cfg_file .security/config.env || { echo "Configuration not found: .security/config.env" >&2; exit 2; }
CONFIG=$CFG_PATH
config_src=""
while IFS= read -r line || [[ -n $line ]]; do config_src+="${line%$'\r'}"$'\n'; done <"$CONFIG"
# CRs stripped: works even if checked out with CRLF on Windows
eval "$config_src" || { echo "Could not read configuration file (syntax error): $CONFIG" >&2; exit 2; }

if [[ -n "${SEC_WORK:-}" ]]; then
  WORK="$SEC_WORK"
elif $IS_GIT; then
  WORK="$GIT_DIR_/repo-sentinel"
else
  echo "SEC_WORK is required outside a git repository (run via security-scan.sh)" >&2
  exit 2
fi
case $WORK in /* | ?:/*) ;; *) WORK="$ROOT/$WORK" ;; esac
[[ -d $WORK ]] || mkdir -p "$WORK"
WORK_REL=""
case "$WORK/" in "$ROOT"/*) WORK_REL="${WORK#"$ROOT"/}" ;; esac
EMPTY_TREE="4b825dc642cb6eb9a060e54bf8d69288fbee4904"
IMAGES="SEC_IMG_GITLEAKS SEC_IMG_OSV SEC_IMG_TRIVY SEC_IMG_SEMGREP SEC_IMG_ACTIONLINT SEC_IMG_ZIZMOR SEC_IMG_JQ"

# ---------------------------------------------------------------- output
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  R=$'\e[31m' G=$'\e[32m' Y=$'\e[33m' D=$'\e[2m' N=$'\e[0m'
else
  R='' G='' Y='' D='' N=''
fi
CHECK=main
WARNS=0 SKIPPED=0 NOFILES=0 BLOCK_N=0 WARN_N=0   # for the report status (reset by run_one)
log()  { printf '%s\n' "${D}[$CHECK]${N} $*"; }
ok()   { printf '%s\n' "${G}✔ [$CHECK]${N} $*"; }
warn() { WARNS=$((WARNS + 1)); printf '%s\n' "${Y}⚠ [$CHECK]${N} $*"; }
err()  { printf '%s\n' "${R}✖ [$CHECK]${N} $*"; }

# ---------------------------------------------------------------- records (for the report)
# When SEC_REPORT_DIR is set, each check writes tab-separated lines to <check>.meta:
#   tool <tool> | scope <scope> | setting <name: value> | file <path> | issue <problem> <problem-tr>
#   step <step> <sec> <exit code> | count <blocking> <warnings>
#   finding <block|warn> <critical|high|medium|low|-> <location> <title> <detail> <id> <url>
#           <title-tr> <detail-tr>
# Texts are English; the "-tr" fields are only for the Turkish report (English is used if missing).
meta() {
  [[ -n "${SEC_REPORT_DIR:-}" ]] || return 0
  local IFS=$'\t'
  printf '%s\n' "$*" >>"$SEC_REPORT_DIR/$CHECK.meta"
}

# clean <text> — turns tabs and line breaks into spaces, returns "-" if empty
clean() { local a=${1//$'\t'/ }; a=${a//$'\r'/}; a=${a//$'\n'/ }; printf '%s' "${a:--}"; }

# issue <problem> [problem-tr] — a problem with the scan itself (reliability section of the report)
issue() { meta issue "$(clean "$1")" "$(clean "${2:-$1}")"; }

# finding <block|warn> <severity> <location> <title> [detail] [id] [url] [title-tr] [detail-tr]
# — a single finding for the report's findings table. Empty fields become "-".
finding() {
  [[ -n "${SEC_REPORT_DIR:-}" ]] || return 0
  meta finding "$(clean "$1")" "$(clean "$2")" "$(clean "$3")" "$(clean "$4")" "$(clean "${5:-}")" \
    "$(clean "${6:-}")" "$(clean "${7:-}")" "$(clean "${8:-$4}")" "$(clean "${9:-${5:-}}")"
}

# cvss_sev <score> — severity of a CVSS score (CVSS v3 ranges)
cvss_sev() {
  awk -v s="$1" 'BEGIN { if (s == "") print "-"; else if (s >= 9) print "critical"; else if (s >= 7) print "high";
    else if (s >= 4) print "medium"; else print "low" }'
}
none() { NOFILES=1; meta scope "0 files ($(scope_desc))"; ok "$*"; }
img_name() { local i=${1%%@*}; printf '%s' "${i##*/}"; }

scope_desc() {
  case $MODE in
    staged) echo "staged" ;;
    range) echo "changed in ${BASE:0:8}..HEAD" ;;
    full) echo "at HEAD" ;;
    worktree | history) echo "on disk" ;;
    changes) echo "changed/new since last commit" ;;
  esac
}

# begin <tool> [scope] — records what the check looks at and with which tool
begin() {
  local scope=${2:-"${#FILES[@]} files ($(scope_desc))"} f
  log "tool: $1 · scope: $scope"
  meta tool "$1"
  meta scope "$scope"
  if [[ ${#FILES[@]} -le 20 ]]; then for f in "${FILES[@]}"; do meta file "$f"; done; fi
}

# setting <name> <value> — a setting/threshold/config source used by the check
setting() { log "$1: $2"; meta setting "$1: $2"; }

# cfg_desc <name> — source of the file found by cfg_file
cfg_desc() {
  case $CFG_PATH in
    "${SEC_DEFAULTS_DIR:-/none}"/*) printf 'built-in default (%s)' "$1" ;;
    *) printf "repo's %s" "$1" ;;
  esac
}

# tool_run <step> <command...> — records the step with its duration and exit code, returns the exit code
tool_run() {
  local name=$1 t=$SECONDS rc=0
  shift
  log "▸ $name"
  "$@" || rc=$?
  log "  ↳ $((SECONDS - t)) s, exit code $rc"
  meta step "$name" "$((SECONDS - t))" "$rc"
  case $rc in
    125) issue "$name: Docker could not start the container (image missing/not downloadable or Docker error; check with 'security-scan.sh pull' and 'doctor')" \
               "$name: Docker konteyneri başlatamadı (imaj bulunamadı/indirilemedi veya Docker hatası; 'security-scan.sh pull' ve 'doctor' ile kontrol edin)" ;;
    126 | 127) issue "$name: could not run the command inside the container (exit code $rc; the image is not the expected tool)" \
                     "$name: konteyner içinde komut çalıştırılamadı (çıkış kodu $rc; imaj beklenen araç değil)" ;;
  esac
  return $rc
}

# last_line <file> — last meaningful line of the tool log (carries the failure reason into the report)
last_line() { grep -v '^[[:space:]]*$' "$1" 2>/dev/null | tail -1 | cut -c1-200; }

# counts <blocking> <warnings> — the check's finding counts
counts() { BLOCK_N=$1 WARN_N=$2; meta count "$1" "$2"; }

# tool_error <problem> [problem-tr] — a tool could not run (no Docker, network error…): fails in CI, warns locally.
tool_error() {
  local policy="${SEC_FAIL_ON_TOOL_ERROR:-auto}"
  issue "$1" "${2:-$1}"
  if [[ $policy == true || ($policy == auto && -n "${CI:-}") ]]; then
    err "$1 — tool error, check counted as failed"
    return 1
  fi
  SKIPPED=1
  warn "$1 — tool error, skipped locally (CI will check again)"
  return 0
}

# ---------------------------------------------------------------- docker
if [[ ${OSTYPE:-} == msys* || ${OSTYPE:-} == cygwin* ]]; then
  host_path() { (cd "$1" && pwd -W); }
else
  host_path() { (cd "$1" && pwd); }
fi

docker_ready() {
  if docker info >/dev/null 2>&1; then return 0; fi
  tool_error "Docker is not running" "Docker çalışmıyor" && return 2
  return 1
}

# dock <image> [docker options...] -- <tool arguments...>
# $WORK is always mounted as /work. Path conversion is disabled only for this call (Git Bash).
dock() {
  local image=$1 opts=()
  shift
  while [[ $# -gt 0 && $1 != -- ]]; do opts+=("$1"); shift; done
  shift
  MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*' docker run --rm \
    -v "$(host_path "$WORK"):/work" ${opts[@]+"${opts[@]}"} "$image" "$@"
}

# ---------------------------------------------------------------- file selection
MODE=staged
BASE=""

resolve_base() {
  local ref=$1 b
  if [[ $ref != auto ]]; then
    if [[ $ref =~ ^0+$ ]] || ! git rev-parse -q --verify "$ref^{commit}" >/dev/null 2>&1; then
      echo "$EMPTY_TREE"
    else
      git merge-base "$ref" HEAD 2>/dev/null || echo "$EMPTY_TREE"
    fi
    return 0
  fi
  for b in '@{upstream}' origin/HEAD origin/main origin/master; do
    if git rev-parse -q --verify "$b" >/dev/null 2>&1; then
      git merge-base "$b" HEAD 2>/dev/null && return 0
    fi
  done
  echo "$EMPTY_TREE"
}

need_git() { $IS_GIT || { echo "'$1' mode requires a git repository: $ROOT" >&2; exit 2; }; }
need_top() {
  need_git "$1"
  [[ -z $GIT_PREFIX ]] || { echo "'$1' mode only works at the repo root (subdirectory: $GIT_PREFIX)" >&2; exit 2; }
}
head_or_empty() { git rev-parse -q --verify HEAD 2>/dev/null || echo "$EMPTY_TREE"; }

parse_mode() {
  case "${1:-}" in
    "" | --staged) need_top --staged; MODE=staged;   BASE=$(head_or_empty) ;;
    --full)        need_top --full;   MODE=full;     BASE="" ;;
    --base)        need_top --base;   MODE=range;    BASE=$(resolve_base "${2:-auto}") ;;
    --worktree)                       MODE=worktree; BASE="" ;;
    --history)     need_git --history; MODE=history; BASE="" ;;
    --changes)     need_git --changes; MODE=changes; BASE=$(head_or_empty) ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
}

# Files that really exist on disk (deleted entries and tracked directory entries are dropped)
existing() { local f; while IFS= read -r f; do if [[ -f $f ]]; then printf '%s\n' "$f"; fi; done; }

list_changed() {
  {
    case $MODE in
      staged) git -c core.quotepath=off diff --cached --name-only --diff-filter=ACMR ;;
      range)  git -c core.quotepath=off diff --name-only --diff-filter=ACMR "$BASE" HEAD ;;
      full)   git -c core.quotepath=off ls-tree -r --name-only HEAD 2>/dev/null || true ;;
      worktree | history)
        if $IS_GIT; then
          git -c core.quotepath=off ls-files -co --exclude-standard | existing
        else
          find . -type f -not -path './.git/*' | sed 's#^\./##'
        fi ;;
      changes)
        if [[ $BASE == "$EMPTY_TREE" ]]; then
          git -c core.quotepath=off ls-files -co --exclude-standard
        else
          git -c core.quotepath=off diff --name-only --relative --diff-filter=ACMR HEAD
          git -c core.quotepath=off ls-files -o --exclude-standard
        fi | sort -u | existing ;;
    esac
  } | { grep -Ev "$SEC_EXCLUDE_REGEX" || true; } | {
    if [[ -n $WORK_REL ]]; then grep -v "^$WORK_REL/" || true; else cat; fi
  }
}

# collect <filtre> → FILES dizisi
collect() {
  local f
  FILES=()
  while IFS= read -r f; do
    if "$1" "$f"; then FILES+=("$f"); fi
  done < <(list_changed)
  return 0
}

source_ref() {
  case $MODE in
    staged) echo staged ;;
    worktree | history | changes) echo worktree ;;
    *) echo HEAD ;;
  esac
}

# fresh_dir <dir> — empties the directory. On Windows the directory itself cannot be deleted while another
# process (IDE file watcher, antivirus) holds it; what matters is that it is empty, otherwise files
# left over from the previous scan would be scanned.
# Returns: 0 ready, 2 skipped locally (warning given), 1 failed (CI)
fresh_dir() {
  rm -rf "$1" 2>/dev/null || true
  mkdir -p "$1"
  if compgen -G "$1/*" >/dev/null || compgen -G "$1/.[!.]*" >/dev/null; then
    tool_error "could not clean the working directory: $1 (a process may be holding the files: IDE, antivirus)" \
               "çalışma dizini temizlenemedi: $1 (dosyaları tutan bir süreç olabilir: IDE, antivirüs)" && return 2
    return 1
  fi
}

# export_to <staged|worktree|ref> <target> <files...> — copies the files' content to the target
export_to() {
  local src=$1 dest=$2
  shift 2
  fresh_dir "$dest" || return
  [[ $# -gt 0 ]] || return 0
  if [[ $src == staged ]]; then
    printf '%s\0' "$@" | git checkout-index --prefix="$dest/" -z --stdin
  elif [[ $src == worktree ]]; then
    printf '%s\0' "$@" | tar --null -T - -cf - | (cd "$dest" && tar -xf -)
  else
    local idx="$WORK/$CHECK.index"
    GIT_INDEX_FILE="$idx" git read-tree "$src"
    printf '%s\0' "$@" | GIT_INDEX_FILE="$idx" git checkout-index --prefix="$dest/" -z --stdin
    rm -f "$idx"
  fi
}

any_file() { return 0; }

is_lockfile() {
  case "${1##*/}" in
    package-lock.json | npm-shrinkwrap.json | pnpm-lock.yaml | yarn.lock | bun.lock | \
    poetry.lock | uv.lock | Pipfile.lock | pdm.lock | requirements*.txt | *requirements.txt | \
    go.sum | Cargo.lock | packages.lock.json | gradle.lockfile | composer.lock | Gemfile.lock) return 0 ;;
  esac
  return 1
}

is_sast_file() {
  case "$1" in
    *.js | *.jsx | *.mjs | *.cjs | *.ts | *.tsx | *.vue | *.py | *.java | *.kt | *.go | *.cs | *.rb | *.php) return 0 ;;
  esac
  return 1
}

is_iac_file() {
  case "${1##*/}" in
    Dockerfile | Dockerfile.* | *.dockerfile | Containerfile | *.tf | *.tfvars | \
    docker-compose*.yml | docker-compose*.yaml | compose.yml | compose.yaml) return 0 ;;
  esac
  case "$1" in
    k8s/* | */k8s/* | kubernetes/* | */kubernetes/* | helm/* | */helm/* | charts/* | */charts/* | manifests/* | */manifests/*)
      case "$1" in *.yml | *.yaml | *.json | *.tpl) return 0 ;; esac ;;
  esac
  return 1
}

is_workflow() {
  case "$1" in .github/workflows/*.yml | .github/workflows/*.yaml) return 0 ;; esac
  return 1
}

in_files() { in_list "$1" "${FILES[@]}"; }
in_list() { local x=$1 f; shift; for f in "$@"; do [[ $f == "$x" ]] && return 0; done; return 1; }

# ---------------------------------------------------------------- kontroller

check_hygiene() {
  local fails=0 f d name lock found
  collect any_file
  [[ ${#FILES[@]} -gt 0 ]] || { none "no files to check"; return 0; }
  begin "bash (built-in rules, no Docker)"
  setting "rules" "secret file names (.env, *.pem, *.key, id_rsa…), lockfile consistency (change modes), .npmrc ignore-scripts"

  for f in "${FILES[@]}"; do
    name="${f##*/}"
    case "$name" in
      .env | .env.* | *.pem | *.key | *.p12 | *.pfx | *.jks | *.keystore | id_rsa | id_dsa | id_ecdsa | id_ed25519)
        case "$name" in *.example | *.sample | *.template | *.dist | *.default) continue ;; esac
        if $IS_GIT; then
          err "secret file must not be in git: $f (add it to .gitignore; use .env.example for samples)"
          finding block high "$f" "File that may contain secrets is in the repo" \
            "Remove it from git, add it to .gitignore and rotate the secrets inside; use .env.example for sample values" "" "" \
            "Gizli bilgi içerebilecek dosya repoda" \
            "Git'ten çıkarın, .gitignore'a ekleyin ve içindeki şifreleri değiştirin; örnek değerler için .env.example kullanın"
          fails=$((fails + 1))
        else
          warn "secret file: $f (leaks if added to git)"
          finding warn medium "$f" "File that may contain secrets" "Leaks if added to git; make sure it is in .gitignore" "" "" \
            "Gizli bilgi içerebilecek dosya" "Git'e eklenirse sızar; .gitignore'da olduğundan emin olun"
        fi ;;
    esac
  done

  if [[ $MODE == staged || $MODE == range || $MODE == changes ]]; then
    for f in "${FILES[@]}"; do
      d="${f%/*}"; [[ $d == "$f" ]] && d="" || d="$d/"
      case "${f##*/}" in
        package.json)
          found=""
          for lock in package-lock.json pnpm-lock.yaml yarn.lock bun.lock; do
            if [[ -f "$d$lock" ]]; then found="$d$lock"; break; fi
          done
          if [[ -z $found ]]; then
            warn "no lockfile for ${d}package.json — locked install (npm ci) is not possible"
            finding warn low "${d}package.json" "No lockfile" \
              "Each install may pull different package versions; create and commit a lockfile (npm install)" "" "" \
              "Lockfile yok" "Her kurulumda farklı paket sürümleri gelebilir; lockfile oluşturup commit'leyin (npm install)"
          elif ! in_files "$found"; then
            warn "${f} changed but $found is not in the commit — if dependencies changed, add the lockfile too"
            finding warn low "$f" "Dependency list changed but lockfile was not added" "If dependencies changed, commit $found as well" "" "" \
              "Bağımlılık listesi değişti ama lockfile eklenmedi" "Bağımlılık değiştiyse $found dosyasını da commit'leyin"
          fi ;;
        pyproject.toml)
          for lock in poetry.lock uv.lock pdm.lock; do
            if [[ -f "$d$lock" ]] && ! in_files "$d$lock"; then
              warn "${f} changed but $d$lock is not in the commit — if dependencies changed, add the lockfile too"
              finding warn low "$f" "Dependency list changed but lockfile was not added" "If dependencies changed, commit $d$lock as well" "" "" \
                "Bağımlılık listesi değişti ama lockfile eklenmedi" "Bağımlılık değiştiyse $d$lock dosyasını da commit'leyin"
            fi
          done ;;
        requirements*.txt | *requirements.txt)
          if grep -Eqv '^\s*(#|-|$)|==' "$f" 2>/dev/null; then
            warn "$f has unpinned lines (use ==; for hashes use pip-compile --generate-hashes)"
            finding warn low "$f" "Unpinned dependencies" \
              "Each install may pull a different version; pin with == (for hashes: pip-compile --generate-hashes)" "" "" \
              "Sürümü sabitlenmemiş bağımlılıklar" \
              "Her kurulumda farklı sürüm gelebilir; == ile sabitleyin (hash için pip-compile --generate-hashes)"
          fi ;;
      esac
    done
  fi

  if [[ -f package-lock.json || -f yarn.lock ]] && ! grep -Eq '^\s*ignore-scripts\s*=\s*true' .npmrc 2>/dev/null; then
    warn ".npmrc has no ignore-scripts=true — package install scripts can run"
    finding warn low ".npmrc" "Package install scripts are not disabled" \
      "A malicious package can run code on the machine during install; add ignore-scripts=true to .npmrc" "" "" \
      "Paket kurulum betikleri kapatılmamış" \
      "Zararlı bir paket kurulurken bilgisayarda kod çalıştırabilir; .npmrc'ye ignore-scripts=true ekleyin"
  fi

  counts "$fails" "$WARNS"
  if [[ $fails -gt 0 ]]; then return 1; fi
  ok "basic hygiene checks passed"
}

# gitleaks_run <dir|git> — runs gitleaks, writes findings to /work/secrets/<kind>.json
gitleaks_run() {
  local kind=$1
  shift
  if [[ $kind == dir ]]; then
    dock "$SEC_IMG_GITLEAKS" --network none -w /work/secrets/target -- \
      dir . "$@" --report-format json --report-path /work/secrets/dir.json
  else
    dock "$SEC_IMG_GITLEAKS" --network none -v "$(host_path "$GIT_TOP"):/src:ro" \
      -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0='*' \
      -- git /src "$@" --report-format json --report-path /work/secrets/git.json
  fi
}

# secrets_findings — writes the findings from the gitleaks JSON reports to the report (values are already redacted)
secrets_findings() {
  local f file line rule desc commit loc
  for f in dir git; do
    [[ -s "$WORK/secrets/$f.json" ]] || continue
    while IFS=$'\t' read -r file line rule desc commit; do
      loc="$file:$line"
      if [[ $commit != - ]]; then loc+=" (commit ${commit:0:8})"; fi
      finding block high "$loc" "$desc" "Revoke and replace the key in its service, then remove it from the code" "$rule" "" \
        "$desc" "Anahtarı serviste iptal edip yenileyin, ardından koddan çıkarın"
    done < <(dock "$SEC_IMG_JQ" --network none -- -r \
      '.[] | [.File, .StartLine, .RuleID, .Description, .Commit]
            | map(tostring | gsub("[\t\r\n]"; " ") | if . == "" then "-" else . end) | @tsv' \
      "/work/secrets/$f.json" 2>/dev/null)
  done
}

check_secrets() {
  local dir="$WORK/secrets" f rc=0 grc=0 range=HEAD scan_dir=false scan_git=false
  local args=(--redact --no-banner --exit-code 1 -v --log-level warn)
  case $MODE in
    staged | worktree | changes) scan_dir=true ;;
    history) scan_dir=true; scan_git=true; range="--all" ;;
    range | full) scan_git=true ;;
  esac
  FILES=()
  if $scan_dir; then collect any_file; fi
  if ! $scan_git && [[ ${#FILES[@]} -eq 0 ]]; then none "no files to check"; return 0; fi
  if [[ $MODE == range && $BASE != "$EMPTY_TREE" ]]; then range="$BASE..HEAD"; fi
  local scope=""
  if $scan_dir; then scope="${#FILES[@]} files ($(scope_desc))"; fi
  if $scan_git; then
    case $range in
      --all) scope+="${scope:+ + }git history (all branches)" ;;
      HEAD)  scope+="${scope:+ + }git history (all commits reachable from HEAD)" ;;
      *)     scope+="${scope:+ + }git history (${BASE:0:8}..HEAD)" ;;
    esac
  fi
  begin "$(img_name "$SEC_IMG_GITLEAKS")" "$scope"
  docker_ready || return $(( $? == 2 ? 0 : 1 ))
  fresh_dir "$dir" || return $(( $? == 2 ? 0 : 1 ))

  if cfg_file .gitleaks.toml; then
    cp "$CFG_PATH" "$dir/"; args+=(--config /work/secrets/.gitleaks.toml)
    setting "rules" "$(cfg_desc .gitleaks.toml)"
  else
    setting "rules" "gitleaks built-in rules"
  fi
  if cfg_file .gitleaksignore; then
    cp "$CFG_PATH" "$dir/"; args+=(--gitleaks-ignore-path /work/secrets/.gitleaksignore)
    setting "exceptions" "$(cfg_desc .gitleaksignore)"
  fi

  if [[ ${#FILES[@]} -gt 0 ]]; then
    tool_run "files copied to the working copy" export_to "$(source_ref)" "$dir/target" "${FILES[@]}" \
      || return $(( $? == 2 ? 0 : 1 ))
    tool_run "gitleaks: file scan (offline)" gitleaks_run dir "${args[@]}" || rc=$?
  fi
  if $scan_git; then
    tool_run "gitleaks: git history scan (read-only, offline)" gitleaks_run git --log-opts="$range" "${args[@]}" || grc=$?
  fi

  local found=0 n
  for f in "$dir/dir.json" "$dir/git.json"; do
    if [[ -f $f ]]; then n=$(grep -c '"RuleID"' "$f" || true); found=$((found + n)); fi
  done
  counts "$found" 0
  if [[ $found -gt 0 && -n "${SEC_REPORT_DIR:-}" ]]; then secrets_findings; fi

  if [[ $rc -eq 1 || $grc -eq 1 ]]; then
    err "$found secret(s) found. Remove them from the code; if pushed, revoke/rotate them FIRST."
    err "If false positive: add a 'gitleaks:allow' comment to the line or the fingerprint to .gitleaksignore."
    return 1
  fi
  if [[ $rc -ne 0 || $grc -ne 0 ]]; then tool_error "gitleaks (exit $rc/$grc)"; return; fi
  ok "no secrets found"
}

# osv_run <new|base> — scans the $WORK/deps/<name> directory, produces <name>.tsv
osv_scan() {
  dock "$SEC_IMG_OSV" -- scan source --format json --output "/work/deps/$1.json" \
    ${OSV_CFG[@]+"${OSV_CFG[@]}"} -r "/work/deps/$1" >"$WORK/deps/$1.log" 2>&1
}

osv_run() {
  local name=$1 rc=0 label pkgs
  label=$(if [[ $name == base ]]; then echo "comparison base"; else echo "scanned state"; fi)
  tool_run "osv-scanner: $label (OSV database query, needs network)" osv_scan "$name" || rc=$?
  case $rc in
    0 | 1) ;;
    128) echo '{"results":[]}' >"$WORK/deps/$name.json"
         log "no packages found in lockfiles (osv-scanner exit code 128)" ;;
    *) tail -5 "$WORK/deps/$name.log"
       [[ $rc -ge 125 ]] || issue "osv-scanner ($label) exit code $rc: $(last_line "$WORK/deps/$name.log")" \
                                  "osv-scanner ($label) çıkış kodu $rc: $(last_line "$WORK/deps/$name.log")"
       return 1 ;;
  esac
  pkgs=$(grep -Eo 'found [0-9]+ packages?' "$WORK/deps/$name.log" | awk '{s += $2} END {print s + 0}')
  setting "package count ($label)" "$pkgs"
  # Columns: ecosystem, package, version, id, CVSS, GHSA severity, lockfile (path relative to target).
  # Empty fields become "-" (read merges consecutive tabs). Path prefixes are trimmed so that
  # base and new rows can be compared.
  local pre="/work/deps/$name/"
  if [[ $name == base ]]; then pre+="$GIT_PREFIX"; fi
  tool_run "jq: findings parsed ($label)" osv_parse "$name" "$pre"
}

osv_parse() {
  local name=$1 pre=$2
  dock "$SEC_IMG_JQ" --network none -- -r --arg pre "$pre" '
    def rank: {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1}[ascii_upcase] // 0;
    def dash: if . == null or . == "" then "-" else . end;
    (.results // [])[] | (.source.path // "" | ltrimstr($pre)) as $src |
    (.packages // [])[] as $p | ($p.groups // [])[] | .ids as $ids |
    ((($ids | map(select(startswith("MAL-"))) | first) // $ids[0])) as $id |
    [ ($p.vulnerabilities // [])[] | select(.id as $i | $ids | index($i)) ] as $vs |
    (($vs | map(select(.id == $id)) | first) // $vs[0] // {}) as $v |
    ($p.package.version | split(".")[0]) as $maj |
    ([ $v.affected[]? | select(.package.name == $p.package.name) | .ranges[]?.events[]? | .fixed // empty ]
      | unique) as $fx |
    [ $p.package.ecosystem, $p.package.name, $p.package.version, $id,
      (.max_severity | dash),
      ([ $vs[] | .database_specific.severity // empty | ascii_upcase ] | max_by(rank) | dash),
      ($src | dash),
      ($v.summary // "" | gsub("[\t\r\n]"; " ") | dash),
      ((($fx | map(select(split(".")[0] == $maj))) as $same
        | if ($same | length) > 0 then $same else $fx end) | join(", ") | dash) ] | @tsv' \
    "/work/deps/$name.json" >"$WORK/deps/$name.tsv"
}

# Lower bound of the CVSS v3 equivalent of the GHSA severity, for vulnerabilities without a score
sev_floor() {
  case $1 in
    CRITICAL) echo 9.0 ;; HIGH) echo 7.0 ;; MODERATE | MEDIUM) echo 4.0 ;; LOW) echo 0.1 ;; *) echo "" ;;
  esac
}

check_deps() {
  local dir="$WORK/deps" f eco name ver id sev gsev src summary fixed fix_en fix_tr loc score label label_tr where
  local block=0 warns=0 base_files=()
  collect is_lockfile
  [[ ${#FILES[@]} -gt 0 ]] || { none "no lockfiles to check"; return 0; }
  begin "$(img_name "$SEC_IMG_OSV") + $(img_name "$SEC_IMG_JQ")"
  setting "blocking threshold" "CVSS ≥ $SEC_DEPS_BLOCK_CVSS (without a score: GitHub severity HIGH/CRITICAL); malicious packages (MAL-) always"
  docker_ready || return $(( $? == 2 ? 0 : 1 ))
  fresh_dir "$dir" || return $(( $? == 2 ? 0 : 1 ))

  OSV_CFG=()
  if cfg_file osv-scanner.toml; then
    cp "$CFG_PATH" "$dir/"; OSV_CFG=(--config=/work/deps/osv-scanner.toml)
    setting "exceptions" "$(cfg_desc osv-scanner.toml)"
  else
    setting "exceptions" "none"
  fi

  tool_run "lockfiles copied to the working copy" export_to "$(source_ref)" "$dir/new" "${FILES[@]}" \
    || return $(( $? == 2 ? 0 : 1 ))
  osv_run new || { tool_error "osv-scanner could not run (possible causes: network access, OSV service, Docker image)" \
                              "osv-scanner çalışamadı (olası nedenler: ağ erişimi, OSV servisi, Docker imajı)"; return; }

  # Comparison base: only in change modes (newly introduced findings block)
  : >"$dir/base.tsv"
  if [[ $MODE == staged || $MODE == range || $MODE == changes ]]; then
    for f in "${FILES[@]}"; do
      if git cat-file -e "$BASE:$GIT_PREFIX$f" 2>/dev/null; then base_files+=("$GIT_PREFIX$f"); fi
    done
    if [[ ${#base_files[@]} -gt 0 ]]; then
      setting "comparison" "${#base_files[@]} lockfile(s) at commit ${BASE:0:8}; only findings introduced by this change are reported"
      tool_run "comparison base copied to the working copy" export_to "$BASE" "$dir/base" "${base_files[@]}" \
        || return $(( $? == 2 ? 0 : 1 ))
      osv_run base || { tool_error "osv-scanner (comparison base) could not run" "osv-scanner (karşılaştırma tabanı) çalışamadı"; return; }
    else
      setting "comparison" "none (lockfiles are new); all findings count as new"
    fi
  else
    setting "comparison" "none (all findings of the state $(scope_desc) are reported)"
  fi

  # In change modes only findings INTRODUCED by this change, otherwise all of them
  grep -vxF -f "$dir/base.tsv" "$dir/new.tsv" >"$dir/added.tsv" || true

  while IFS=$'\t' read -r eco name ver id sev gsev src summary fixed; do
    [[ -n $id ]] || continue
    [[ $sev == - ]] && sev=""
    [[ $gsev == - ]] && gsev=""
    [[ $src == - ]] && src=""
    [[ $summary == - ]] && summary=""
    [[ $fixed == - ]] && fixed=""
    score=$sev label="CVSS $sev" label_tr="CVSS $sev" where=""
    if [[ -z $sev ]]; then
      score=$(sev_floor "$gsev")
      label="no CVSS, severity: ${gsev:-unknown}"
      label_tr="CVSS yok, önem: ${gsev:-bilinmiyor}"
    fi
    if [[ ${#FILES[@]} -gt 1 && -n $src ]]; then where=" [$src]"; fi
    if [[ -n $fixed ]]; then
      fix_en="Fixed version: $fixed" fix_tr="Düzeltilmiş sürüm: $fixed"
    else
      fix_en="No fixed version yet" fix_tr="Henüz düzeltilmiş sürüm yok"
    fi
    loc="$name@$ver${src:+ ($src)}"
    if [[ $id == MAL-* ]]; then
      err "MALICIOUS PACKAGE: $eco $name@$ver ($id)$where — remove it and start incident response"
      finding block critical "$loc" "Malicious package${summary:+: $summary}" \
        "Remove the package immediately; rotate credentials on machines where it was installed and start incident response" \
        "$id" "https://osv.dev/$id" "Zararlı paket${summary:+: $summary}" \
        "Paketi hemen kaldırın; kurulduğu makinelerde şifreleri değiştirin ve olay müdahalesi başlatın"
      block=$((block + 1))
    elif [[ -n $score ]] && awk -v s="$score" -v t="$SEC_DEPS_BLOCK_CVSS" 'BEGIN { exit !(s + 0 >= t + 0) }'; then
      err "$eco $name@$ver — $id ($label)$where https://osv.dev/$id"
      finding block "$(cvss_sev "$score")" "$loc" "${summary:-$id} ($label)" "$fix_en" "$id" "https://osv.dev/$id" \
        "${summary:-$id} ($label_tr)" "$fix_tr"
      block=$((block + 1))
    else
      warn "$eco $name@$ver — $id ($label)$where"
      finding warn "$(cvss_sev "$score")" "$loc" "${summary:-$id} ($label)" "$fix_en" "$id" "https://osv.dev/$id" \
        "${summary:-$id} ($label_tr)" "$fix_tr"
      warns=$((warns + 1))
    fi
  done <"$dir/added.tsv"

  counts "$block" "$warns"
  if [[ $block -gt 0 ]]; then
    err "$block blocking finding(s) (CVSS >= $SEC_DEPS_BLOCK_CVSS, equivalent GHSA severity when unscored, or malicious package)."
    err "Upgrade to a fixed version or add a TIME-LIMITED exception to osv-scanner.toml (ignoreUntil + reason)."
    return 1
  fi
  if [[ $warns -gt 0 ]]; then ok "no blocking findings ($warns warnings)"; else ok "no vulnerabilities found"; fi
}

trivy_scan() {
  dock "$SEC_IMG_TRIVY" -v repo-sentinel-trivy-cache:/root/.cache/trivy -w /work/iac/target -- \
    config --quiet --table-mode detailed --severity "$SEC_IAC_SEVERITY" --exit-code 3 \
    ${IAC_IGN[@]+"${IAC_IGN[@]}"} . >"$WORK/iac/out.txt" 2>&1
}

# trivy_findings — fetches the findings again as JSON and writes them to the report (runs only when there are findings)
trivy_json() {
  dock "$SEC_IMG_TRIVY" -v repo-sentinel-trivy-cache:/root/.cache/trivy -w /work/iac/target -- \
    config --quiet --format json --output /work/iac/result.json --severity "$SEC_IAC_SEVERITY" \
    ${IAC_IGN[@]+"${IAC_IGN[@]}"} . >/dev/null 2>&1
}
trivy_findings() {
  local target line sev id title fix url
  trivy_json || return 0
  # Empty fields become "-" (read merges consecutive tabs)
  while IFS=$'\t' read -r target line sev id title fix url; do
    [[ $line == - ]] && line=""
    finding block "${sev,,}" "$target${line:+:$line}" "$title" "$fix" "$id" "$url"
  done < <(dock "$SEC_IMG_JQ" --network none -- -r \
    '.Results[]? | .Target as $t | .Misconfigurations[]? | [$t, (.CauseMetadata.StartLine // "-"), .Severity,
       (.AVDID // .ID), .Title, (.Resolution // "-"), (.PrimaryURL // "-")]
       | map(tostring | gsub("[\t\r\n]"; " ") | if . == "" then "-" else . end) | @tsv' \
    /work/iac/result.json 2>/dev/null)
}

check_iac() {
  local dir="$WORK/iac" rc=0 n
  collect is_iac_file
  [[ ${#FILES[@]} -gt 0 ]] || { none "no IaC/Dockerfile to check"; return 0; }
  begin "$(img_name "$SEC_IMG_TRIVY") config"
  setting "blocking severities" "$SEC_IAC_SEVERITY"
  IAC_IGN=()
  if cfg_file .trivyignore.yaml; then
    setting "exceptions" "$(cfg_desc .trivyignore.yaml)"
  else
    setting "exceptions" "none"
  fi
  docker_ready || return $(( $? == 2 ? 0 : 1 ))

  tool_run "files copied to the working copy" export_to "$(source_ref)" "$dir/target" "${FILES[@]}" \
    || return $(( $? == 2 ? 0 : 1 ))
  if cfg_file .trivyignore.yaml; then cp "$CFG_PATH" "$dir/"; IAC_IGN=(--ignorefile /work/iac/.trivyignore.yaml); fi

  tool_run "trivy: misconfiguration scan" trivy_scan || rc=$?
  cat "$dir/out.txt"
  n=$(grep -Eo 'Failures: [0-9]+' "$dir/out.txt" | awk '{s += $2} END {print s + 0}')
  counts "$n" 0
  if [[ $rc -eq 3 && -n "${SEC_REPORT_DIR:-}" ]]; then trivy_findings; fi

  case $rc in
    0 | 3) ;;
    *) issue "trivy exit code $rc: $(last_line "$dir/out.txt")" "trivy çıkış kodu $rc: $(last_line "$dir/out.txt")" ;;
  esac
  case $rc in
    0) ok "no misconfigurations found (${#FILES[@]} files)" ;;
    3) err "$n $SEC_IAC_SEVERITY misconfiguration(s). Fix them or add a time-limited exception (expired_at) to .trivyignore.yaml."
       return 1 ;;
    *) tool_error "trivy (exit $rc)" ;;
  esac
}

actionlint_run() {
  dock "$SEC_IMG_ACTIONLINT" --network none -w /work/workflows/target -- "${FILES[@]}" >"$WORK/workflows/actionlint.txt" 2>&1
}
zizmor_run() {
  dock "$SEC_IMG_ZIZMOR" --network none -w /work/workflows/target -- \
    --offline --quiet --min-severity "$SEC_WORKFLOW_MIN_SEVERITY" "${FILES[@]}" >"$WORK/workflows/zizmor.txt" 2>&1
}

# workflow_findings <zizmor-exit-code> — writes actionlint lines and (if there are findings) zizmor's JSON
# output to the report
zizmor_json() {
  dock "$SEC_IMG_ZIZMOR" --network none -w /work/workflows/target -- \
    --offline --quiet --format json --min-severity "$SEC_WORKFLOW_MIN_SEVERITY" "${FILES[@]}"
}
workflow_findings() {
  local line re='^([^ ]+:[0-9]+):[0-9]+: (.*) \[([a-z-]+)\]$' loc sev id title note url
  while IFS= read -r line; do
    if [[ $line =~ $re ]]; then
      finding block medium "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "" "actionlint: ${BASH_REMATCH[3]}"
    fi
  done <"$WORK/workflows/actionlint.txt"
  [[ $1 -ge 10 ]] || return 0
  while IFS=$'\t' read -r loc sev id title note url; do
    case $sev in critical | high | medium | low) ;; *) sev=low ;; esac
    [[ $note == - ]] && note=""
    finding block "$sev" "$loc" "$title" "$note" "zizmor: $id" "$url"
  done < <(zizmor_json 2>/dev/null | dock "$SEC_IMG_JQ" --network none -i -- -r \
    '.[] | ((.locations | map(select(.symbolic.kind == "Primary")) | first) // .locations[0]) as $l |
     [ "\($l.symbolic.key.Local.verbatim_path // $l.symbolic.key.Local.given_path // "?"):\($l.concrete.location.start_point.row + 1)",
       (.determinations.severity | ascii_downcase), .ident, .desc, ($l.symbolic.annotation // "-"), (.url // "-") ]
     | map(tostring | gsub("[\t\r\n]"; " ") | if . == "" then "-" else . end) | @tsv' 2>/dev/null)
}

check_workflows() {
  local dir="$WORK/workflows" rc=0 zrc=0 na nz
  collect is_workflow
  [[ ${#FILES[@]} -gt 0 ]] || { none "no workflows to check"; return 0; }
  begin "$(img_name "$SEC_IMG_ACTIONLINT") (syntax) + $(img_name "$SEC_IMG_ZIZMOR") (security)"
  setting "zizmor minimum severity" "$SEC_WORKFLOW_MIN_SEVERITY"
  docker_ready || return $(( $? == 2 ? 0 : 1 ))
  tool_run "files copied to the working copy" export_to "$(source_ref)" "$dir/target" "${FILES[@]}" \
    || return $(( $? == 2 ? 0 : 1 ))

  tool_run "actionlint: syntax and expression check (offline)" actionlint_run || rc=$?
  cat "$dir/actionlint.txt"
  tool_run "zizmor: security audit (offline)" zizmor_run || zrc=$?
  cat "$dir/zizmor.txt"
  na=$(grep -cE '^[^ ]+:[0-9]+:[0-9]+: ' "$dir/actionlint.txt" || true)
  nz=$(grep -cE '^(error|warning)\[' "$dir/zizmor.txt" || true)
  counts "$((na + nz))" 0
  if [[ -n "${SEC_REPORT_DIR:-}" ]]; then workflow_findings "$zrc"; fi

  if [[ $rc -gt 1 ]]; then tool_error "actionlint (exit $rc): $(last_line "$dir/actionlint.txt")" || return 1; rc=0; fi
  if [[ $zrc -ne 0 && $zrc -lt 10 ]]; then tool_error "zizmor (exit $zrc): $(last_line "$dir/zizmor.txt")" || return 1; zrc=0; fi
  if [[ $rc -ne 0 || $zrc -ne 0 ]]; then
    err "workflow problems: actionlint $na, zizmor $nz (permissions, script injection, unpinned actions...)"
    return 1
  fi
  ok "workflows are clean"
}

# "auto": only the rule packs for the languages of the changed files (~3x faster than p/default)
semgrep_packs() {
  if [[ $SEC_SAST_CONFIG != auto ]]; then echo "$SEC_SAST_CONFIG"; return; fi
  local f p packs=" "
  for f in "${FILES[@]}"; do
    case "$f" in
      *.py) p=p/python ;;
      *.js | *.jsx | *.mjs | *.cjs | *.vue | *.ts | *.tsx) p=p/javascript ;;
      *.java) p=p/java ;;
      *.kt) p=p/kotlin ;;
      *.go) p=p/golang ;;
      *.cs) p=p/csharp ;;
      *.rb) p=p/ruby ;;
      *.php) p=p/php ;;
      *) continue ;;
    esac
    case "$packs" in *" $p "*) ;; *) packs="$packs$p " ;; esac
  done
  echo $packs
}

# semgrep_rules <target> — caches the packs once a day and copies them to the target root.
# Keeping them at the root strips the path prefix from rule IDs (nosemgrep works the same locally and in CI)
# and lets the scan run without network (--network none).
semgrep_rules() {
  local cache="$WORK/cache" p n f offline=true src
  mkdir -p "$cache"
  SG_ARGS=()
  SG_NET=()
  for p in $(semgrep_packs); do
    n="semgrep-$(printf '%s' "$p" | tr '/:' '__').yml"
    f="$cache/$n"
    src="from cache ($(date -r "$f" '+%Y-%m-%d %H:%M' 2>/dev/null || echo '?'))"
    if [[ ! -s $f || -n "$(find "$f" -mtime +0 2>/dev/null)" ]]; then
      if curl -fsSL --max-time 30 -o "$f.tmp" "https://semgrep.dev/c/$p"; then
        mv "$f.tmp" "$f"; src="downloaded from semgrep.dev"
      else
        rm -f "$f.tmp"
        if [[ -s $f ]]; then
          src="download failed, cache older than 1 day used"
          issue "semgrep rule pack $p could not be updated (semgrep.dev unreachable); an old cache was used" \
                "semgrep kural paketi $p güncellenemedi (semgrep.dev erişilemedi); eski önbellek kullanıldı"
        fi
      fi
    fi
    if [[ -s $f ]]; then
      cp "$f" "$1/.$n"
      SG_ARGS+=(--config ".$n")
    else
      SG_ARGS+=(--config "$p")
      offline=false
      src="download failed; will run directly from the semgrep registry (network on)"
      issue "semgrep rule pack $p could not be downloaded; the scan was attempted with network access" \
            "semgrep kural paketi $p indirilemedi; tarama ağ erişimiyle denendi"
    fi
    setting "rule pack $p" "$src"
  done
  SG_ARGS+=(--exclude '.semgrep-*.yml')
  if $offline; then SG_NET=(--network none); fi
}

semgrep_run() {
  dock "$SEC_IMG_SEMGREP" ${SG_NET[@]+"${SG_NET[@]}"} -w /work/sast/target -- \
    semgrep scan "${SG_ARGS[@]}" --severity "$SEC_SAST_BLOCK_SEVERITY" --error \
    --json-output=/work/sast/result.json --metrics=off --disable-version-check --quiet .
}

# semgrep_stats — "R <findings>", "E <errors>" and an "S <path>" line for each scanned file
semgrep_stats() {
  dock "$SEC_IMG_JQ" --network none -- -r \
    '"R\t\(.results // [] | length)", "E\t\(.errors // [] | length)", (.paths.scanned // [] | .[] | "S\t\(.)")' \
    /work/sast/result.json
}

# vue_scripts <target> — writes the <script> blocks of each .vue file, keeping line numbers
# (lines outside the blocks are blank), to a <file>.vue.ts / .vue.js shadow file. Semgrep cannot
# parse .vue; this way the script code is scanned with JS/TS rules. VUE_SHADOW: .vue files that have a shadow
vue_scripts() {
  local root=$1 f ext
  VUE_SHADOW=()
  for f in "${FILES[@]}"; do
    [[ $f == *.vue ]] || continue
    grep -qiE '<script([[:space:]>]|$)' "$root/$f" || continue
    ext=js
    if grep -qiE '<script[^>]*lang=["'\'']ts' "$root/$f"; then ext=ts; fi
    awk '
      /<\/script>/ { inside = 0; print ""; next }
      inside        { print; next }
      /<script([[:space:]>]|$)/ { inside = 1 }
      { print "" }' "$root/$f" >"$root/$f.$ext"
    VUE_SHADOW+=("$f")
  done
}

# vue_vhtml <target> — v-html usages (writes raw HTML into the DOM; XSS with user data)
vue_vhtml() {
  local root=$1 f hits=() line n=0
  for f in "${FILES[@]}"; do
    [[ $f == *.vue ]] || continue
    while IFS= read -r line; do hits+=("$f:${line%%:*}"); done < <(grep -n 'v-html' "$root/$f" 2>/dev/null || true)
  done
  [[ ${#hits[@]} -gt 0 ]] || return 0
  for line in "${hits[@]}"; do
    n=$((n + 1))
    if [[ $n -le 20 ]]; then warn "Vue v-html: $line — XSS if the content includes user data; verify it is sanitized (DOMPurify etc.)"; fi
    finding warn medium "$line" "Raw HTML rendered with v-html" \
      "Leads to XSS if the content includes user data; verify it is sanitized with DOMPurify or similar" "v-html" "" \
      "v-html ile ham HTML basılıyor" \
      "İçerik kullanıcı verisi içeriyorsa XSS'e yol açar; DOMPurify vb. ile temizlendiğini doğrulayın"
  done
  if [[ $n -gt 20 ]]; then warn "… and $((n - 20)) more v-html usages"; fi
  VHTML_N=$n
}

# semgrep_errors — writes every error semgrep reports to the console and the report, with where it is,
# what it means and what to do (at most 10 in detail)
semgrep_errors() {
  local path line type level msg what what_tr n=0
  while IFS=$'\t' read -r path line type level msg; do
    n=$((n + 1))
    [[ $line == - ]] && line=""
    [[ $path == *.vue.ts || $path == *.vue.js ]] && path=${path%.*}
    msg=${msg//\`/\'} msg=${msg//.vue.ts/.vue} msg=${msg//.vue.js/.vue}
    case $type in
      PartialParsing)
        what="Semgrep did not recognize the syntax on this line (usually newer TypeScript/JS features); only this part was skipped, the rest of the file was scanned. It does not mean your code has an error; reviewing the skipped lines by hand is enough"
        what_tr="bu satırdaki söz dizimi Semgrep tarafından tanınmadı (çoğunlukla yeni TypeScript/JS özellikleri); yalnızca bu kısım atlandı, dosyanın geri kalanı tarandı. Kodunuzda hata olduğu anlamına gelmez; atlanan satırları elle gözden geçirmek yeterli" ;;
      *Timeout*)
        what="scanning the file exceeded the time limit and the file was not scanned. If the file is very large (e.g. generated/bundled code) it can be added to .semgrepignore; otherwise review it by hand"
        what_tr="dosyanın taranması zaman sınırını aştı ve dosya taranmadı. Dosya çok büyükse (ör. üretilmiş/bundle kod) .semgrepignore'a eklenebilir; değilse elle gözden geçirin" ;;
      *OutOfMemory* | *TooBig*)
        what="the file is too large to scan and was not scanned. If it is generated/bundled code it can be added to .semgrepignore; otherwise review it by hand"
        what_tr="dosya taranamayacak kadar büyük ve taranmadı. Üretilmiş/bundle koddaysa .semgrepignore'a eklenebilir; değilse elle gözden geçirin" ;;
      *Syntax* | *Parse* | *Lexical*)
        what="the file could not be parsed and was not scanned (syntax error or syntax Semgrep does not support). If the file compiles, the problem is in Semgrep; review the file by hand"
        what_tr="dosya ayrıştırılamadı ve taranmadı (söz dizimi hatası veya Semgrep'in desteklemediği bir söz dizimi). Dosya derleniyorsa sorun Semgrep'tedir; dosyayı elle gözden geçirin" ;;
      *Rule* | *Pattern* | *Config*)
        what="a Semgrep rule could not run (a rule pack problem, not a code problem). If it persists, update repo-sentinel's Semgrep image or rule pack"
        what_tr="bir Semgrep kuralı çalıştırılamadı (kural paketiyle ilgili; kodla ilgili değil). Sorun sürerse repo-sentinel'in Semgrep imajını veya kural paketini güncelleyin" ;;
      *)
        what="Semgrep could not fully scan this file ($type). Review the file by hand"
        what_tr="Semgrep bu dosyayı tam tarayamadı ($type). Dosyayı elle gözden geçirin" ;;
    esac
    log "  ↳ $path${line:+:$line} — $type: $msg"
    [[ $n -le 10 ]] || continue
    issue "\`$path${line:+:$line}\` — $what. (Semgrep: $type, $level: $msg)" \
          "\`$path${line:+:$line}\` — $what_tr. (Semgrep: $type, $level: $msg)"
  done < <(dock "$SEC_IMG_JQ" --network none -- -r \
    '.errors[]? | [(.path // .spans[0].file // "-"), (.spans[0].start.line // "-"),
       (if (.type | type) == "array" then .type[0] else .type end // "-"), (.level // "-"),
       (.message // "-" | split("\n") | map(gsub("^\\s+"; "")) | join(" ") | .[:200])]
     | map(tostring | gsub("[\t\r\n]"; " ") | if . == "" then "-" else . end) | @tsv' /work/sast/result.json 2>/dev/null)
  if [[ $n -gt 10 ]]; then
    issue "…and $((n - 10)) more Semgrep errors (full list in the console output)" \
          "…ve $((n - 10)) Semgrep hatası daha (tam liste konsol çıktısında)"
  fi
  if [[ $n -eq 0 ]]; then
    issue "semgrep reported errors but their details could not be read; the affected files may be partially unscanned" \
          "semgrep hata bildirdi ama ayrıntıları okunamadı; ilgili dosyalar kısmen taranmamış olabilir"
  fi
}

# sast_findings — writes the semgrep results to the report; .vue shadow files appear under the real .vue name
sast_findings() {
  local path line rule msg url
  while IFS=$'\t' read -r path line rule msg url; do
    [[ $path == *.vue.ts || $path == *.vue.js ]] && path=${path%.*}
    finding block high "$path:$line" "$msg" \
      "Fix the line; if it is truly safe, add a 'nosemgrep: ${rule##*.}' comment with the reason" "${rule##*.}" "$url" \
      "$msg" "Satırı düzeltin; gerçekten güvenliyse gerekçesiyle 'nosemgrep: ${rule##*.}' yorumu ekleyin"
  done < <(dock "$SEC_IMG_JQ" --network none -- -r \
    '.results[]? | [.path, .start.line, .check_id,
       (.extra.message | if length > 300 then .[:300] + "…" else . end),
       (.extra.metadata.shortlink // .extra.metadata.source // "-")]
     | map(tostring | gsub("[\t\r\n]"; " ") | if . == "" then "-" else . end) | @tsv' /work/sast/result.json 2>/dev/null)
}

check_sast() {
  local dir="$WORK/sast" rc=0 nres=0 nerr=0 nscan=0 f k v tests=() other=() noscript=() scanned
  collect is_sast_file
  [[ ${#FILES[@]} -gt 0 ]] || { none "no source code to check"; return 0; }
  begin "$(img_name "$SEC_IMG_SEMGREP") (Community Edition, intra-file analysis)"
  setting "blocking severity" "$SEC_SAST_BLOCK_SEVERITY (lower-severity rules are not run)"
  docker_ready || return $(( $? == 2 ? 0 : 1 ))

  tool_run "files copied to the working copy" export_to "$(source_ref)" "$dir/target" "${FILES[@]}" \
    || return $(( $? == 2 ? 0 : 1 ))
  semgrep_rules "$dir/target"
  if [[ -d .semgrep ]]; then
    cp -R .semgrep "$dir/target/.semgrep"
    SG_ARGS+=(--config .semgrep --exclude .semgrep)
    setting "custom rules" "repo's .semgrep/ directory"
  fi

  # Exclusions: the repo's .semgrepignore > SEC_SAST_SCAN_TESTS > Semgrep default
  if [[ -f .semgrepignore ]]; then
    cp .semgrepignore "$dir/target/.semgrepignore"
    setting "exclusions" "repo's .semgrepignore file (Semgrep default disabled)"
  elif [[ ${SEC_SAST_SCAN_TESTS:-false} == true ]]; then
    printf '%s\n' node_modules/ vendor/ dist/ build/ '*.min.js' >"$dir/target/.semgrepignore"
    setting "exclusions" "test/ and tests/ directories INCLUDED (SEC_SAST_SCAN_TESTS=true); node_modules, vendor, dist, build, *.min.js excluded"
  else
    setting "exclusions" "Semgrep default: test/, tests/, node_modules/, vendor/, dist/, build/ directories and *.min.js"
  fi

  VUE_SHADOW=() VHTML_N=0
  vue_scripts "$dir/target"
  if [[ ${#VUE_SHADOW[@]} -gt 0 ]]; then
    setting "Vue" "<script> blocks of ${#VUE_SHADOW[@]} .vue files are scanned with JS/TS rules; findings appear as '<file>.vue.ts|js' with the original line numbers (the template part is not scanned by Semgrep; v-html is searched separately)"
  fi

  tool_run "semgrep: code scan ($(if [[ ${#SG_NET[@]} -gt 0 ]]; then echo offline; else echo "network on"; fi))" semgrep_run || rc=$?

  if [[ -s "$dir/result.json" ]] && semgrep_stats >"$dir/stats.tsv"; then
    scanned=$'\n'
    while IFS=$'\t' read -r k v; do
      case $k in R) nres=$v ;; E) nerr=$v ;; S) scanned+="$v"$'\n' ;; esac
    done <"$dir/stats.tsv"
    # Coverage: was every requested file scanned? (for .vue the shadow file counts)
    for f in "${FILES[@]}"; do
      if [[ $scanned == *$'\n'"$f"$'\n'* || $scanned == *$'\n'"$f.ts"$'\n'* || $scanned == *$'\n'"$f.js"$'\n'* ]]; then
        nscan=$((nscan + 1))
      elif [[ $f == *.vue ]] && ! in_list "$f" "${VUE_SHADOW[@]}"; then
        noscript+=("$f")
      elif [[ $f =~ (^|/)tests?/ && ! -f "$dir/target/.semgrepignore" ]]; then
        tests+=("$f")
      else
        other+=("$f")
      fi
    done
    setting "files scanned" "$nscan / ${#FILES[@]}"
    if [[ ${#tests[@]} -gt 0 ]]; then
      setting "out of scope (policy)" "${#tests[@]} files in test/ or tests/ directories (Semgrep default; set SEC_SAST_SCAN_TESTS=true to scan them) — e.g. ${tests[0]}"
    fi
    if [[ ${#noscript[@]} -gt 0 ]]; then
      setting ".vue without script block" "${#noscript[@]} files (template only; v-html search was done)"
    fi
    if [[ ${#other[@]} -gt 0 ]]; then
      warn "${#other[@]} files were not scanned (exclusion rule, size limit or unsupported file) — e.g. ${other[0]}"
      issue "sast: ${#other[@]} files were unexpectedly not scanned — e.g. $(printf '%s ' "${other[@]:0:5}")" \
            "sast: ${#other[@]} dosya beklenmedik şekilde taranmadı — ör. $(printf '%s ' "${other[@]:0:5}")"
    fi
    if [[ $nerr -gt 0 ]]; then
      warn "semgrep reported $nerr file/rule error(s) (e.g. unparsable file); these parts may not have been scanned"
      semgrep_errors
    fi
    if [[ $nres -gt 0 && -n "${SEC_REPORT_DIR:-}" ]]; then sast_findings; fi
  fi
  vue_vhtml "$dir/target"
  counts "$nres" "$((VHTML_N + ${#other[@]}))"

  case $rc in
    0) ok "no findings at $SEC_SAST_BLOCK_SEVERITY level (${nscan}/${#FILES[@]} files scanned)" ;;
    1) err "$nres code security finding(s). Fix them; if false positive, add a '# nosemgrep: <rule-id>' comment with the reason."
       return 1 ;;
    *) tool_error "semgrep (exit $rc)" ;;
  esac
}

# ---------------------------------------------------------------- komutlar

# run_one <check> — runs the check; if SEC_REPORT_DIR is set, appends its status to status.tsv
status_text() {
  case $1 in
    pass) echo "passed" ;; warn) echo "passed (with warnings)" ;; fail) echo "FAILED" ;;
    skipped) echo "skipped (tool error)" ;; n/a) echo "no files" ;; *) echo "$1" ;;
  esac
}

run_one() {
  local c=$1 rc=0 t0=$SECONDS st sec
  CHECK=$c WARNS=0 SKIPPED=0 NOFILES=0 BLOCK_N=0 WARN_N=0
  "check_$c" || rc=$?
  if [[ $rc -ne 0 ]]; then st=fail
  elif [[ $SKIPPED -gt 0 ]]; then st=skipped
  elif [[ $NOFILES -gt 0 ]]; then st=n/a
  elif [[ $WARNS -gt 0 ]]; then st=warn
  else st=pass
  fi
  sec=$((SECONDS - t0))
  if [[ $st != n/a ]]; then
    log "■ result: $(status_text "$st") · blocking: $BLOCK_N · warnings: $WARN_N · $sec s"
  fi
  printf '%s\t%s\t%s\n' "$c" "$st" "$sec" >>"$STATUS_FILE"
  if [[ -n "${SEC_REPORT_DIR:-}" ]]; then
    printf '%s\t%s\t%s\n' "$c" "$st" "$sec" >>"$SEC_REPORT_DIR/status.tsv"
  fi
  return $rc
}

run_checks() {
  local c st sec fails="" warns="" skips="" nas="" passes=0
  STATUS_FILE="$WORK/status.$$.tsv"
  : >"$STATUS_FILE"
  for c in "$@"; do
    if [[ -n "${SEC_REPORT_DIR:-}" ]]; then
      run_one "$c" 2>&1 | tee "$SEC_REPORT_DIR/$c.log" || true
    else
      run_one "$c" || true
    fi
  done
  while IFS=$'\t' read -r c st sec; do
    case $st in
      fail) fails+="${fails:+, }$c" ;; warn) warns+="${warns:+, }$c" ;;
      skipped) skips+="${skips:+, }$c" ;; n/a) nas+="${nas:+, }$c" ;; *) passes=$((passes + 1)) ;;
    esac
  done <"$STATUS_FILE"
  rm -f "$STATUS_FILE"
  CHECK=summary
  if [[ $# -gt 1 ]]; then
    log "$# checks · passed: $passes · failed: ${fails:-none} · with warnings: ${warns:-none} · skipped: ${skips:-none} · no files: ${nas:-none}"
  fi
  if [[ -n $fails ]]; then
    if [[ $# -gt 1 ]]; then err "RESULT: failed ($fails) — findings are in the output of each check"; fi
    return 1
  fi
  if [[ $# -gt 1 ]]; then
    if [[ -n $skips ]]; then
      warn "RESULT: no blocking findings, but $skips could not run (tool error) — these checks were not verified"
    else
      ok "RESULT: all checks passed"
    fi
  fi
  return 0
}

cmd_doctor() {
  CHECK=doctor
  local bad=0 v hooks
  ok "git $(git --version | awk '{print $3}'), bash $BASH_VERSION"
  if docker info >/dev/null 2>&1; then ok "Docker is running"; else err "Docker is not running or not installed"; bad=1; fi
  if command -v lefthook >/dev/null 2>&1; then
    ok "lefthook $(lefthook version 2>/dev/null | head -1)"
  else
    warn "lefthook is not installed — winget install evilmartians.lefthook | brew install lefthook | npm i -D lefthook"
  fi
  if $IS_GIT; then
    hooks="$(git rev-parse --git-path hooks)"
    if grep -qs lefthook "$hooks/pre-commit"; then ok "pre-commit hook installed"; else warn "hook not installed — run 'lefthook install'"; fi
    if grep -qs lefthook "$hooks/pre-push"; then ok "pre-push hook installed"; else warn "pre-push hook not installed"; fi
  fi
  for v in $IMAGES; do
    if docker image inspect "${!v}" >/dev/null 2>&1; then ok "image ready: ${!v%%@*}"; else warn "image not downloaded: ${!v%%@*} — 'security.sh pull'"; fi
  done
  return $bad
}

cmd_pull() {
  CHECK=pull
  local v
  for v in $IMAGES; do
    log "downloading: ${!v%%@*}"
    docker pull -q "${!v}" >/dev/null
  done
  ok "all images ready"
}

main() {
  local cmd="${1:-}"
  shift || true
  case $cmd in
    hygiene | secrets | deps | iac | workflows | sast) parse_mode "$@"; run_checks "$cmd" ;;
    check)
      parse_mode "$@"
      # shellcheck disable=SC2086 # SEC_CHECKS is a space-separated list of checks
      run_checks ${SEC_CHECKS:-hygiene secrets deps iac workflows sast} ;;
    scan)  parse_mode --full; run_checks hygiene secrets deps iac workflows sast ;;
    doctor) cmd_doctor ;;
    pull)   cmd_pull ;;
    *) sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
  esac
}

main "$@"
