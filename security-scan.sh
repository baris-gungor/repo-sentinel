#!/usr/bin/env bash
# On-demand security scan, independent of commits. Installs nothing into the target repo.
#
# Usage:
#   security-scan.sh <repo-path>... [mode] [--ref REF] [--only c1,c2] [--lang en|tr] [--report-dir DIR] [--no-report]
#   security-scan.sh pull | doctor
#
# Modes (state on disk, independent of commits):
#   worktree   (default) all files on disk (uncommitted and new included, .gitignore excluded).
#              Also works in non-git directories.
#   history    worktree + secret scan over the whole git history (all branches)
#   changes    files changed or added since the last commit; for dependencies only
#              vulnerabilities introduced by this change block
# Modes (git content; pass the repo root):
#   staged     files added with git add — same as pre-commit
#   base       between --ref REF (default: upstream/origin) and HEAD — same as pre-push/PR
#   full       all files at HEAD — same as the nightly scan
#
# Checks (--only): hygiene, secrets, deps, iac, workflows, sast
# Report language (--lang): en (default) or tr. Console output and JSON are always English.
#
# Examples:
#   bash security-scan.sh C:/Repos/project worktree
#   bash security-scan.sh ../api ../web changes --only secrets,deps
#   bash security-scan.sh C:/Repos/project base --ref origin/main --lang tr
#
# If the target repo has .security/config.env and exception files (.gitleaks.toml, osv-scanner.toml,
# .trivyignore.yaml, .semgrep/), those are used; otherwise the built-in defaults. Reports: <repo-sentinel>/reports/
set -euo pipefail

KIT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENGINE="$KIT/template/scripts/security/security.sh"
DEFAULTS="$KIT/template"
ALL_CHECKS="hygiene secrets deps iac workflows sast"
REPORT_LANG=en

usage() { sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

engine() { # engine <target> <work> <report-dir|""> <args...>
  local target=$1 work=$2 rdir=$3
  shift 3
  SEC_TARGET="$target" SEC_WORK="$work" SEC_DEFAULTS_DIR="$DEFAULTS" SEC_REPORT_DIR="$rdir" \
    SEC_CHECKS="${CHECKS:-}" bash "$ENGINE" "$@"
}

strip_ansi() { sed -E "s/$(printf '\033')\\[[0-9;]*[A-Za-z]//g"; }
json_str() { local s=${1//\\/\\\\}; s=${s//\"/\\\"}; printf '"%s"' "$s"; }
json_str_or_null() { if [[ -n $1 ]]; then json_str "$1"; else printf 'null'; fi; }

# L <english> <turkish> — text in the language of the .md report (console and JSON are always English)
L() { if [[ $REPORT_LANG == tr ]]; then printf '%s' "$2"; else printf '%s' "$1"; fi; }

mode_desc() {
  case $1 in
    worktree) L "all files on disk (.gitignore excluded)" "diskteki tüm dosyalar (.gitignore hariç)" ;;
    history)  L "all files on disk + secret scan over the whole git history" "diskteki tüm dosyalar + tüm git geçmişinde secret taraması" ;;
    changes)  L "files changed or added since the last commit" "son commit'e göre değişen ve yeni dosyalar" ;;
    staged)   L "staged files" "commit'e eklenmiş (staged) dosyalar" ;;
    base)     L "changes between ${REF} and HEAD" "${REF} ile HEAD arasındaki değişiklikler" ;;
    full)     L "all files at HEAD" "HEAD'deki tüm dosyalar" ;;
  esac
}

status_icon() {
  case $1 in
    pass) L "✅ clean" "✅ temiz" ;; warn) L "⚠️ warnings" "⚠️ uyarı var" ;; fail) L "❌ issues found" "❌ sorun var" ;;
    skipped) L "⏭️ could not be checked" "⏭️ kontrol edilemedi" ;; n/a) L "➖ no relevant files" "➖ ilgili dosya yok" ;;
    missing) L "⛔ did not run" "⛔ çalışmadı" ;; *) echo "$1" ;;
  esac
}

# Texts that explain the report to non-technical readers: title, short name, what it does, why it matters
check_title() {
  case $1 in
    secrets) L "🔑 Leaked secrets" "🔑 Sızmış gizli bilgiler" ;;
    deps) L "📦 Vulnerable dependencies" "📦 Açığı olan bağımlılıklar" ;;
    sast) L "🧩 Insecure code patterns" "🧩 Güvensiz kod kalıpları" ;;
    iac) L "🐳 Infrastructure configuration" "🐳 Altyapı yapılandırması" ;;
    workflows) L "⚙️ CI/CD (GitHub Actions)" "⚙️ CI/CD (GitHub Actions)" ;;
    hygiene) L "🧹 Basic hygiene" "🧹 Temel hijyen" ;;
  esac
}
check_short() {
  case $1 in
    secrets) L "Passwords, API keys and tokens written into the code" "Koda yazılmış şifre, API anahtarı ve token'lar" ;;
    deps) L "Known vulnerabilities in third-party libraries" "Kullanılan dış kütüphanelerdeki bilinen açıklar" ;;
    sast) L "Dangerous programming patterns in the source code" "Kaynak koddaki tehlikeli programlama kalıpları" ;;
    iac) L "Docker, Kubernetes, Terraform settings" "Docker, Kubernetes, Terraform ayarları" ;;
    workflows) L "Automated test/release (GitHub Actions) files" "Otomatik test/yayın (GitHub Actions) dosyaları" ;;
    hygiene) L "Files that should not be in the repo, basic settings" "Repoda durmaması gereken dosyalar, temel ayarlar" ;;
  esac
}
check_what() {
  case $1 in
    secrets) L "Looks for API keys, tokens, passwords and private keys written into the code. In modes that scan git history, it also checks past commits." \
               "Kodun içine yazılmış API anahtarı, token, şifre ve özel anahtarları arar. Git geçmişi taranan modlarda geçmiş commit'lere de bakar." ;;
    deps) L "Compares the third-party libraries (packages) the project uses against a public vulnerability database (OSV)." \
            "Projenin kullandığı dış kütüphaneleri (paketleri) herkese açık güvenlik açığı veritabanıyla (OSV) karşılaştırır." ;;
    sast) L "Scans the source code line by line for known dangerous patterns such as SQL injection, command execution and XSS." \
            "Kaynak kodu SQL injection, komut çalıştırma, XSS gibi bilinen tehlikeli kalıplar için satır satır tarar." ;;
    iac) L "Looks for risky settings in the Dockerfile, docker-compose, Kubernetes and Terraform files that define how and where the application runs." \
           "Uygulamanın nasıl ve nerede çalışacağını tanımlayan Dockerfile, docker-compose, Kubernetes ve Terraform dosyalarındaki riskli ayarları arar." ;;
    workflows) L "Reviews the GitHub Actions files that test and release the code automatically, for both errors and security." \
                 "Kodu otomatik test eden ve yayınlayan GitHub Actions dosyalarını hem hata hem güvenlik açısından inceler." ;;
    hygiene) L "Checks for files that should not be in the repo (such as .env and private key files) and for basic settings needed to install dependencies safely." \
               "Repoda durmaması gereken dosyaları (.env, özel anahtar dosyaları gibi) ve bağımlılıkların güvenli kurulması için gereken temel ayarları kontrol eder." ;;
  esac
}
check_why() {
  case $1 in
    secrets) L "A key written into the code lets anyone who can see the code (the team, contractors, attackers if the repo leaks) access that system with your permissions. Deleting it from the code is not enough: it stays in git history." \
               "Koda yazılmış bir anahtar, kodu görebilen herkesin (ekip, dış firmalar, repo sızarsa saldırganlar) o sisteme sizin yetkinizle erişebilmesi demektir. Koddan silmek yetmez: git geçmişinde kalır." ;;
    deps) L "Most of an application is made of these libraries. Using a version with a publicly known vulnerability lets attackers get in with ready-made methods." \
            "Uygulamanın büyük kısmı bu kütüphanelerden oluşur. Açığı herkesçe bilinen bir sürümü kullanmak, saldırganın hazır yöntemlerle sisteme girebilmesine kapı açar." ;;
    sast) L "These patterns can let data coming from a user perform unintended actions in the database, on the server or in other users' browsers." \
            "Bu kalıplar, kullanıcıdan gelen bir verinin veritabanında, sunucuda veya diğer kullanıcıların tarayıcısında istenmeyen işlemler yapmasına yol açabilir." ;;
    iac) L "Even if the code is secure, a misconfigured container or server (e.g. running as administrator, needlessly exposed) increases the impact of an attack." \
           "Kod güvenli olsa bile yanlış ayarlanmış bir container ya da sunucu (ör. yönetici yetkisiyle çalışan, gereksiz yere dışarı açık) bir saldırının etkisini büyütür." ;;
    workflows) L "CI usually has access to release permissions and secrets. A poorly designed workflow can let a pull request from outside take over these permissions." \
                 "CI genellikle yayın yetkilerine ve gizli anahtarlara erişir. Kötü kurgulanmış bir workflow, dışarıdan açılan bir PR'ın bu yetkileri ele geçirmesine izin verebilir." ;;
    hygiene) L "Once a file containing passwords gets into git, it stays in the history even if deleted later. Missing install settings also let a malicious package run code on a developer's machine." \
               "Şifre içeren bir dosya bir kez git'e girerse, sonradan silinse bile geçmişte kalır. Eksik kurulum ayarları da zararlı bir paketin geliştirici bilgisayarında kod çalıştırmasına izin verir." ;;
  esac
}
check_fix() {
  case $1 in
    secrets) L "1. **Revoke the key immediately and create a new one** in the service it belongs to.
2. Move the value out of the code into an environment variable or a secret manager.
3. If it is not a real key (test data, sample value), add a \`gitleaks:allow\` comment to the line." \
"1. İlgili anahtarı ait olduğu serviste **hemen iptal edin ve yenisini oluşturun**.
2. Değeri koddan çıkarıp ortam değişkenine veya bir secret manager'a taşıyın.
3. Gerçek bir anahtar değilse (test verisi, örnek değer) satıra \`gitleaks:allow\` yorumu ekleyin." ;;
    deps) L "1. Upgrade the packages to the fixed version shown in the table (e.g. \`npm install package@version\`) and run the tests.
2. If you cannot upgrade right away, assess the risk and add a **time-limited, justified** exception to \`osv-scanner.toml\`." \
"1. Paketleri tabloda belirtilen düzeltilmiş sürüme yükseltin (ör. \`npm install paket@sürüm\`) ve testleri çalıştırın.
2. Hemen yükseltilemiyorsa riski değerlendirip \`osv-scanner.toml\` dosyasına **süreli ve gerekçeli** istisna ekleyin." ;;
    sast) L "1. Fix the lines shown in the table; the links explain the problem and its fix in detail.
2. If the code is truly safe (e.g. the data is always constant), add a \`nosemgrep: <rule>\` comment with the reason." \
"1. Tabloda belirtilen satırları düzeltin; bağlantılar sorunun ve çözümünün ayrıntılı açıklamasını içerir.
2. Kod gerçekten güvenliyse (ör. veri her zaman sabitse) satıra gerekçesiyle \`nosemgrep: <kural>\` yorumu ekleyin." ;;
    iac) L "1. Apply the suggested fixes from the table in the relevant file.
2. If it is a deliberate choice, add a **time-limited, justified** exception to \`.trivyignore.yaml\`." \
"1. Tablodaki önerilen çözümleri ilgili dosyada uygulayın.
2. Bilinçli bir tercihse \`.trivyignore.yaml\` dosyasına **süreli ve gerekçeli** istisna ekleyin." ;;
    workflows) L "1. Fix each finding on its line; the links explain the problem and its fix in detail.
2. If it is a deliberate choice, add a \`# zizmor: ignore[<rule>]\` comment to the line." \
"1. Her bulguyu ilgili satırda düzeltin; bağlantılar sorunun ve çözümünün ayrıntılı açıklamasını içerir.
2. Bilinçli bir tercihse satıra \`# zizmor: ignore[<kural>]\` yorumu ekleyin." ;;
    hygiene) L "1. Remove secret files from git, add them to \`.gitignore\` and change the passwords inside.
2. Warnings are suggestions that improve install security; apply them when convenient." \
"1. Gizli dosyaları git'ten çıkarıp \`.gitignore\`'a ekleyin ve içlerindeki şifreleri değiştirin.
2. Uyarılar kurulum güvenliğini artıran önerilerdir; planlı bir zamanda uygulayın." ;;
  esac
}

sev_label() {
  case $1 in
    critical) L "🔴 Critical" "🔴 Kritik" ;; high) L "🟠 High" "🟠 Yüksek" ;; medium) L "🟡 Medium" "🟡 Orta" ;;
    low) L "🔵 Low" "🔵 Düşük" ;; *) L "⚪ Unknown" "⚪ Belirsiz" ;;
  esac
}

# meta_vals <meta-file> <key> — all values of the key (tab-separated columns are kept)
meta_vals() { [[ -f $1 ]] && awk -F'\t' -v k="$2" '$1 == k { sub(/^[^\t]*\t/, ""); print }' "$1"; return 0; }
meta_one() { meta_vals "$1" "$2" | head -1; }
# issue_vals <meta> <1|2> — problems with the scan itself: column 1 English, column 2 Turkish
issue_vals() { meta_vals "$1" issue | cut -f"$2"; }
md_cell() { local s=${1//|/\\|}; s=${s//</\&lt;}; s=${s//>/\&gt;}; printf '%s' "${s:--}"; }
code_cell() { local s=${1//|/\\|}; printf '`%s`' "${s//\`/\'}"; }

# sorted_findings <meta> — findings: blocking first, then by severity
sorted_findings() {
  meta_vals "$1" finding | awk -F'\t' -v OFS='\t' '{
    r = ($2 == "critical") ? 0 : ($2 == "high") ? 1 : ($2 == "medium") ? 2 : ($2 == "low") ? 3 : 4
    print ($1 == "block" ? 0 : 1), r, NR, $0 }' | sort -t$'\t' -k1,1n -k2,2n -k3,3n | cut -f4-
}

# findings_table <meta> — findings table for the reader (at most 100 rows)
findings_table() {
  local n=0 total lvl sev loc title detail ref link title_tr detail_tr what
  total=$(meta_vals "$1" finding | wc -l | tr -d ' ')
  [[ $total -gt 0 ]] || return 0
  L "| | Severity | Where | What was found | What to do |" "| | Önem | Nerede | Ne bulundu | Ne yapmalı |"
  echo
  echo "|:-:|------|--------|------------|------------|"
  while IFS=$'\t' read -r lvl sev loc title detail ref link title_tr detail_tr; do
    n=$((n + 1))
    [[ $n -le 100 ]] || continue
    if [[ $REPORT_LANG == tr ]]; then title=${title_tr:-$title} detail=${detail_tr:-$detail}; fi
    what=$(md_cell "$title")
    if [[ $link != - && $ref != - ]]; then what+=" · [$(md_cell "$ref")]($link)"
    elif [[ $link != - ]]; then what+=" · [$(L details ayrıntı)]($link)"
    elif [[ $ref != - ]]; then what+=" · $(code_cell "$ref")"; fi
    echo "| $(if [[ $lvl == block ]]; then echo ❌; else echo ⚠️; fi) | $(sev_label "$sev") | $(code_cell "$loc") | $what | $(md_cell "$detail") |"
  done < <(sorted_findings "$1")
  if [[ $total -gt 100 ]]; then
    echo
    L "_…and $((total - 100)) more findings; the full list is in the technical details below._" \
      "_…ve $((total - 100)) bulgu daha; tam liste aşağıdaki teknik ayrıntılarda._"
    echo
  fi
}

# deps_upgrades <meta> — for each package with a blocking vulnerability: "package@version (lockfile)<TAB>suggested version";
# the suggested version is the highest fixed version that closes all blocking vulnerabilities of that package (empty if none)
deps_upgrades() {
  meta_vals "$1" finding | awk -F'\t' -v OFS='\t' '$1 == "block" {
      p = "Fixed version: "
      if (index($5, p) == 1) { n = split(substr($5, length(p) + 1), v, ", "); for (i = 1; i <= n; i++) print $3, v[i] }
      else print $3, "" }' | sort -t$'\t' -k1,1 -k2,2V |
    awk -F'\t' '{ if (!($1 in last)) order[++n] = $1; last[$1] = $2 } END { for (i = 1; i <= n; i++) print order[i] "\t" last[order[i]] }'
}

# upgrade_list <meta> [max] — writes the deps_upgrades output as a bullet list
upgrade_list() {
  local loc fix main pkg ver src n=0 total
  total=$(deps_upgrades "$1" | wc -l | tr -d ' ')
  while IFS=$'\t' read -r loc fix; do
    n=$((n + 1))
    [[ -z ${2:-} || $n -le $2 ]] || continue
    main=${loc%% (*} src=""
    [[ $loc == *" ("* ]] && src=" _(${loc#* (}_"
    pkg=${main%@*} ver=${main##*@}
    if [[ -n $fix ]]; then
      echo "   - **$pkg** $ver → **$fix**$src"
    else
      echo "   - **$pkg** $ver → $(L "no fixed version yet; consider an alternative package or an exception" \
        "henüz düzeltilmiş sürüm yok; alternatif paket veya istisna değerlendirin")$src"
    fi
  done < <(deps_upgrades "$1")
  if [[ -n ${2:-} && $total -gt $2 ]]; then
    echo "   - $(L "…and $((total - $2)) more packages (see the 📦 section below)" "…ve $((total - $2)) paket daha (aşağıda 📦 bölümünde)")"
  fi
}

# report_rows <report-dir> — for each requested check, in risk order, "check<TAB>status<TAB>duration";
# checks missing from status.tsv (the engine stopped before reaching them) are returned as "missing"
report_rows() {
  local c st sec
  for c in secrets deps sast iac workflows hygiene; do
    case " $CHECKS " in *" $c "*) ;; *) continue ;; esac
    if IFS=$'\t' read -r _ st sec < <(awk -F'\t' -v k="$c" '$1 == k' "$1/status.tsv" 2>/dev/null) && [[ -n $st ]]; then
      printf '%s\t%s\t%s\n' "$c" "$st" "$sec"
    else
      printf '%s\tmissing\t-\n' "$c"
    fi
  done
}

# action_line <check> <blocking> — an item in the "Do these first" list
action_line() {
  case $1 in
    secrets) L "**$2 secret(s)** (password, API key, token) are exposed in the code. Revoke and replace the keys **today**; just deleting them from the code is not enough." \
               "**$2 gizli bilgi** (şifre, API anahtarı, token) kodda açıkta duruyor. İlgili anahtarları **bugün** iptal edip yenileyin; sadece koddan silmek yetmez." ;;
    deps) L "The libraries in use have **$2 high-risk vulnerabilities**. These packages need to be upgraded:" \
            "Kullanılan kütüphanelerde **$2 yüksek riskli açık** var. Şu paketlerin yükseltilmesi gerekiyor:" ;;
    sast) L "**$2 dangerous pattern(s)** were found in the code. A developer should fix the lines shown." \
            "Kodda **$2 tehlikeli kalıp** bulundu. Belirtilen satırlar geliştirici tarafından düzeltilmeli." ;;
    iac) L "There are **$2 risky infrastructure setting(s)**. Apply the suggested changes in the Dockerfile and configuration files." \
           "**$2 riskli altyapı ayarı** var. Dockerfile ve yapılandırma dosyalarında önerilen değişiklikler uygulanmalı." ;;
    workflows) L "The GitHub Actions files have **$2 problem(s)**. They can let a pull request from outside abuse CI permissions." \
                 "GitHub Actions dosyalarında **$2 sorun** var. Bunlar, dışarıdan gelen bir PR'ın CI yetkilerini kötüye kullanmasına yol açabilir." ;;
    hygiene) L "**$2 file(s)** that should not be in the repo (e.g. \`.env\`). Remove them from git and change the passwords inside." \
               "Repoda bulunmaması gereken **$2 dosya** var (ör. \`.env\`). Git'ten çıkarılmalı, içindeki şifreler değiştirilmeli." ;;
  esac
}

# write_report <name> <path> <is_git> <report-dir> <result> <md> <json>
write_report() {
  local name=$1 abs=$2 is_git=$3 rdir=$4 result=$5 md=$6 json=$7
  local branch="" commit="" dirty="" cfg c st sec first=true top disp m
  local tool scope cnt blk wrn n_issue=0 line f files step_name step_sec step_rc rows fi_ icol
  local tot_blk=0 tot_wrn=0 skipped="" n_act=0 lvl sev loc title detail ref link
  disp=$( (cd "$abs" && pwd -W) 2>/dev/null || echo "$abs")   # C:/... form on Windows
  rows=$(report_rows "$rdir")
  icol=$(if [[ $REPORT_LANG == tr ]]; then echo 2; else echo 1; fi)
  cfg=$(L "built-in default" "yerleşik varsayılan")

  if $is_git; then
    branch=$(git -C "$abs" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "-")
    commit=$(git -C "$abs" rev-parse --short HEAD 2>/dev/null || echo "-")
    dirty=$(git -C "$abs" status --porcelain 2>/dev/null | wc -l | tr -d ' ')
    top=$(git -C "$abs" rev-parse --show-toplevel)
    if [[ -f "$abs/.security/config.env" || -f "$top/.security/config.env" ]]; then cfg=$(L "repo's own config" "repo'nun kendi config'i"); fi
  elif [[ -f "$abs/.security/config.env" ]]; then
    cfg=$(L "repo's own config" "repo'nun kendi config'i")
  fi

  while IFS=$'\t' read -r c st sec; do
    cnt=$(meta_one "$rdir/$c.meta" count)
    [[ -z $cnt ]] || tot_blk=$((tot_blk + ${cnt%%$'\t'*})) tot_wrn=$((tot_wrn + ${cnt#*$'\t'}))
    if [[ $st == skipped || $st == missing ]]; then skipped+="${skipped:+, }$(check_title "$c")"; fi
  done <<<"$rows"

  {
    echo "# 🛡️ $(L "Security Report" "Güvenlik Raporu") — $name"
    echo
    if [[ $result == fail ]]; then
      echo "> ### ❌ $(L "$tot_blk issue(s) need immediate attention" "Hemen ilgilenilmesi gereken $tot_blk sorun bulundu")"
      echo ">"
      printf '> %s' "$(L "The **Do these first** section below lists the most critical steps in order." \
        "Aşağıdaki **Önce bunları yapın** bölümü, en kritik adımları sırasıyla listeler.")"
      if [[ $tot_wrn -gt 0 ]]; then
        printf ' %s' "$(L "There are also $tot_wrn warning(s) worth reviewing." "Ayrıca gözden geçirilmesi önerilen $tot_wrn uyarı var.")"
      fi
      echo
    elif [[ $tot_wrn -gt 0 ]]; then
      echo "> ### ✅ $(L "No urgent issues found" "Acil bir sorun bulunmadı")"
      echo ">"
      echo "> $(L "There are $tot_wrn warning(s) worth reviewing when convenient." "Planlı bir zamanda gözden geçirilmesi önerilen $tot_wrn uyarı var.")"
    else
      echo "> ### ✅ $(L "No issues found" "Sorun bulunmadı")"
      echo ">"
      echo "> $(L "All scanned areas are clean." "Taranan tüm alanlar temiz.")"
    fi
    if [[ -n $skipped ]]; then
      echo ">"
      echo "> ⚠️ $(L "**Note:** $skipped could not be checked. You cannot say \"no issues\" for these areas; the reason is in **Scan reliability**." \
        "**Dikkat:** $skipped kontrol edilemedi. Bu alanlar için \"sorun yok\" denemez; nedeni **Taramanın güvenilirliği** bölümünde.")"
    fi
    echo
    echo "**$(L Project Proje):** \`$disp\` · **$(L Date Tarih):** $START_TS · **$(L Scope Kapsam):** $(mode_desc "$MODE")"
    echo

    if [[ $result == fail ]]; then
      echo "## 🎯 $(L "Do these first" "Önce bunları yapın")"
      echo
      while IFS=$'\t' read -r c st sec; do
        [[ $st == fail ]] || continue
        cnt=$(meta_one "$rdir/$c.meta" count)
        n_act=$((n_act + 1))
        echo "$n_act. $(check_title "$c" | cut -d' ' -f1) $(action_line "$c" "${cnt%%$'\t'*}")"
        if [[ $c == deps ]]; then upgrade_list "$rdir/$c.meta" 10; fi
      done <<<"$rows"
      echo
    fi

    echo "## 📊 $(L "Overview" "Genel bakış")"
    echo
    L "| Area | What was checked | Result | Blocking | Warnings |" "| Alan | Neye bakıldı | Sonuç | Engelleyici | Uyarı |"
    echo
    echo "|------|--------------|-------|:-----------:|:-----:|"
    while IFS=$'\t' read -r c st sec; do
      cnt=$(meta_one "$rdir/$c.meta" count)
      blk=${cnt%%$'\t'*} wrn=${cnt#*$'\t'}
      echo "| $(check_title "$c") | $(check_short "$c") | $(status_icon "$st") | ${blk:--} | ${wrn:--} |"
    done <<<"$rows"
    echo
    L "**Blocking:** an issue that should be fixed now. **Warning:** lower risk or context-dependent; worth reviewing." \
      "**Engelleyici:** hemen düzeltilmesi gereken sorun. **Uyarı:** risk düşük ya da bağlama bağlı; gözden geçirilmesi önerilir."
    echo
    echo

    echo "## 🔍 $(L "Findings" "Bulgular")"
    while IFS=$'\t' read -r c st sec; do
      m="$rdir/$c.meta"
      echo
      echo "### $(check_title "$c") — $(status_icon "$st")"
      echo
      echo "**$(L "What does this check do?" "Bu kontrol ne yapar?")** $(check_what "$c")"
      echo
      echo "**$(L "Why does it matter?" "Neden önemli?")** $(check_why "$c")"
      echo
      case $st in
        missing) echo "⛔ $(L "This check did not run: the scan stopped before reaching it." "Bu kontrol çalışmadı: tarama bu kontrole gelmeden durdu.")" ;;
        skipped) echo "⏭️ $(L "This check could not be done (the tool could not run). You cannot say \"no issues\" for this area; the reason is in **Scan reliability**." \
          "Bu kontrol yapılamadı (araç çalışamadı). Bu alan için \"sorun yok\" denemez; nedeni **Taramanın güvenilirliği** bölümünde.")" ;;
        n/a) echo "➖ $(L "There were no relevant files to check in this scan." "Bu taramada kontrol edilecek ilgili dosya yoktu.")" ;;
        pass) echo "✅ $(L "No issues found." "Sorun bulunmadı.")" ;;
        *)
          if [[ -n $(meta_vals "$m" finding) ]]; then
            echo "**$(L "What was found" "Bulunanlar")**"
            echo
            findings_table "$m"
            echo
          else
            L "No security findings. The warning concerns the scan itself; see **Scan reliability**." \
              "Güvenlik bulgusu yok. Uyarı taramanın kendisiyle ilgili; **Taramanın güvenilirliği** bölümüne bakın."
            echo
          fi
          if [[ $c == deps && $st == fail ]]; then
            echo "**$(L "Packages to upgrade" "Yükseltilmesi gereken paketler")** $(L "(the version that closes all blocking vulnerabilities)" "(engelleyici açıkların hepsini kapatan sürüm)")"
            echo
            upgrade_list "$m" | sed 's/^   //'
            echo
          fi
          if [[ $st == fail ]]; then
            echo "**$(L "What to do?" "Ne yapmalı?")**"
            echo
            check_fix "$c"
            echo
          fi ;;
      esac
      [[ $st != missing ]] || continue
      echo
      echo "<details><summary>$(L "Technical details (for developers)" "Teknik ayrıntılar (geliştiriciler için)")</summary>"
      echo
      tool=$(meta_one "$m" tool) scope=$(meta_one "$m" scope)
      [[ -z $tool ]] || echo "- $(L Tool Araç): $tool"
      [[ -z $scope ]] || echo "- $(L Scope Kapsam): $scope"
      while IFS= read -r line; do [[ -z $line ]] || echo "- $(md_cell "$line")"; done < <(meta_vals "$m" setting)
      files=$(meta_vals "$m" file)
      if [[ -n $files ]]; then
        printf -- '- %s: ' "$(L Files Dosyalar)"
        first=true
        while IFS= read -r f; do $first || printf ', '; first=false; printf '`%s`' "$f"; done <<<"$files"
        echo
      fi
      echo "- $(L Duration Süre): $sec $(L s sn)"
      if [[ -n $(meta_vals "$m" step) ]]; then
        echo
        L "| Step | Duration | Exit code |" "| Adım | Süre | Çıkış kodu |"
        echo
        echo "|------|-----:|:----------:|"
        while IFS=$'\t' read -r step_name step_sec step_rc; do
          echo "| $(md_cell "$step_name") | ${step_sec} $(L s sn) | $step_rc |"
        done < <(meta_vals "$m" step)
        echo
        L "_Exit code 0: clean. Codes meaning findings: gitleaks/semgrep/actionlint 1, trivy 3, osv-scanner 1, zizmor ≥ 10. Other values are tool errors._" \
          "_Çıkış kodu 0: temiz. Bulgu var anlamına gelenler: gitleaks/semgrep/actionlint 1, trivy 3, osv-scanner 1, zizmor ≥ 10. Diğer değerler araç hatasıdır._"
        echo
      fi
      echo
      echo '````text'
      strip_ansi <"$rdir/$c.log"
      echo '````'
      echo
      echo "</details>"
    done <<<"$rows"
    echo

    echo "## 🩺 $(L "Scan reliability" "Taramanın güvenilirliği")"
    echo
    L "This section lists problems with the scan itself (a tool that could not run, network access, etc.), not security findings. If there is a problem here, the result for that area may be incomplete." \
      "Bu bölüm güvenlik bulgularını değil, taramanın kendisinde yaşanan sorunları (çalışamayan araç, internet erişimi vb.) listeler. Burada bir sorun varsa ilgili alanın sonucu eksik olabilir."
    echo
    echo
    while IFS=$'\t' read -r c st sec; do
      if [[ $st == missing ]]; then
        echo "- **$(check_title "$c")**: $(L "did not run — the scan stopped before reaching this check. See the end of the console output (below)." \
          "çalışmadı — tarama bu kontrole gelmeden durdu. Konsol çıktısının sonuna bakın (aşağıda).")"
        n_issue=$((n_issue + 1))
      fi
      while IFS= read -r line; do
        [[ -n $line && $line != - ]] || continue
        echo "- **$(check_title "$c")**: $(md_cell "$line")"
        n_issue=$((n_issue + 1))
      done < <(issue_vals "$rdir/$c.meta" "$icol")
    done <<<"$rows"
    [[ $n_issue -gt 0 ]] || echo "✅ $(L "No problems: all tools ran and all checks completed." "Sorun yaşanmadı: tüm araçlar çalıştı ve kontroller tamamlandı.")"
    if grep -q missing <<<"$rows" && [[ -s "$rdir/console.log" ]]; then
      echo
      echo "**$(L "End of the console output" "Konsol çıktısının sonu")**"
      echo
      echo '````text'
      tail -40 "$rdir/console.log" | strip_ansi
      echo '````'
    fi
    echo

    echo "## ℹ️ $(L "Scan information" "Tarama bilgileri")"
    echo
    echo "| | |"
    echo "|---|---|"
    echo "| $(L "Project path" "Proje yolu") | \`$disp\` |"
    echo "| $(L "What was scanned" "Ne tarandı") | \`$MODE\` $(L mode modu) — $(mode_desc "$MODE") |"
    if $is_git; then
      echo "| Git | $(L "branch \`$branch\`, commit \`$commit\` — uncommitted/new files: $dirty" \
        "\`$branch\` dalı, \`$commit\` commit'i — commit'lenmemiş/yeni dosya: $dirty") |"
    else
      echo "| Git | $(L "not a git repository" "git deposu değil") |"
    fi
    echo "| $(L Started Başlangıç) | $START_TS |"
    echo "| $(L "Total duration" "Toplam süre") | $((ELAPSED / 60)) $(L min dk) $((ELAPSED % 60)) $(L s sn) |"
    echo "| $(L Configuration Yapılandırma) | $cfg (\`$(engine_config "$abs" | sed "s#^$KIT/##")\`) |"
    echo "| $(L Tools Araçlar) | $(grep -h '^SEC_IMG_' "$(engine_config "$abs")" | sed -E 's/^SEC_IMG_[A-Z]+="([^@"]+).*/`\1`/' | paste -sd' ' | sed 's/` `/`, `/g') |"
    echo
    echo "## 📖 $(L "Glossary" "Terimler")"
    echo
    L "| Term | Meaning |" "| Terim | Anlamı |"
    echo
    echo "|-------|--------|"
    L "| Blocking / Warning | A blocking finding should be fixed now; a warning is lower risk or depends on context. |
| Severity (Critical → Low) | How much damage the finding could cause if abused. |
| CVE / GHSA | The ID of a publicly recorded security vulnerability. |
| CVSS | A standard that scores the severity of a vulnerability from 0 to 10. 7 and above is high, 9 and above is critical. |
| Dependency / lockfile | Third-party libraries the project uses / the file that records their exact versions (e.g. \`package-lock.json\`). |
| Secret | Information that must stay private, such as a password, API key or token. |
| SAST | Finding vulnerabilities by reading the source code without running it. |
| IaC | Defining infrastructure (servers, containers, networks) as code: Dockerfile, Terraform, Kubernetes files. |
| CI/CD | The process where code is tested and released automatically (here GitHub Actions). |
| False positive | A finding the tool flags as a problem that actually carries no risk. |" \
"| Engelleyici / Uyarı | Engelleyici bulgu hemen düzeltilmelidir; uyarı daha düşük risklidir veya bağlama göre değerlendirilir. |
| Önem (Kritik → Düşük) | Bulgunun kötüye kullanılırsa yol açabileceği zararın büyüklüğü. |
| CVE / GHSA | Herkese açık olarak kayda geçmiş bir güvenlik açığının kimlik numarası. |
| CVSS | Bir açığın ciddiyetini 0–10 arasında puanlayan standart. 7 ve üstü yüksek, 9 ve üstü kritik sayılır. |
| Bağımlılık / lockfile | Projenin kullandığı dış kütüphaneler / bunların tam sürümlerinin kaydedildiği dosya (ör. \`package-lock.json\`). |
| Secret | Şifre, API anahtarı, token gibi gizli kalması gereken bilgi. |
| SAST | Kaynak kodu çalıştırmadan, yazılışına bakarak açık arama. |
| IaC | Altyapının (sunucu, container, ağ) kodla tanımlanması: Dockerfile, Terraform, Kubernetes dosyaları. |
| CI/CD | Kodun otomatik test edilip yayınlandığı süreç (burada GitHub Actions). |
| Yanlış pozitif | Araç tarafından sorun sanılan ama gerçekte risk taşımayan bulgu. |"
    echo
  } >"$md"

  {
    printf '{\n  "repo": %s,\n  "path": %s,\n  "mode": %s,\n' "$(json_str "$name")" "$(json_str "$disp")" "$(json_str "$MODE")"
    printf '  "started_at": %s,\n  "duration_seconds": %s,\n  "result": %s,\n' \
      "$(json_str "$START_ISO")" "$ELAPSED" "$(json_str "$result")"
    if $is_git; then
      printf '  "git": {"branch": %s, "commit": %s, "dirty_files": %s},\n' "$(json_str "$branch")" "$(json_str "$commit")" "$dirty"
    else
      printf '  "git": null,\n'
    fi
    printf '  "checks": ['
    first=true
    while IFS=$'\t' read -r c st sec; do
      m="$rdir/$c.meta"
      cnt=$(meta_one "$m" count)
      blk=${cnt%%$'\t'*} wrn=${cnt#*$'\t'}
      $first || printf ','
      first=false
      printf '\n    {"name": %s, "status": %s, "seconds": %s, "tool": %s, "scope": %s, "blocking": %s, "warnings": %s, "issues": [' \
        "$(json_str "$c")" "$(json_str "$st")" "${sec/-/null}" "$(json_str_or_null "$(meta_one "$m" tool)")" \
        "$(json_str_or_null "$(meta_one "$m" scope)")" "${blk:-null}" "${wrn:-null}"
      fi_=true
      while IFS= read -r line; do
        [[ -n $line && $line != - ]] || continue
        $fi_ || printf ', '
        fi_=false
        json_str "$line"
      done < <(issue_vals "$m" 1)
      printf '], "findings": ['
      fi_=true
      while IFS=$'\t' read -r lvl sev loc title detail ref link _; do
        $fi_ || printf ','
        fi_=false
        printf '\n      {"level": %s, "severity": %s, "location": %s, "title": %s, "detail": %s, "id": %s, "url": %s}' \
          "$(json_str "$lvl")" "$(json_str_or_null "${sev#-}")" "$(json_str "$loc")" "$(json_str "$title")" \
          "$(json_str_or_null "${detail#-}")" "$(json_str_or_null "${ref#-}")" "$(json_str_or_null "${link#-}")"
      done < <(sorted_findings "$m")
      $fi_ || printf '\n    '
      printf ']}'
    done <<<"$rows"
    printf '\n  ]\n}\n'
  } >"$json"
}

# clean_work <dir> — fully deletes the temporary working directory (copies of the scanned code, intermediate
# output, rule cache). Only the report is left behind after a scan.
clean_work() {
  [[ -n $1 && -d $1 ]] || return 0
  rm -rf "$1" 2>/dev/null || true
  if [[ -e $1 ]]; then
    echo "⚠ could not delete the temporary working directory: $1 (a process may be holding the files: IDE, antivirus)" >&2
  fi
}

engine_config() {
  local top
  if [[ -f "$1/.security/config.env" ]]; then echo "$1/.security/config.env"; return; fi
  top=$(git -C "$1" rev-parse --show-toplevel 2>/dev/null || true)
  if [[ -n $top && -f "$top/.security/config.env" ]]; then echo "$top/.security/config.env"; return; fi
  echo "$DEFAULTS/.security/config.env"
}

# scan_repo <path> → 0 passed, 1 failed, 2 could not run
scan_repo() {
  local path=$1 abs name work rdir is_git=false result=pass c base md json
  if ! abs=$(cd "$path" 2>/dev/null && pwd); then echo "✖ directory not found: $path"; return 2; fi
  name=$(basename "$abs")
  if git -C "$abs" rev-parse --is-inside-work-tree >/dev/null 2>&1; then is_git=true; fi
  if [[ $MODE != worktree ]] && ! $is_git; then
    echo "✖ '$MODE' mode requires a git repository: $abs (use 'worktree' for non-git directories)"
    return 2
  fi
  case $MODE in
    staged | base | full)
      if [[ -n $(git -C "$abs" rev-parse --show-prefix) ]]; then
        echo "✖ '$MODE' mode needs the repo root: $(git -C "$abs" rev-parse --show-toplevel)"
        return 2
      fi ;;
  esac

  # Each scan runs in a new, empty directory in the system temp dir and is fully deleted afterwards
  work=$(mktemp -d "${TMPDIR:-/tmp}/repo-sentinel-$name-XXXXXX") || { echo "✖ could not create a temporary directory"; return 2; }
  CUR_WORK=$work
  rdir="$work/report"
  mkdir -p "$rdir"
  START_TS=$(date '+%Y-%m-%d %H:%M:%S') START_ISO=$(date -u '+%Y-%m-%dT%H:%M:%SZ') START_SEC=$SECONDS
  base="$REPORT_DIR/$name-$(date +%Y%m%d-%H%M%S)"
  echo
  echo "════════ $name ($MODE) — $abs"
  engine "$abs" "$work" "$rdir" check "${MODE_ARGS[@]}" 2>&1 | tee "$rdir/console.log" || result=fail
  ELAPSED=$((SECONDS - START_SEC))

  if $REPORT; then
    mkdir -p "$REPORT_DIR"
    md="$base.md"; json="$base.json"
    write_report "$name" "$abs" "$is_git" "$rdir" "$result" "$md" "$json"
    echo "Report: $md"
    SUMMARY+=("$name"$'\t'"$result"$'\t'"$md")
  else
    SUMMARY+=("$name"$'\t'"$result"$'\t'"-")
  fi
  clean_work "$work"
  CUR_WORK=""
  [[ $result == pass ]]
}

main() {
  local repos=() only="" rc=0 r line name result md

  case "${1:-}" in
    pull | doctor)
      CUR_WORK=$(mktemp -d "${TMPDIR:-/tmp}/repo-sentinel-XXXXXX")
      trap 'clean_work "$CUR_WORK"' EXIT
      engine "$KIT" "$CUR_WORK" "" "$1"
      return ;;
  esac

  MODE="" REF="" REPORT=true REPORT_DIR="$KIT/reports"
  while [[ $# -gt 0 ]]; do
    case $1 in
      worktree | history | changes | staged | base | full) MODE=$1 ;;
      --ref) REF=${2:?--ref expects a git reference}; shift ;;
      --only) only=${2:?--only expects a list of checks}; shift ;;
      --lang) REPORT_LANG=${2:?--lang expects en or tr}; shift ;;
      --report-dir) REPORT_DIR=${2:?--report-dir expects a directory}; shift ;;
      --no-report) REPORT=false ;;
      -h | --help) usage ;;
      -*) echo "Unknown option: $1" >&2; usage ;;
      *) repos+=("$1") ;;
    esac
    shift
  done
  [[ ${#repos[@]} -gt 0 ]] || usage
  case $REPORT_LANG in en | tr) ;; *) echo "Unknown language: $REPORT_LANG (valid: en, tr)" >&2; exit 2 ;; esac
  MODE=${MODE:-worktree}
  [[ -z $REF || $MODE == base ]] || { echo "--ref can only be used with 'base' mode" >&2; exit 2; }
  if [[ $MODE == base ]]; then
    REF=${REF:-auto}
    MODE_ARGS=(--base "$REF")
  else
    MODE_ARGS=("--$MODE")
  fi

  CHECKS=$ALL_CHECKS
  if [[ -n $only ]]; then
    CHECKS=$(echo "$only" | tr ',' ' ')
    for c in $CHECKS; do
      case " $ALL_CHECKS " in *" $c "*) ;; *) echo "Unknown check: $c (valid: $ALL_CHECKS)" >&2; exit 2 ;; esac
    done
  fi

  if ! docker info >/dev/null 2>&1; then
    echo "✖ Docker is not running. Start Docker Desktop; on first use run: bash security-scan.sh pull" >&2
    exit 2
  fi

  SUMMARY=() CUR_WORK=""
  trap 'clean_work "$CUR_WORK"' EXIT   # copies must not be left behind on Ctrl+C or errors either
  for r in "${repos[@]}"; do
    scan_repo "$r" || { r=$?; [[ $r -gt $rc ]] && rc=$r; true; }
  done

  if [[ ${#repos[@]} -gt 1 ]]; then
    echo
    echo "════════ Summary"
    printf '%-24s %-12s %s\n' "REPO" "RESULT" "REPORT"
    for line in ${SUMMARY[@]+"${SUMMARY[@]}"}; do
      IFS=$'\t' read -r name result md <<<"$line"
      printf '%-24s %-12s %s\n' "$name" "$(if [[ $result == fail ]]; then echo "❌ failed"; else echo "✅ passed"; fi)" "$md"
    done
  fi
  return $rc
}

main "$@"
