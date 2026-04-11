#!/usr/bin/env zsh
# mac-clean.sh — Safe macOS storage cleaner (audit-first)
# Adds two-phase workflow: --scan-plan FILE (generate TSV) -> edit selections -> --apply-plan FILE
# Optional interactive picker: --pick (prompts for indexes to delete)

set -euo pipefail

SCRIPT_NAME=${0:t}

# Defaults
DRY_RUN=1
YES=0
KEEP_DAYS=30
AGGRESSIVE=0

# Action toggles (opt-in via flags or presets)
DO_CACHES=0
DO_LOGS=0
DO_TRASH=0
DO_XCODE=0
DO_SIMS=0
DO_BREW=0
DO_DOCKER=0
DO_NPM=0
DO_YARN=0
DO_PNPM=0
DO_IOS_BACKUPS=0
DO_IMESSAGE=0
DO_QL=0
DO_SNAPSHOTS=0
BIG_FIND=0
BIG_MIN_SIZE="1G"

# New workflow flags
SCAN_PLAN_FILE=""
APPLY_PLAN_FILE=""
DO_PICK=0

RED="\033[31m"; GREEN="\033[32m"; YELLOW="\033[33m"; BLUE="\033[34m"; BOLD="\033[1m"; RESET="\033[0m"

msg() { printf "%s\n" "$1"; }
info() { printf "%bℹ %s%b\n" "$BLUE$BOLD" "$1" "$RESET"; }
success() { printf "%b✓ %s%b\n" "$GREEN$BOLD" "$1" "$RESET"; }
warn() { printf "%b! %s%b\n" "$YELLOW$BOLD" "$1" "$RESET"; }
err() { printf "%b✗ %s%b\n" "$RED$BOLD" "$1" "$RESET"; }

# Human-readable size from KB without external tools
humanize_kb() {
  local kb=${1:-0}
  local units=(KB MB GB TB PB)
  local idx=0
  local ival=$kb
  while (( ival >= 1024 && idx < ${#units[@]}-1 )); do
    ival=$(( ival / 1024 ))
    (( idx++ ))
  done
  printf '%s.0 %s' "$ival" "${units[$((idx+1))]}"
}

# Safe du -sk wrapper that returns 0 on error (no cut/awk)
size_kb_of() {
  local path="$1"
  [[ -e "$path" ]] || { echo 0; return 0; }
  local out
  out=$(du -sk "$path" 2>/dev/null) || out=""
  out="${out%%[[:space:]]*}"
  [[ -n "$out" ]] && echo "$out" || echo 0
}

# Read du output ("SIZE PATH") from stdin and emit only SIZE per line
du_sizes_only() {
  local size rest
  while IFS=$' \t' read -r size rest || [[ -n "$size" ]]; do
    [[ -z "$size" ]] && continue
    print -r -- "$size"
  done
}

# Sum integers from stdin, one per line
sum_kb_pipe() {
  local s=0 n
  while IFS= read -r n; do
    [[ -z "$n" ]] && continue
    n=${n%%[^0-9]*}
    [[ -z "$n" ]] && continue
    s=$(( s + n ))
  done
  print -r -- "$s"
}

confirm() {
  local prompt="$1"
  if [[ "$YES" -eq 1 ]]; then return 0; fi
  vared -p "$prompt [y/N]: " -c reply
  [[ "${reply:l}" == "y" || "${reply:l}" == "yes" ]]
}

need_cmd() { command -v "$1" >/dev/null 2>&1; }

usage() {
  cat <<USAGE
${BOLD}mac-clean.sh${RESET} — Audit and free disk space on macOS

Usage: ./${SCRIPT_NAME} [--audit|--run|--scan-plan F|--apply-plan F|--pick] [--all|--aggressive] [options]

Two-phase workflow:
  --scan-plan=FILE      Generate TSV plan with candidates (selected=0 by default)
  --apply-plan=FILE     Apply deletions where selected=1 (with prompts unless -y)
  --pick                Interactive picker after scan (enter indexes to delete)

Core:
  --audit               Show what would be cleaned (default)
  --run                 Perform cleanup (destructive for selected items)
  -y, --yes             Do not prompt for confirmation
  --keep-days=N         Keep files newer than N days (logs/archives), default ${KEEP_DAYS}

Presets:
  --all                 Safe set: caches, logs, trash, xcode, sims, brew, quicklook
  --aggressive          Add risky items: iOS backups, iMessage, Docker prune, snapshots

Targets (opt-in):
  --caches | --logs | --trash | --xcode | --sims | --brew | --docker | --npm | --yarn | --pnpm |
  --ios-backups | --imessage | --quicklook | --snapshots | --big[=SIZE]

Plan TSV columns (tab-separated):
  idx\ttype\tselected\tsize_kb\tcategory\titem
    - type: file|dir|op   item: path or operation name
USAGE
}

# Parse args
[[ $# -eq 0 ]] && { usage; exit 0; }
for raw in "$@"; do
  case "$raw" in
    --audit) DRY_RUN=1 ;;
    --run) DRY_RUN=0 ;;
    -y|--yes) YES=1 ;;
    --keep-days=*) KEEP_DAYS="${raw#*=}" ;;
    --all) DO_CACHES=1; DO_LOGS=1; DO_TRASH=1; DO_XCODE=1; DO_SIMS=1; DO_BREW=1; DO_QL=1 ;;
    --aggressive) AGGRESSIVE=1; DO_IOS_BACKUPS=1; DO_IMESSAGE=1; DO_DOCKER=1; DO_SNAPSHOTS=1 ;;
    --caches) DO_CACHES=1 ;;
    --logs) DO_LOGS=1 ;;
    --trash) DO_TRASH=1 ;;
    --xcode) DO_XCODE=1 ;;
    --sims) DO_SIMS=1 ;;
    --brew) DO_BREW=1 ;;
    --docker) DO_DOCKER=1 ;;
    --npm) DO_NPM=1 ;;
    --yarn) DO_YARN=1 ;;
    --pnpm) DO_PNPM=1 ;;
    --ios-backups) DO_IOS_BACKUPS=1 ;;
    --imessage) DO_IMESSAGE=1 ;;
    --quicklook) DO_QL=1 ;;
    --snapshots) DO_SNAPSHOTS=1 ;;
    --big) BIG_FIND=1 ;;
    --big=*) BIG_FIND=1; BIG_MIN_SIZE="${raw#*=}" ;;
    --scan-plan=*) SCAN_PLAN_FILE="${raw#*=}" ;;
    --apply-plan=*) APPLY_PLAN_FILE="${raw#*=}" ;;
    --pick) DO_PICK=1 ;;
    -h|--help) usage; exit 0 ;;
    *) err "Unknown option: $raw"; usage; exit 1 ;;
  esac
done

[[ "$AGGRESSIVE" -eq 1 ]] && warn "Aggressive mode enabled: includes riskier deletions."

TOTAL_KB=0
add_total() { TOTAL_KB=$(( TOTAL_KB + ${1:-0} )); }

# ---------- Plan helpers ----------
PLAN_IDX=0
plan_header() { print -r -- $'# idx\ttype\tselected\tsize_kb\tcategory\titem'; }
plan_add() {
  local type="$1" sel="0" size_kb="$2" cat="$3" item="$4"
  PLAN_IDX=$(( PLAN_IDX + 1 ))
  print -r -- "$PLAN_IDX\t$type\t$sel\t$size_kb\t$cat\t$item"
}

# ---------- Collectors (build plan) ----------
collect_caches() {
  local base="$HOME/Library/Caches"
  [[ -d "$base" ]] && {
    local p
    for p in "$base"/*(.N) "$base"/*(/N); do
      [[ -e "$p" ]] || continue
      plan_add dir "$(size_kb_of "$p")" caches "$p"
    done
  }
  local extra=(
    "$HOME/Library/Application Support/Slack/Cache"
    "$HOME/Library/Application Support/Slack/Service Worker/CacheStorage"
    "$HOME/Library/Application Support/Code/Cache"
    "$HOME/Library/Application Support/Google/Chrome/Default/Cache"
    "$HOME/Library/Containers/com.apple.Safari/Data/Library/Caches"
    "$HOME/Library/Caches/com.apple.QuickLookThumbnailing"
    "$HOME/Library/Containers/com.apple.mail/Data/Library/Mail Downloads"
  )
  local p
  for p in "$extra[@]"; do
    [[ -e "$p" ]] || continue
    plan_add dir "$(size_kb_of "$p")" caches "$p"
  done
}

collect_logs() {
  local d
  for d in "$HOME/Library/Logs" "/Library/Logs"; do
    [[ -d "$d" ]] || continue
    # Per-file older than KEEP_DAYS
    local f
    while IFS= read -r -d '' f; do
      plan_add file "$(size_kb_of "$f")" logs "$f"
    done < <(find "$d" -type f -mtime +"$KEEP_DAYS" -print0 2>/dev/null)
  done
}

collect_trash() {
  local t="$HOME/.Trash"
  [[ -d "$t" ]] || return 0
  local p
  for p in "$t"/*(N); do
    [[ -e "$p" ]] || continue
    plan_add dir "$(size_kb_of "$p")" trash "$p"
  done
}

collect_xcode() {
  local dd="$HOME/Library/Developer/Xcode/DerivedData"
  local arch="$HOME/Library/Developer/Xcode/Archives"
  local ds="$HOME/Library/Developer/Xcode/iOS DeviceSupport"
  local p
  [[ -d "$dd" ]] && for p in "$dd"/*(N); do [[ -e "$p" ]] && plan_add dir "$(size_kb_of "$p")" xcode "$p"; done
  [[ -d "$ds" ]] && for p in "$ds"/*(N); do [[ -e "$p" ]] && plan_add dir "$(size_kb_of "$p")" xcode "$p"; done
  if [[ -d "$arch" ]]; then
    while IFS= read -r -d '' p; do
      plan_add dir "$(size_kb_of "$p")" xcode "$p"
    done < <(find "$arch" -type d -maxdepth 2 -mindepth 2 -mtime +"$KEEP_DAYS" -print0 2>/dev/null)
  fi
}

collect_sims() {
  local sc="$HOME/Library/Developer/CoreSimulator/Caches"
  [[ -d "$sc" ]] && plan_add dir "$(size_kb_of "$sc")" sims "$sc"
  local devices="$HOME/Library/Developer/CoreSimulator/Devices"
  if [[ -d "$devices" ]]; then
    local p
    while IFS= read -r -d '' p; do
      plan_add dir "$(size_kb_of "$p")" sims "$p"
    done < <(find "$devices" -type d -path "*/data/Library/Caches" -print0 2>/dev/null)
  fi
}

collect_brew() {
  if need_cmd brew; then
    local cache="$HOME/Library/Caches/Homebrew"
    local size=$(size_kb_of "$cache")
    plan_add op "$size" brew brew_cleanup
  fi
}

collect_pkg_mgr() {
  if need_cmd npm; then
    local dir="$(npm config get cache 2>/dev/null || true)"
    [[ -n "$dir" && -d "$dir" ]] && plan_add dir "$(size_kb_of "$dir")" npm "$dir"
  fi
  if need_cmd yarn; then
    local dir="$HOME/Library/Caches/Yarn"
    [[ -d "$dir" ]] && plan_add dir "$(size_kb_of "$dir")" yarn "$dir"
  fi
  if need_cmd pnpm; then
    local dir="$(pnpm store path 2>/dev/null || true)"
    [[ -n "$dir" && -d "$dir" ]] && plan_add dir "$(size_kb_of "$dir")" pnpm "$dir"
  fi
}

collect_docker() {
  if need_cmd docker; then
    plan_add op 0 docker docker_prune_all
  fi
}

collect_ios_backups() {
  local dir="$HOME/Library/Application Support/MobileSync/Backup"
  [[ -d "$dir" ]] || return 0
  local p
  while IFS= read -r -d '' p; do
    plan_add dir "$(size_kb_of "$p")" ios_backup "$p"
  done < <(find "$dir" -type d -maxdepth 1 -mindepth 1 -mtime +"$KEEP_DAYS" -print0 2>/dev/null)
}

collect_imessage() {
  local dir="$HOME/Library/Messages/Attachments"
  [[ -d "$dir" ]] || return 0
  # Aggregate op for old attachments; per-file would be huge.
  local kb=$({
    find "$dir" -type f -mtime +"$KEEP_DAYS" -print0 2>/dev/null | xargs -0 -I{} du -sk {} 2>/dev/null
  } | du_sizes_only | sum_kb_pipe)
  plan_add op "$kb" imessage imessage_clean_old
}

collect_quicklook() {
  local dir="$HOME/Library/Caches/com.apple.QuickLookThumbnailing"
  [[ -d "$dir" ]] && plan_add dir "$(size_kb_of "$dir")" quicklook "$dir"
}

collect_snapshots() {
  if need_cmd tmutil; then
    plan_add op 0 snapshots tmutil_thin_10g
  fi
}

collect_bigfiles() {
  while IFS= read -r -d '' p; do
    plan_add file "$(size_kb_of "$p")" bigfile "$p"
  done < <(find "$HOME" -xdev -type f -size +${BIG_MIN_SIZE} \
            -not -path "$HOME/Library/Mobile Documents/*" \
            -not -path "$HOME/.Trash/*" -print0 2>/dev/null)
}

scan_to_plan() {
  local out="$1"
  : > "$out"
  plan_header >> "$out"
  [[ "$DO_CACHES" -eq 1 ]] && collect_caches >> "$out"
  [[ "$DO_LOGS" -eq 1 ]] && collect_logs >> "$out"
  [[ "$DO_TRASH" -eq 1 ]] && collect_trash >> "$out"
  [[ "$DO_XCODE" -eq 1 ]] && collect_xcode >> "$out"
  [[ "$DO_SIMS" -eq 1 ]] && collect_sims >> "$out"
  [[ "$DO_BREW" -eq 1 ]] && collect_brew >> "$out"
  [[ "$DO_NPM" -eq 1 || "$DO_YARN" -eq 1 || "$DO_PNPM" -eq 1 ]] && collect_pkg_mgr >> "$out"
  [[ "$DO_DOCKER" -eq 1 ]] && collect_docker >> "$out"
  [[ "$DO_IOS_BACKUPS" -eq 1 ]] && collect_ios_backups >> "$out"
  [[ "$DO_IMESSAGE" -eq 1 ]] && collect_imessage >> "$out"
  [[ "$DO_QL" -eq 1 ]] && collect_quicklook >> "$out"
  [[ "$DO_SNAPSHOTS" -eq 1 ]] && collect_snapshots >> "$out"
  [[ "$BIG_FIND" -eq 1 ]] && collect_bigfiles >> "$out"
}

apply_op() {
  local op="$1"
  case "$op" in
    brew_cleanup)
      need_cmd brew || { warn "brew not available; skipping"; return 0; }
      confirm "Run 'brew cleanup -s --prune=all'?" || return 0
      brew cleanup -s --prune=all -q || true
      rm -rf "$HOME/Library/Caches/Homebrew"/* 2>/dev/null || true
      ;;
    docker_prune_all)
      need_cmd docker || { warn "docker not available; skipping"; return 0; }
      confirm "Run 'docker system prune -af --volumes'?" || return 0
      docker system prune -af --volumes || true
      ;;
    imessage_clean_old)
      local dir="$HOME/Library/Messages/Attachments"
      [[ -d "$dir" ]] || { warn "No iMessage dir"; return 0; }
      confirm "Delete iMessage attachments older than ${KEEP_DAYS}d?" || return 0
      find "$dir" -type f -mtime +"$KEEP_DAYS" -delete 2>/dev/null || true
      ;;
    tmutil_thin_10g)
      need_cmd tmutil || { warn "tmutil not available"; return 0; }
      confirm "Thin local snapshots by ~10G?" || return 0
      sudo tmutil thinlocalsnapshots / 10000000000 4 2>/dev/null || true
      ;;
    *) warn "Unknown op: $op" ;;
  esac
}

apply_plan() {
  local file="$1"
  [[ -f "$file" ]] || { err "Plan not found: $file"; exit 1; }
  local IFS=$'\t'
  local line idx type sel size_kb cat item
  local count=0
  while read -r idx type sel size_kb cat item || [[ -n "$idx" ]]; do
    [[ -z "$idx" || "$idx" == \#* ]] && continue
    [[ "$sel" != "1" ]] && continue
    if [[ "$type" == "op" ]]; then
      apply_op "$item"
      continue
    fi
    if [[ ! -e "$item" ]]; then warn "Missing: $item"; continue; fi
    if [[ -d "$item" ]]; then
      confirm "Delete directory: $item?" || continue
      rm -rf -- "$item" 2>/dev/null || true
    else
      confirm "Delete file: $item?" || continue
      rm -f -- "$item" 2>/dev/null || true
    fi
    (( count++ ))
  done < "$file"
  success "Applied plan selections: $count items processed"
}

# ---------- Original action mode (audit/run) ----------
act_caches() {
  local target="$HOME/Library/Caches"
  local kb=$(size_kb_of "$target")
  info "Caches (~/${target#${HOME}/}) => $(humanize_kb "$kb")"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    confirm "Clear user caches?" || return 0
    find "$target" -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null || true
    success "Cleared user caches"
  fi
  add_total "$kb"
  local p
  for p in \
    "$HOME/Library/Application Support/Slack/Cache" \
    "$HOME/Library/Application Support/Slack/Service Worker/CacheStorage" \
    "$HOME/Library/Application Support/Code/Cache" \
    "$HOME/Library/Application Support/Google/Chrome/Default/Cache" \
    "$HOME/Library/Containers/com.apple.Safari/Data/Library/Caches" \
    "$HOME/Library/Caches/com.apple.QuickLookThumbnailing" \
    "$HOME/Library/Containers/com.apple.mail/Data/Library/Mail Downloads" ; do
    [[ -e "$p" ]] || continue
    local pkb=$(size_kb_of "$p")
    info "Extra cache: ${p#${HOME}/} => $(humanize_kb "$pkb")"
    if [[ "$DRY_RUN" -eq 0 ]]; then
      confirm "Delete ${p#${HOME}/}?" || continue
      rm -rf -- "$p" 2>/dev/null || true
      success "Removed ${p#${HOME}/}"
    fi
    add_total "$pkb"
  done
}

act_logs() {
  local kb=0
  local d add
  for d in "$HOME/Library/Logs" "/Library/Logs"; do
    [[ -d "$d" ]] || continue
    add=$({
        find "$d" -type f -mtime +"$KEEP_DAYS" -print0 2>/dev/null \
        | xargs -0 -I{} du -sk {} 2>/dev/null
      } | du_sizes_only | sum_kb_pipe)
    [[ -z "$add" ]] && add=0
    kb=$(( kb + add ))
  done
  info "Old logs (>${KEEP_DAYS}d) => $(humanize_kb "$kb")"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    confirm "Delete old logs?" && {
      for d in "$HOME/Library/Logs" "/Library/Logs"; do
        [[ -d "$d" ]] || continue
        find "$d" -type f -mtime +"$KEEP_DAYS" -delete 2>/dev/null || true
      done
      success "Old logs deleted"
    }
  fi
  add_total "$kb"
}

act_trash() {
  local kb=0
  local t="$HOME/.Trash"
  if [[ -d "$t" ]]; then
    local tkb=$(size_kb_of "$t")
    kb=$(( kb + tkb ))
  fi
  info "Trash => $(humanize_kb "$kb")"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    confirm "Empty Trash?" && { rm -rf "$t"/* 2>/dev/null || true; success "Trash emptied"; }
  fi
  add_total "$kb"
}

act_xcode() {
  local kb=0
  local dd="$HOME/Library/Developer/Xcode/DerivedData"
  local arch="$HOME/Library/Developer/Xcode/Archives"
  local ds="$HOME/Library/Developer/Xcode/iOS DeviceSupport"
  local p
  for p in "$dd" "$ds"; do
    [[ -e "$p" ]] || continue
    local add=$(size_kb_of "$p")
    kb=$(( kb + add ))
    info "Xcode: ${p#${HOME}/} => $(humanize_kb "$add")"
  done
  if [[ -d "$arch" ]]; then
    local add=$({
        find "$arch" -type d -maxdepth 2 -mindepth 2 -mtime +"$KEEP_DAYS" -print0 2>/dev/null \
        | xargs -0 -I{} du -sk {} 2>/dev/null
      } | du_sizes_only | sum_kb_pipe)
    kb=$(( kb + add ))
    info "Xcode: Archives older than ${KEEP_DAYS}d => $(humanize_kb "$add")"
  fi
  if [[ "$DRY_RUN" -eq 0 ]]; then
    confirm "Clean Xcode DerivedData and old archives?" && {
      [[ -d "$dd" ]] && rm -rf "$dd" 2>/dev/null || true
      if [[ -d "$arch" ]]; then
        find "$arch" -type d -maxdepth 2 -mindepth 2 -mtime +"$KEEP_DAYS" -exec rm -rf {} + 2>/dev/null || true
      fi
      [[ -d "$ds" ]] && rm -rf "$ds" 2>/dev/null || true
      success "Xcode cleanup complete"
    }
  fi
  add_total "$kb"
}

act_sims() {
  local kb=0
  local sc="$HOME/Library/Developer/CoreSimulator/Caches"
  local devices="$HOME/Library/Developer/CoreSimulator/Devices"
  if [[ -d "$sc" ]]; then
    kb=$(( kb + $(size_kb_of "$sc") ))
  fi
  if [[ -d "$devices" ]]; then
    local add=$({
        find "$devices" -type d -path "*/data/Library/Caches" -print0 2>/dev/null \
        | xargs -0 -I{} du -sk {} 2>/dev/null
      } | du_sizes_only | sum_kb_pipe)
    kb=$(( kb + add ))
  fi
  info "Simulator caches => $(humanize_kb "$kb")"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    confirm "Clear simulator caches and delete unavailable devices?" && {
      [[ -d "$sc" ]] && rm -rf "$sc" 2>/dev/null || true
      if need_cmd xcrun; then
        xcrun simctl delete unavailable >/dev/null 2>&1 || true
      fi
      if [[ -d "$devices" ]]; then
        find "$devices" -type d -path "*/data/Library/Caches" -exec rm -rf {} + 2>/dev/null || true
      fi
      success "Simulator cleanup complete"
    }
  fi
  add_total "$kb"
}

act_brew() {
  if ! need_cmd brew; then warn "Homebrew not found; skipping"; return 0; fi
  info "Homebrew cleanup (downloads, old versions)"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    confirm "Run 'brew cleanup -s --prune=all' and clear cache?" && {
      brew cleanup -s --prune=all -q || true
      rm -rf "$HOME/Library/Caches/Homebrew"/* 2>/dev/null || true
      success "Homebrew cleanup complete"
    }
  fi
}

act_pkg_mgr() {
  if [[ "$DO_NPM" -eq 1 ]]; then
    if need_cmd npm; then
      info "npm cache => size may vary"
      [[ "$DRY_RUN" -eq 0 ]] && confirm "npm cache clean --force?" && npm cache clean --force || true
    else warn "npm not found; skipping"; fi
  fi
  if [[ "$DO_YARN" -eq 1 ]]; then
    if need_cmd yarn; then
      info "yarn cache"
      [[ "$DRY_RUN" -eq 0 ]] && confirm "yarn cache clean?" && yarn cache clean || true
    else warn "yarn not found; skipping"; fi
  fi
  if [[ "$DO_PNPM" -eq 1 ]]; then
    if need_cmd pnpm; then
      info "pnpm store"
      [[ "$DRY_RUN" -eq 0 ]] && confirm "pnpm store prune?" && pnpm store prune || true
    else warn "pnpm not found; skipping"; fi
  fi
}

act_docker() {
  if ! need_cmd docker; then warn "docker not found; skipping"; return 0; fi
  info "Docker system prune (images, containers, volumes)"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    confirm "Run 'docker system prune -af --volumes'? This removes ALL unused data." && {
      docker system prune -af --volumes || true
      success "Docker prune done"
    }
  fi
}

act_ios_backups() {
  local dir="$HOME/Library/Application Support/MobileSync/Backup"
  [[ -d "$dir" ]] || { warn "No iOS backups directory"; return 0; }
  local kb=$({
      find "$dir" -type d -maxdepth 1 -mindepth 1 -mtime +"$KEEP_DAYS" -print0 2>/dev/null \
      | xargs -0 -I{} du -sk {} 2>/dev/null
    } | du_sizes_only | sum_kb_pipe)
  info "iOS backups older than ${KEEP_DAYS}d => $(humanize_kb "$kb")"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    confirm "Delete older iOS device backups?" && {
      find "$dir" -type d -maxdepth 1 -mindepth 1 -mtime +"$KEEP_DAYS" -exec rm -rf {} + 2>/dev/null || true
      success "Old iOS backups removed"
    }
  fi
  add_total "$kb"
}

act_imessage() {
  local dir="$HOME/Library/Messages/Attachments"
  [[ -d "$dir" ]] || { warn "No iMessage attachments dir"; return 0; }
  local kb=$({
      find "$dir" -type f -mtime +"$KEEP_DAYS" -print0 2>/dev/null \
      | xargs -0 -I{} du -sk {} 2>/dev/null
    } | du_sizes_only | sum_kb_pipe)
  info "iMessage attachments older than ${KEEP_DAYS}d => $(humanize_kb "$kb") (DANGEROUS)"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    confirm "Delete old iMessage attachments? (cannot be undone)" && {
      find "$dir" -type f -mtime +"$KEEP_DAYS" -delete 2>/dev/null || true
      success "Old iMessage attachments deleted"
    }
  fi
  add_total "$kb"
}

act_quicklook() {
  local dir="$HOME/Library/Caches/com.apple.QuickLookThumbnailing"
  local kb=$(size_kb_of "$dir")
  info "Quick Look cache => $(humanize_kb "$kb")"
  if [[ "$DRY_RUN" -eq 0 ]]; then
    confirm "Clear Quick Look cache?" && { rm -rf "$dir" 2>/dev/null || true; success "Quick Look cache cleared"; }
  fi
  add_total "$kb"
}

act_snapshots() {
  if ! need_cmd tmutil; then warn "tmutil not found; skipping snapshots"; return 0; fi
  info "Local Time Machine snapshots: listing"
  tmutil listlocalsnapshots / 2>/dev/null || true
  if [[ "$DRY_RUN" -eq 0 ]]; then
    confirm "Thin local snapshots by ~10G? (admin may be required)" && {
      sudo tmutil thinlocalsnapshots / 10000000000 4 2>/dev/null || true
      success "Requested snapshot thinning"
    }
  fi
}

act_bigfiles() {
  info "Listing files >= ${BIG_MIN_SIZE} under ~ (no deletion)"
  find "$HOME" -xdev -type f -size +${BIG_MIN_SIZE} \
    -not -path "$HOME/Library/Mobile Documents/*" \
    -not -path "$HOME/.Trash/*" \
    -print
}

run_selected_actions() {
  if [[ "$DO_CACHES" -eq 1 ]]; then act_caches; fi
  if [[ "$DO_LOGS" -eq 1 ]]; then act_logs; fi
  if [[ "$DO_TRASH" -eq 1 ]]; then act_trash; fi
  if [[ "$DO_XCODE" -eq 1 ]]; then act_xcode; fi
  if [[ "$DO_SIMS" -eq 1 ]]; then act_sims; fi
  if [[ "$DO_BREW" -eq 1 ]]; then act_brew; fi
  if [[ "$DO_NPM" -eq 1 || "$DO_YARN" -eq 1 || "$DO_PNPM" -eq 1 ]]; then act_pkg_mgr; fi
  if [[ "$DO_DOCKER" -eq 1 ]]; then act_docker; fi
  if [[ "$DO_IOS_BACKUPS" -eq 1 ]]; then act_ios_backups; fi
  if [[ "$DO_IMESSAGE" -eq 1 ]]; then act_imessage; fi
  if [[ "$DO_QL" -eq 1 ]]; then act_quicklook; fi
  if [[ "$DO_SNAPSHOTS" -eq 1 ]]; then act_snapshots; fi
  if [[ "$BIG_FIND" -eq 1 ]]; then act_bigfiles; fi
}

# ---------- Main flow ----------

# 1) Plan generation
if [[ -n "$SCAN_PLAN_FILE" ]]; then
  info "Scanning and writing plan to: $SCAN_PLAN_FILE"
  scan_to_plan "$SCAN_PLAN_FILE"
  success "Plan generated. Edit the 'selected' column to 1 for items to delete, then run:"
  msg "  ./$SCRIPT_NAME --apply-plan='$SCAN_PLAN_FILE' -y"
  [[ "$DO_PICK" -eq 0 ]] && exit 0
fi

# 2) Interactive picker
if [[ "$DO_PICK" -eq 1 ]]; then
  local tmp_plan="${SCAN_PLAN_FILE:-$PWD/mac-clean-plan.tsv}"
  [[ -z "$SCAN_PLAN_FILE" ]] && { scan_to_plan "$tmp_plan"; }
  info "Interactive picker — showing candidates"
  nl -ba "$tmp_plan" | sed -n '1,200p'
  vared -p $'Enter indexes to delete (e.g., 3,5-7) or blank to cancel: ' -c picks
  if [[ -z "${picks:-}" ]]; then
    warn "No selection; exiting"
    exit 0
  fi
  # Build a temp plan with selected=1 for chosen indexes
  local sel_plan="$PWD/.mac-clean-selected.tsv"
  : > "$sel_plan"
  local IFS=$'\t'
  local idx type sel size_kb cat item
  while read -r idx type sel size_kb cat item || [[ -n "$idx" ]]; do
    if [[ -z "$idx" || "$idx" == \#* ]]; then
      print -r -- "$idx" >> "$sel_plan"; continue
    fi
    # Check if idx is in picks
    if print -r -- ",$picks," | grep -Eq ",("$idx"|[0-9]+-[0-9]+),"; then
      # Rough range support via grep; fallback sets to 1 when any match
      print -r -- "$idx\t$type\t1\t$size_kb\t$cat\t$item" >> "$sel_plan"
    else
      print -r -- "$idx\t$type\t0\t$size_kb\t$cat\t$item" >> "$sel_plan"
    fi
  done < "$tmp_plan"
  APPLY_PLAN_FILE="$sel_plan"
fi

# 3) Apply plan
if [[ -n "$APPLY_PLAN_FILE" ]]; then
  apply_plan "$APPLY_PLAN_FILE"
  exit 0
fi

# 4) Legacy audit/run flow
phase_desc=$([[ "$DRY_RUN" -eq 1 ]] && echo "AUDIT" || echo "CLEAN")
info "${phase_desc} starting…"
run_selected_actions
if [[ "$DRY_RUN" -eq 1 ]]; then
  info "Estimated reclaimable (upper bound): $(humanize_kb "$TOTAL_KB")"
  warn "This is an estimate; some items may be in use or protected."
else
  success "Cleanup completed. You may want to reboot or log out/in."
fi

exit 0
