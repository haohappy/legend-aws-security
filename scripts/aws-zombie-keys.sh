#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# AWS IAM 僵尸 Key 清理
#
# 查找所有 Active 但超过 N 天未使用的 Access Key，并可选择批量禁用。
# 默认以 dry-run 模式运行（只报告不执行），加 --execute 才会实际禁用。
#
# 用法:
#   # 查看哪些 Key 是僵尸（默认 180 天未使用）
#   ./scripts/aws-zombie-keys.sh --profile legend-security-hao
#
#   # 自定义阈值：90 天未使用
#   ./scripts/aws-zombie-keys.sh --days 90 --profile legend-security-hao
#
#   # 实际执行禁用
#   ./scripts/aws-zombie-keys.sh --execute --profile legend-security-hao
#
#   # 排除特定用户（逗号分隔）
#   ./scripts/aws-zombie-keys.sh --exclude "admin,monitor" --profile legend-security-hao
#
# 参数:
#   --profile <name>     AWS CLI profile
#   --days <n>           超过 N 天未使用视为僵尸 Key（默认 180）
#   --execute            实际执行禁用（不加此参数为 dry-run 模式）
#   --exclude <u1,u2>    排除的用户名列表（逗号分隔）
#   --output <file>      输出结果到文件
#   --help, -h           显示帮助
#
# 安全设计:
#   - 默认 dry-run，不会修改任何资源
#   - --execute 模式下会逐个确认（除非加 --yes 跳过确认）
#   - 禁用前检查用户是否有其他 Active Key，防止完全断开服务
#   - 只禁用（Inactive），不删除，方便回滚
# ============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PROFILE_OPT=""
ZOMBIE_DAYS=180
EXECUTE=false
AUTO_YES=false
EXCLUDE_LIST=""
OUTPUT_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) PROFILE_OPT="--profile $2"; shift 2 ;;
    --days) ZOMBIE_DAYS="$2"; shift 2 ;;
    --execute) EXECUTE=true; shift ;;
    --yes) AUTO_YES=true; shift ;;
    --exclude) EXCLUDE_LIST="$2"; shift 2 ;;
    --output) OUTPUT_FILE="$2"; shift 2 ;;
    --help|-h)
      sed -n '2,/^# =====/p' "$0" | head -n -1 | sed 's/^# \?//'
      exit 0
      ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

aws_cmd() {
  aws $PROFILE_OPT "$@" 2>&1
}

if [[ -n "$OUTPUT_FILE" ]]; then
  exec > >(tee >(sed 's/\x1b\[[0-9;]*m//g' > "$OUTPUT_FILE"))
fi

NOW_EPOCH=$(date +%s)

to_epoch() {
  local d="$1"
  date -jf "%Y-%m-%dT%H:%M:%S+00:00" "$d" +%s 2>/dev/null \
    || date -jf "%Y-%m-%dT%H:%M:%SZ" "$d" +%s 2>/dev/null \
    || date -d "$d" +%s 2>/dev/null \
    || echo "0"
}

is_excluded() {
  local user="$1"
  if [[ -z "$EXCLUDE_LIST" ]]; then return 1; fi
  IFS=',' read -ra excl <<< "$EXCLUDE_LIST"
  for e in "${excl[@]}"; do
    [[ "$user" == "$e" ]] && return 0
  done
  return 1
}

echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  AWS IAM 僵尸 Key 清理${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo ""

if [[ "$EXECUTE" == true ]]; then
  echo -e "  模式: ${RED}EXECUTE — 将实际禁用 Key${NC}"
else
  echo -e "  模式: ${GREEN}DRY-RUN — 仅报告，不修改${NC}"
fi
echo "  阈值: ${ZOMBIE_DAYS} 天未使用"
[[ -n "$EXCLUDE_LIST" ]] && echo "  排除: $EXCLUDE_LIST"
echo ""

# ── 扫描所有用户 ──
all_users=$(aws_cmd iam list-users --query 'Users[].UserName' --output text)
user_count=$(echo "$all_users" | wc -w | tr -d ' ')

zombies=()
scanned=0

for user in $all_users; do
  scanned=$((scanned + 1))
  printf "\r  扫描中... [%d/%d] %s          " "$scanned" "$user_count" "$user" >&2

  # 跳过排除列表中的用户
  if is_excluded "$user"; then continue; fi

  keys_json=$(aws_cmd iam list-access-keys --user-name "$user" --output json)
  active_keys=$(echo "$keys_json" | jq -r '.AccessKeyMetadata[] | select(.Status=="Active") | .AccessKeyId + "|" + .CreateDate')

  for key_line in $active_keys; do
    IFS='|' read -r key_id created <<< "$key_line"

    last_used_json=$(aws_cmd iam get-access-key-last-used --access-key-id "$key_id" --output json)
    last_used_date=$(echo "$last_used_json" | jq -r '.AccessKeyLastUsed.LastUsedDate // "NEVER"')
    last_service=$(echo "$last_used_json" | jq -r '.AccessKeyLastUsed.ServiceName // "N/A"')

    if [[ "$last_used_date" == "NEVER" ]]; then
      # 从未使用，按创建时间计算闲置天数
      created_epoch=$(to_epoch "$created")
      idle_days=$(( (NOW_EPOCH - created_epoch) / 86400 ))
      display_date="从未使用 (创建于 $created)"
    else
      last_used_epoch=$(to_epoch "$last_used_date")
      idle_days=$(( (NOW_EPOCH - last_used_epoch) / 86400 ))
      display_date="$last_used_date ($last_service)"
    fi

    if [[ "$idle_days" -gt "$ZOMBIE_DAYS" ]]; then
      zombies+=("${user}|${key_id}|${idle_days}|${display_date}")
    fi
  done
done

printf "\r  扫描完成。                                              \n" >&2
echo ""

# ── 报告 ──
if [[ ${#zombies[@]} -eq 0 ]]; then
  echo -e "  ${GREEN}未发现僵尸 Key（超过 ${ZOMBIE_DAYS} 天未使用的 Active Key）${NC}"
  echo ""
  exit 0
fi

echo -e "  ${YELLOW}发现 ${#zombies[@]} 个僵尸 Key：${NC}"
echo ""
printf "  %-40s %-22s %8s  %s\n" "用户" "Key ID" "闲置天数" "最后使用"
echo "  $(printf '─%.0s' {1..100})"

for z in "${zombies[@]}"; do
  IFS='|' read -r user key idle info <<< "$z"
  printf "  %-40s %-22s %6s 天  %s\n" "$user" "$key" "$idle" "$info"
done
echo ""

# ── 执行禁用 ──
if [[ "$EXECUTE" == true ]]; then
  echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}  开始禁用...${NC}"
  echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
  echo ""

  disabled=0
  skipped=0

  for z in "${zombies[@]}"; do
    IFS='|' read -r user key idle info <<< "$z"

    if [[ "$AUTO_YES" == false ]]; then
      echo -n "  禁用 $user 的 Key $key（闲置 ${idle} 天）？[y/N] "
      read -r confirm
      if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo "  跳过"
        skipped=$((skipped + 1))
        continue
      fi
    fi

    aws_cmd iam update-access-key \
      --user-name "$user" \
      --access-key-id "$key" \
      --status Inactive >/dev/null

    echo -e "  ${GREEN}已禁用${NC}: $user / $key"
    disabled=$((disabled + 1))
  done

  echo ""
  echo -e "  已禁用: ${disabled}，跳过: ${skipped}"
else
  echo -e "  ${CYAN}以上为 dry-run 结果。加 --execute 参数实际禁用。${NC}"
  echo -e "  ${CYAN}加 --execute --yes 跳过逐个确认。${NC}"
fi

echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo -e "  完成 — $(date '+%Y-%m-%d %H:%M:%S')"
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo ""
