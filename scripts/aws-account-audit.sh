#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# AWS IAM 全账户安全审计
#
# 扫描账户下所有 IAM 用户，检查凭据安全状态，输出分类汇总报告。
# 这是 aws-user-audit.sh（单用户深度审计）的批量版。
#
# 检查项:
#   - Access Key 状态与年龄（是否超 90 天未轮换）
#   - Key 最后使用时间（是否为僵尸 Key）
#   - Key 使用的服务是否与用户名推断的用途一致
#   - MFA 是否启用
#   - 是否配置了 IP 限制策略（如 DenyWithoutIPorMFA）
#   - Console 登录权限（login profile）
#
# 用法:
#   ./scripts/aws-account-audit.sh [--profile <profile>] [--zombie-days <n>] [--rotation-days <n>]
#
# 参数:
#   --profile <name>       AWS CLI profile（可选，默认使用 default profile）
#   --zombie-days <n>      超过 N 天未使用视为僵尸 Key（默认 180）
#   --rotation-days <n>    超过 N 天未轮换视为不合规（默认 90）
#   --output <file>        输出结果到文件（可选，默认仅输出到终端）
#   --help, -h             显示帮助
#
# 示例:
#   # 使用 legend-security-hao profile 审计全账户
#   ./scripts/aws-account-audit.sh --profile legend-security-hao
#
#   # 自定义阈值，将结果保存到文件
#   ./scripts/aws-account-audit.sh --profile legend-security-hao \
#     --zombie-days 90 --rotation-days 60 --output audit-result.txt
#
# 输出:
#   [1] 账户概览         — 用户总数、Key 总数、MFA 覆盖率
#   [2] 高危用户清单     — 有 Active Key 但无 MFA 且无 IP 限制
#   [3] 僵尸 Key 清单    — Active 但长期未使用的 Key
#   [4] 未轮换 Key 清单  — Active 且超期未轮换的 Key
#   [5] 服务异常检测     — Key 使用的服务与用户名不匹配
#   [6] Console 登录风险 — 有 Console 权限但无 MFA 的用户
# ============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── 参数解析 ──
PROFILE_OPT=""
ZOMBIE_DAYS=180
ROTATION_DAYS=90
OUTPUT_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) PROFILE_OPT="--profile $2"; shift 2 ;;
    --zombie-days) ZOMBIE_DAYS="$2"; shift 2 ;;
    --rotation-days) ROTATION_DAYS="$2"; shift 2 ;;
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

# 如果指定了输出文件，同时输出到终端和文件（去掉颜色码写入文件）
if [[ -n "$OUTPUT_FILE" ]]; then
  exec > >(tee >(sed 's/\x1b\[[0-9;]*m//g' > "$OUTPUT_FILE"))
fi

NOW_EPOCH=$(date +%s)

# 跨平台日期转换：将 ISO 8601 日期转为 epoch
to_epoch() {
  local d="$1"
  # macOS
  date -jf "%Y-%m-%dT%H:%M:%S+00:00" "$d" +%s 2>/dev/null \
    || date -jf "%Y-%m-%dT%H:%M:%SZ" "$d" +%s 2>/dev/null \
    || date -d "$d" +%s 2>/dev/null \
    || echo "0"
}

echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  AWS IAM 全账户安全审计${NC}"
echo -e "${BOLD}  $(date '+%Y-%m-%d %H:%M:%S')${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo ""

# ── 获取账户信息 ──
account_id=$(aws_cmd sts get-caller-identity --query 'Account' --output text)
caller_arn=$(aws_cmd sts get-caller-identity --query 'Arn' --output text)
echo -e "  账户 ID:    ${CYAN}${account_id}${NC}"
echo -e "  审计身份:   ${caller_arn}"
echo -e "  僵尸阈值:   ${ZOMBIE_DAYS} 天"
echo -e "  轮换阈值:   ${ROTATION_DAYS} 天"
echo ""

# ── 获取所有用户 ──
all_users=$(aws_cmd iam list-users --query 'Users[].UserName' --output text)
user_count=$(echo "$all_users" | wc -w | tr -d ' ')

echo -e "${BOLD}══════════════════════════════════════════════════════════=${NC}"
echo -e "${BOLD}[1] 开始扫描 ${user_count} 个用户...${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo ""

# ── 初始化计数器 ──
total_active_keys=0
total_inactive_keys=0
users_with_mfa=0
users_with_ip_policy=0
users_with_console=0
console_no_mfa=0

# ── 分类收集器（用临时文件） ──
TMP_DIR=$(mktemp -d)
trap "rm -rf $TMP_DIR" EXIT

touch "$TMP_DIR/high_risk.txt"       # 有 Active Key，无 MFA，无 IP 限制
touch "$TMP_DIR/zombie_keys.txt"     # Active 但长期未使用
touch "$TMP_DIR/unrotated_keys.txt"  # Active 但超期未轮换
touch "$TMP_DIR/service_mismatch.txt" # 使用服务与用户名不匹配
touch "$TMP_DIR/console_risk.txt"    # 有 Console 但无 MFA

# ── 推断用户用途（根据用户名中的关键词） ──
infer_service() {
  local name="$1"
  case "$name" in
    *ses*|*smtp*|*mail*) echo "ses" ;;
    *s3*)               echo "s3" ;;
    *ecr*)              echo "ecr" ;;
    *sqs*)              echo "sqs" ;;
    *sns*)              echo "sns" ;;
    *kms*)              echo "kms" ;;
    *eks*)              echo "eks|sts" ;;
    *firehose*)         echo "firehose" ;;
    *opensearch*)       echo "osis|es" ;;
    *monitor*)          echo "cloudwatch|monitoring" ;;
    *)                  echo "" ;;  # 无法推断
  esac
}

# ── 逐用户扫描 ──
scanned=0
for user in $all_users; do
  scanned=$((scanned + 1))
  printf "\r  扫描中... [%d/%d] %s          " "$scanned" "$user_count" "$user" >&2

  has_mfa=false
  has_ip_policy=false
  has_active_key=false
  has_console=false

  # -- MFA 检查 --
  mfa_count=$(aws_cmd iam list-mfa-devices --user-name "$user" --query 'MFADevices | length(@)' --output text)
  if [[ "$mfa_count" -gt 0 ]]; then
    has_mfa=true
    users_with_mfa=$((users_with_mfa + 1))
  fi

  # -- Console 登录检查 --
  if aws_cmd iam get-login-profile --user-name "$user" --output text >/dev/null 2>&1; then
    has_console=true
    users_with_console=$((users_with_console + 1))
    if [[ "$has_mfa" == false ]]; then
      console_no_mfa=$((console_no_mfa + 1))
      echo "$user" >> "$TMP_DIR/console_risk.txt"
    fi
  fi

  # -- IP 限制策略检查 --
  policies=$(aws_cmd iam list-user-policies --user-name "$user" --query 'PolicyNames[]' --output text)
  if echo "$policies" | grep -qiE "deny|ip"; then
    has_ip_policy=true
    users_with_ip_policy=$((users_with_ip_policy + 1))
  fi

  # -- Access Key 检查 --
  keys_json=$(aws_cmd iam list-access-keys --user-name "$user" --output json)
  key_ids=$(echo "$keys_json" | jq -r '.AccessKeyMetadata[] | .AccessKeyId + "|" + .Status + "|" + .CreateDate')

  active_key_list=""

  for key_line in $key_ids; do
    IFS='|' read -r key_id status created <<< "$key_line"

    if [[ "$status" == "Active" ]]; then
      has_active_key=true
      total_active_keys=$((total_active_keys + 1))
      active_key_list="${active_key_list}${key_id} "

      # 计算 Key 年龄
      created_epoch=$(to_epoch "$created")
      key_age_days=$(( (NOW_EPOCH - created_epoch) / 86400 ))

      # 获取最后使用信息
      last_used_json=$(aws_cmd iam get-access-key-last-used --access-key-id "$key_id" --output json)
      last_used_date=$(echo "$last_used_json" | jq -r '.AccessKeyLastUsed.LastUsedDate // "N/A"')
      last_service=$(echo "$last_used_json" | jq -r '.AccessKeyLastUsed.ServiceName // "N/A"')
      last_region=$(echo "$last_used_json" | jq -r '.AccessKeyLastUsed.Region // "N/A"')

      # 检查：轮换超期
      if [[ "$key_age_days" -gt "$ROTATION_DAYS" ]]; then
        echo "${user}|${key_id}|${key_age_days}|${last_used_date}|${last_service}|${last_region}" >> "$TMP_DIR/unrotated_keys.txt"
      fi

      # 检查：僵尸 Key
      if [[ "$last_used_date" != "N/A" ]]; then
        last_used_epoch=$(to_epoch "$last_used_date")
        idle_days=$(( (NOW_EPOCH - last_used_epoch) / 86400 ))
        if [[ "$idle_days" -gt "$ZOMBIE_DAYS" ]]; then
          echo "${user}|${key_id}|${idle_days}|${last_used_date}|${last_service}" >> "$TMP_DIR/zombie_keys.txt"
        fi
      fi

      # 检查：服务异常
      expected=$(infer_service "$user")
      if [[ -n "$expected" && "$last_service" != "N/A" ]]; then
        # 检查 last_service 是否匹配预期（支持用 | 分隔的多个预期值）
        match=false
        for exp in $(echo "$expected" | tr '|' ' '); do
          if echo "$last_service" | grep -qi "$exp"; then
            match=true
            break
          fi
        done
        # ses-smtp 也算 ses 的正常使用
        if echo "$last_service" | grep -qi "ses" && echo "$expected" | grep -qi "ses"; then
          match=true
        fi
        # sts 对 eks 用户是正常的
        if [[ "$last_service" == "sts" ]] && echo "$expected" | grep -qi "eks"; then
          match=true
        fi
        if [[ "$match" == false ]]; then
          echo "${user}|${key_id}|预期:${expected}|实际:${last_service}|${last_region}" >> "$TMP_DIR/service_mismatch.txt"
        fi
      fi
    else
      total_inactive_keys=$((total_inactive_keys + 1))
    fi
  done

  # 高危用户：有 Active Key + 无 MFA + 无 IP 限制
  if [[ "$has_active_key" == true && "$has_mfa" == false && "$has_ip_policy" == false ]]; then
    echo "${user}|${active_key_list}" >> "$TMP_DIR/high_risk.txt"
  fi
done

printf "\r  扫描完成。                                              \n" >&2
echo ""

# ══════════════════════════════════════════════════
# 输出报告
# ══════════════════════════════════════════════════

# ── [1] 账户概览 ──
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}[1] 账户概览${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "  用户总数:          $user_count"
echo "  Active Key 总数:   $total_active_keys"
echo "  Inactive Key 总数: $total_inactive_keys"
echo ""

mfa_pct=0
ip_pct=0
[[ "$user_count" -gt 0 ]] && mfa_pct=$((users_with_mfa * 100 / user_count))
[[ "$user_count" -gt 0 ]] && ip_pct=$((users_with_ip_policy * 100 / user_count))

if [[ "$mfa_pct" -lt 50 ]]; then
  echo -e "  MFA 启用:          ${RED}${users_with_mfa}/${user_count} (${mfa_pct}%)${NC}"
else
  echo -e "  MFA 启用:          ${GREEN}${users_with_mfa}/${user_count} (${mfa_pct}%)${NC}"
fi

if [[ "$ip_pct" -lt 50 ]]; then
  echo -e "  IP 限制策略:       ${RED}${users_with_ip_policy}/${user_count} (${ip_pct}%)${NC}"
else
  echo -e "  IP 限制策略:       ${GREEN}${users_with_ip_policy}/${user_count} (${ip_pct}%)${NC}"
fi

echo "  Console 登录权限:  $users_with_console"
echo ""

# ── [2] 高危用户 ──
high_risk_count=$(wc -l < "$TMP_DIR/high_risk.txt" | tr -d ' ')
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}[2] 高危用户 — Active Key + 无 MFA + 无 IP 限制${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo ""

if [[ "$high_risk_count" -eq 0 ]]; then
  echo -e "  ${GREEN}无高危用户${NC}"
else
  echo -e "  ${RED}共 ${high_risk_count} 个用户完全无防护：${NC}"
  echo ""
  while IFS='|' read -r user keys; do
    echo -e "  ${YELLOW}${user}${NC}"
    echo "    Keys: $keys"
  done < "$TMP_DIR/high_risk.txt"
fi
echo ""

# ── [3] 僵尸 Key ──
zombie_count=$(wc -l < "$TMP_DIR/zombie_keys.txt" | tr -d ' ')
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}[3] 僵尸 Key — Active 但超过 ${ZOMBIE_DAYS} 天未使用${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo ""

if [[ "$zombie_count" -eq 0 ]]; then
  echo -e "  ${GREEN}无僵尸 Key${NC}"
else
  echo -e "  ${YELLOW}共 ${zombie_count} 个 Key 建议禁用：${NC}"
  echo ""
  printf "  %-40s %-22s %8s  %s\n" "用户" "Key ID" "闲置天数" "最后使用"
  echo "  $(printf '─%.0s' {1..95})"
  sort -t'|' -k3 -rn "$TMP_DIR/zombie_keys.txt" | while IFS='|' read -r user key idle last_date svc; do
    printf "  %-40s %-22s %6s 天  %s (%s)\n" "$user" "$key" "$idle" "$last_date" "$svc"
  done
fi
echo ""

# ── [4] 未轮换 Key ──
unrotated_count=$(wc -l < "$TMP_DIR/unrotated_keys.txt" | tr -d ' ')
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}[4] 未轮换 Key — Active 且超过 ${ROTATION_DAYS} 天未轮换${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo ""

if [[ "$unrotated_count" -eq 0 ]]; then
  echo -e "  ${GREEN}所有 Key 均在轮换周期内${NC}"
else
  echo -e "  ${YELLOW}共 ${unrotated_count} 个 Key 超期未轮换：${NC}"
  echo ""
  printf "  %-40s %-22s %8s  %-12s %s\n" "用户" "Key ID" "Key 年龄" "最后服务" "最后区域"
  echo "  $(printf '─%.0s' {1..110})"
  sort -t'|' -k3 -rn "$TMP_DIR/unrotated_keys.txt" | while IFS='|' read -r user key age last_date svc region; do
    printf "  %-40s %-22s %5s 天  %-12s %s\n" "$user" "$key" "$age" "$svc" "$region"
  done
fi
echo ""

# ── [5] 服务异常 ──
mismatch_count=$(wc -l < "$TMP_DIR/service_mismatch.txt" | tr -d ' ')
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}[5] 服务使用异常 — 实际服务与用户名推断用途不匹配${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo ""

if [[ "$mismatch_count" -eq 0 ]]; then
  echo -e "  ${GREEN}未发现服务异常${NC}"
else
  echo -e "  ${RED}共 ${mismatch_count} 个 Key 的使用服务与预期不符（可能是泄露信号）：${NC}"
  echo ""
  while IFS='|' read -r user key expected actual region; do
    echo -e "  ${YELLOW}${user}${NC}  Key: ${key}"
    echo "    ${expected}  ${actual}  Region: ${region}"
  done < "$TMP_DIR/service_mismatch.txt"
fi
echo ""

# ── [6] Console 风险 ──
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}[6] Console 登录风险 — 有 Console 权限但无 MFA${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo ""

if [[ "$console_no_mfa" -eq 0 ]]; then
  echo -e "  ${GREEN}无 Console 登录风险${NC}"
else
  echo -e "  ${RED}共 ${console_no_mfa} 个用户有 Console 权限但未启用 MFA：${NC}"
  echo ""
  while read -r user; do
    echo -e "  ${YELLOW}${user}${NC}"
  done < "$TMP_DIR/console_risk.txt"
fi
echo ""

# ── 汇总 ──
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  审计汇总${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "  高危用户（无防护）:       $high_risk_count"
echo "  僵尸 Key:                $zombie_count"
echo "  未轮换 Key:              $unrotated_count"
echo "  服务异常:                $mismatch_count"
echo "  Console 无 MFA:          $console_no_mfa"
echo ""

total_issues=$((high_risk_count + zombie_count + mismatch_count + console_no_mfa))
if [[ "$total_issues" -eq 0 ]]; then
  echo -e "  ${GREEN}未发现安全问题${NC}"
else
  echo -e "  ${RED}共发现 ${total_issues} 项需要关注的安全问题${NC}"
fi
echo ""

if [[ -n "$OUTPUT_FILE" ]]; then
  echo -e "  结果已保存到: ${CYAN}${OUTPUT_FILE}${NC}"
  echo ""
fi

echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo -e "  审计完成 — $(date '+%Y-%m-%d %H:%M:%S')"
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo ""
