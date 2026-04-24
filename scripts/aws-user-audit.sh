#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# AWS IAM User Activity Audit
# 检查 IAM 用户的访问密钥使用情况和近期 API 调用，用于判断是否存在泄露/盗用
#
# 用法:
#   ./scripts/aws-user-audit.sh <username> [--profile <profile>] [--days <n>]
#
# 参数:
#   username              IAM 用户名（必填）
#   --profile <name>      AWS CLI profile 名称（可选，默认使用 default profile）
#   --days <n>            CloudTrail 回溯天数（可选，默认 7 天）
#   --help, -h            显示帮助
#
# 示例:
#   # 审计 admin 用户，使用 tokenrouter-deploy profile，默认看 7 天
#   ./scripts/aws-user-audit.sh admin --profile tokenrouter-deploy
#
#   # 审计 admin 用户，看最近 30 天
#   ./scripts/aws-user-audit.sh admin --profile tokenrouter-deploy --days 30
#
#   # 审计 Bedrock API 用户
#   ./scripts/aws-user-audit.sh BedrockAPIKey-qinn --profile tokenrouter-deploy
#
#   # 审计 SES 用户
#   ./scripts/aws-user-audit.sh AmazonSSM_Claude_Code_Hao --profile tokenrouter-deploy
#
# 输出内容:
#   [1] 用户基本信息     — ARN、创建时间、控制台最后登录
#   [2] Access Key 状态  — 每个 Key 的最后使用时间/服务/区域
#   [3] 权限策略         — 托管策略、内联策略、所属组
#   [4] MFA 状态         — 是否启用多因素认证
#   [5] CloudTrail 记录  — 按来源 IP 和 API 调用统计，显示详细记录
#   [6] 异常检测         — 多活跃 Key、无 MFA、Key 未轮换、IP 限制策略检查
#
# 判断泄露的关键指标:
#   - [5] 中出现不认识的来源 IP
#   - [5] 中出现非业务相关的 API 调用（如 CreateUser、AttachPolicy 等）
#   - [2] 中 Key 最后使用的服务/区域与预期不符
# ============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

USERNAME=""
PROFILE_OPT=""
DAYS=7

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) PROFILE_OPT="--profile $2"; shift 2 ;;
    --days) DAYS="$2"; shift 2 ;;
    --help|-h)
      echo "Usage: $0 <username> [--profile <profile>] [--days <n>]"
      echo ""
      echo "  username           IAM user name (required)"
      echo "  --profile <name>   AWS CLI profile (optional)"
      echo "  --days <n>         CloudTrail lookback days (default: 7)"
      exit 0
      ;;
    *) USERNAME="$1"; shift ;;
  esac
done

if [[ -z "$USERNAME" ]]; then
  echo -e "${RED}Error: username required${NC}"
  echo "Usage: $0 <username> [--profile <profile>] [--days <n>]"
  exit 1
fi

aws_cmd() {
  aws $PROFILE_OPT "$@" 2>&1
}

echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  AWS IAM User Audit: ${CYAN}${USERNAME}${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
echo ""

# ── 1. User Info ──
echo -e "${BOLD}[1] 用户基本信息${NC}"
echo "────────────────────────────────────────"

user_info=$(aws_cmd iam get-user --user-name "$USERNAME" --output json)
user_arn=$(echo "$user_info" | jq -r '.User.Arn')
create_date=$(echo "$user_info" | jq -r '.User.CreateDate')
password_last_used=$(echo "$user_info" | jq -r '.User.PasswordLastUsed // "从未使用控制台登录"')

echo "  ARN:              $user_arn"
echo "  创建时间:          $create_date"
echo "  控制台最后登录:     $password_last_used"
echo ""

# ── 2. Access Keys ──
echo -e "${BOLD}[2] Access Key 状态${NC}"
echo "────────────────────────────────────────"

keys=$(aws_cmd iam list-access-keys --user-name "$USERNAME" --output json)
key_count=$(echo "$keys" | jq '.AccessKeyMetadata | length')

if [[ "$key_count" -eq 0 ]]; then
  echo "  无 Access Key"
else
  echo "$keys" | jq -r '.AccessKeyMetadata[] | .AccessKeyId' | while read -r key_id; do
    key_meta=$(echo "$keys" | jq -r ".AccessKeyMetadata[] | select(.AccessKeyId==\"$key_id\")")
    status=$(echo "$key_meta" | jq -r '.Status')
    created=$(echo "$key_meta" | jq -r '.CreateDate')

    last_used_info=$(aws_cmd iam get-access-key-last-used --access-key-id "$key_id" --output json)
    last_used=$(echo "$last_used_info" | jq -r '.AccessKeyLastUsed.LastUsedDate // "从未使用"')
    last_service=$(echo "$last_used_info" | jq -r '.AccessKeyLastUsed.ServiceName // "N/A"')
    last_region=$(echo "$last_used_info" | jq -r '.AccessKeyLastUsed.Region // "N/A"')

    status_color=$GREEN
    [[ "$status" == "Inactive" ]] && status_color=$YELLOW

    echo ""
    echo -e "  Key: ${BOLD}${key_id}${NC}"
    echo -e "  状态:       ${status_color}${status}${NC}"
    echo "  创建时间:    $created"
    echo "  最后使用:    $last_used"
    echo "  最后服务:    $last_service"
    echo "  最后区域:    $last_region"
  done
fi
echo ""

# ── 3. Attached Policies ──
echo -e "${BOLD}[3] 权限策略${NC}"
echo "────────────────────────────────────────"

# Managed policies
managed=$(aws_cmd iam list-attached-user-policies --user-name "$USERNAME" --output json)
echo "$managed" | jq -r '.AttachedPolicies[] | "  [托管] \(.PolicyName)"' 2>/dev/null || echo "  无托管策略"

# Inline policies
inline=$(aws_cmd iam list-user-policies --user-name "$USERNAME" --output json)
echo "$inline" | jq -r '.PolicyNames[] | "  [内联] \(.)"' 2>/dev/null || echo "  无内联策略"

# Groups
groups=$(aws_cmd iam list-groups-for-user --user-name "$USERNAME" --output json)
group_count=$(echo "$groups" | jq '.Groups | length')
if [[ "$group_count" -gt 0 ]]; then
  echo "$groups" | jq -r '.Groups[] | "  [组]   \(.GroupName)"'
fi
echo ""

# ── 4. MFA ──
echo -e "${BOLD}[4] MFA 状态${NC}"
echo "────────────────────────────────────────"

mfa=$(aws_cmd iam list-mfa-devices --user-name "$USERNAME" --output json)
mfa_count=$(echo "$mfa" | jq '.MFADevices | length')

if [[ "$mfa_count" -eq 0 ]]; then
  echo -e "  ${RED}未启用 MFA${NC} — 建议立即启用"
else
  echo "$mfa" | jq -r '.MFADevices[] | "  ✓ \(.SerialNumber) (启用于 \(.EnableDate))"'
fi
echo ""

# ── 5. CloudTrail — 近期 API 调用 ──
echo -e "${BOLD}[5] 近 ${DAYS} 天 API 调用（CloudTrail）${NC}"
echo "────────────────────────────────────────"

start_time=$(date -u -v-${DAYS}d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "${DAYS} days ago" +%Y-%m-%dT%H:%M:%SZ)

# 尝试每个可能有 trail 的区域
for region in us-east-1 ap-southeast-1; do
  echo ""
  echo -e "  ${CYAN}── Region: ${region} ──${NC}"

  trail_events=$(aws_cmd cloudtrail lookup-events \
    --lookup-attributes "AttributeKey=Username,AttributeValue=$USERNAME" \
    --start-time "$start_time" \
    --max-results 50 \
    --region "$region" \
    --output json 2>&1 || true)

  if echo "$trail_events" | jq -e '.Events' >/dev/null 2>&1; then
    event_count=$(echo "$trail_events" | jq '.Events | length')

    if [[ "$event_count" -eq 0 ]]; then
      echo "  无记录"
    else
      echo -e "  共 ${BOLD}${event_count}${NC} 条记录（显示最近 50 条）"
      echo ""

      # 汇总：按源 IP 统计
      echo -e "  ${BOLD}按来源 IP 统计:${NC}"
      echo "$trail_events" | jq -r '
        [.Events[] | .CloudTrailEvent | fromjson | .sourceIPAddress] |
        group_by(.) | map({ip: .[0], count: length}) |
        sort_by(-.count)[] |
        "    \(.ip)  (\(.count) 次)"
      ' 2>/dev/null || echo "    解析失败"
      echo ""

      # 汇总：按 API 调用统计
      echo -e "  ${BOLD}按 API 调用统计:${NC}"
      echo "$trail_events" | jq -r '
        [.Events[] | .EventName] |
        group_by(.) | map({api: .[0], count: length}) |
        sort_by(-.count)[] |
        "    \(.api)  (\(.count) 次)"
      ' 2>/dev/null || echo "    解析失败"
      echo ""

      # 详细：最近 10 条
      echo -e "  ${BOLD}最近 10 条调用:${NC}"
      echo "$trail_events" | jq -r '
        .Events[:10][] |
        .CloudTrailEvent | fromjson |
        "    \(.eventTime)  \(.eventName)  \(.sourceIPAddress)  \(.awsRegion)"
      ' 2>/dev/null || echo "    解析失败"
    fi
  else
    echo "  CloudTrail 不可用或无权限"
  fi
done
echo ""

# ── 6. 异常检测 ──
echo -e "${BOLD}[6] 异常检测${NC}"
echo "────────────────────────────────────────"

warnings=0

# 检查：多个活跃 Key
active_keys=$(echo "$keys" | jq '[.AccessKeyMetadata[] | select(.Status=="Active")] | length')
if [[ "$active_keys" -gt 1 ]]; then
  echo -e "  ${YELLOW}⚠ 存在 ${active_keys} 个活跃 Access Key — 建议只保留一个${NC}"
  warnings=$((warnings + 1))
fi

# 检查：无 MFA
if [[ "$mfa_count" -eq 0 ]]; then
  echo -e "  ${YELLOW}⚠ 未启用 MFA — 高权限用户必须启用${NC}"
  warnings=$((warnings + 1))
fi

# 检查：Key 超过 90 天未轮换
echo "$keys" | jq -r '.AccessKeyMetadata[] | select(.Status=="Active") | .AccessKeyId + " " + .CreateDate' | while read -r kid cdate; do
  key_age_seconds=$(( $(date +%s) - $(date -jf "%Y-%m-%dT%H:%M:%S+00:00" "$cdate" +%s 2>/dev/null || date -d "$cdate" +%s) ))
  key_age_days=$((key_age_seconds / 86400))
  if [[ "$key_age_days" -gt 90 ]]; then
    echo -e "  ${YELLOW}⚠ Key ${kid} 已 ${key_age_days} 天未轮换 — 建议定期轮换${NC}"
  fi
done

# 检查：是否有 AdministratorAccess
if echo "$managed" | jq -r '.AttachedPolicies[].PolicyName' 2>/dev/null | grep -q "AdministratorAccess"; then
  if [[ "$mfa_count" -eq 0 ]]; then
    echo -e "  ${RED}✗ 拥有 AdministratorAccess 但未启用 MFA — 高风险${NC}"
    warnings=$((warnings + 1))
  fi
fi

# 检查 IP 限制策略
has_ip_policy=false
echo "$inline" | jq -r '.PolicyNames[]' 2>/dev/null | while read -r pname; do
  policy_doc=$(aws_cmd iam get-user-policy --user-name "$USERNAME" --policy-name "$pname" --output json)
  if echo "$policy_doc" | jq -r '.PolicyDocument' | grep -q "aws:SourceIp"; then
    echo -e "  ${GREEN}✓ 已配置 IP 限制策略: ${pname}${NC}"
    # 显示允许的 IP
    echo "$policy_doc" | jq -r '.PolicyDocument.Statement[].Condition.NotIpAddress["aws:SourceIp"][]' 2>/dev/null | while read -r ip; do
      echo "    允许 IP: $ip"
    done
    has_ip_policy=true
  fi
done

if [[ "$has_ip_policy" == false ]]; then
  echo "$inline" | jq -r '.PolicyNames[]' 2>/dev/null | grep -q "." || echo -e "  ${YELLOW}⚠ 未配置 IP 限制策略${NC}"
fi

if [[ "$warnings" -eq 0 ]]; then
  echo -e "  ${GREEN}✓ 未发现明显异常${NC}"
fi

echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
echo -e "  审计完成 — $(date '+%Y-%m-%d %H:%M:%S')"
echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
echo ""
