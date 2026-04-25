#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# AWS IAM IP 限制策略批量部署
#
# 批量为 IAM 用户附加 DenyWithoutIPorMFA 策略，限制 API 调用必须来自
# 白名单 IP 或通过 MFA 认证。
#
# 策略逻辑（"二选一"）：
#   - 请求来自白名单 IP → 放行
#   - 请求带有 MFA 认证 → 放行
#   - 两者都不满足 → Deny 全部操作（除 sts:GetSessionToken）
#
# 用法:
#   # dry-run：查看哪些用户会被部署策略
#   ./scripts/aws-deploy-ip-policy.sh \
#     --ips "124.195.223.66/32,150.228.211.208/32" \
#     --profile legend-security-hao
#
#   # 实际部署
#   ./scripts/aws-deploy-ip-policy.sh \
#     --ips "124.195.223.66/32,150.228.211.208/32" \
#     --execute \
#     --profile legend-security-hao
#
#   # 排除特定用户（如服务器上运行的程序需要额外 IP）
#   ./scripts/aws-deploy-ip-policy.sh \
#     --ips "124.195.223.66/32" \
#     --exclude "flashwire-prod,monitor" \
#     --execute \
#     --profile legend-security-hao
#
#   # 只对指定用户部署（而非全账户）
#   ./scripts/aws-deploy-ip-policy.sh \
#     --ips "124.195.223.66/32" \
#     --users "lending_ses_prod,flashwire-prod" \
#     --execute \
#     --profile legend-security-hao
#
# 参数:
#   --ips <ip1,ip2,...>     白名单 IP 列表，CIDR 格式（必填）
#   --profile <name>       AWS CLI profile
#   --execute              实际执行部署（不加此参数为 dry-run 模式）
#   --exclude <u1,u2>      排除的用户名列表（逗号分隔）
#   --users <u1,u2>        只对指定用户部署（不指定则全账户）
#   --policy-name <name>   策略名称（默认 DenyWithoutIPorMFA）
#   --skip-existing        跳过已有同名策略的用户（默认行为）
#   --force                覆盖已有的同名策略
#   --help, -h             显示帮助
#
# 安全设计:
#   - 默认 dry-run，不修改任何资源
#   - 默认跳过已有同名策略的用户，防止覆盖手动定制的策略
#   - 策略中保留 sts:GetSessionToken 的 Allow，确保 IP 变更后可通过 MFA 恢复访问
#   - 策略中排除 aws:ViaAWSService 调用，防止影响 AWS 服务间内部通信
# ============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PROFILE_OPT=""
ALLOWED_IPS=""
EXECUTE=false
EXCLUDE_LIST=""
USER_LIST=""
POLICY_NAME="DenyWithoutIPorMFA"
FORCE=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) PROFILE_OPT="--profile $2"; shift 2 ;;
    --ips) ALLOWED_IPS="$2"; shift 2 ;;
    --execute) EXECUTE=true; shift ;;
    --exclude) EXCLUDE_LIST="$2"; shift 2 ;;
    --users) USER_LIST="$2"; shift 2 ;;
    --policy-name) POLICY_NAME="$2"; shift 2 ;;
    --force) FORCE=true; shift ;;
    --skip-existing) shift ;; # 默认行为，兼容参数
    --help|-h)
      sed -n '2,/^# =====/p' "$0" | head -n -1 | sed 's/^# \?//'
      exit 0
      ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

if [[ -z "$ALLOWED_IPS" ]]; then
  echo -e "${RED}错误：必须指定 --ips 参数${NC}"
  echo "用法: $0 --ips \"124.195.223.66/32,150.228.211.208/32\" [--execute] [--profile <profile>]"
  exit 1
fi

aws_cmd() {
  aws $PROFILE_OPT "$@" 2>&1
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

# ── 构建 IP 列表的 JSON 数组 ──
build_ip_json() {
  local ips="$1"
  local result="["
  local first=true
  IFS=',' read -ra ip_arr <<< "$ips"
  for ip in "${ip_arr[@]}"; do
    if [[ "$first" == true ]]; then
      first=false
    else
      result="${result},"
    fi
    result="${result}\"${ip}\""
  done
  result="${result}]"
  echo "$result"
}

IP_JSON=$(build_ip_json "$ALLOWED_IPS")

# ── 构建策略文档 ──
POLICY_DOC=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowGetSessionTokenAnywhere",
      "Effect": "Allow",
      "Action": "sts:GetSessionToken",
      "Resource": "*"
    },
    {
      "Sid": "DenyUnlessWhitelistedIPorMFA",
      "Effect": "Deny",
      "NotAction": "sts:GetSessionToken",
      "Resource": "*",
      "Condition": {
        "NotIpAddress": {
          "aws:SourceIp": ${IP_JSON}
        },
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        },
        "Bool": {
          "aws:ViaAWSService": "false"
        }
      }
    }
  ]
}
EOF
)

echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  AWS IAM IP 限制策略批量部署${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo ""

if [[ "$EXECUTE" == true ]]; then
  echo -e "  模式:     ${RED}EXECUTE — 将实际部署策略${NC}"
else
  echo -e "  模式:     ${GREEN}DRY-RUN — 仅报告，不修改${NC}"
fi
echo "  策略名:   $POLICY_NAME"
echo "  白名单 IP: $ALLOWED_IPS"
echo ""

# ── 获取目标用户列表 ──
if [[ -n "$USER_LIST" ]]; then
  IFS=',' read -ra target_users <<< "$USER_LIST"
else
  target_users=($(aws_cmd iam list-users --query 'Users[].UserName' --output text))
fi

will_deploy=()
will_skip_existing=()
will_skip_excluded=()

for user in "${target_users[@]}"; do
  # 检查排除列表
  if is_excluded "$user"; then
    will_skip_excluded+=("$user")
    continue
  fi

  # 检查是否已有同名策略
  existing=$(aws_cmd iam list-user-policies --user-name "$user" --query 'PolicyNames[]' --output text)
  if echo "$existing" | grep -q "$POLICY_NAME"; then
    if [[ "$FORCE" == false ]]; then
      will_skip_existing+=("$user")
      continue
    fi
  fi

  will_deploy+=("$user")
done

echo "  目标用户:   ${#target_users[@]}"
echo "  将部署:     ${#will_deploy[@]}"
echo "  跳过(已有): ${#will_skip_existing[@]}"
echo "  跳过(排除): ${#will_skip_excluded[@]}"
echo ""

if [[ ${#will_deploy[@]} -eq 0 ]]; then
  echo -e "  ${GREEN}没有需要部署的用户${NC}"
  echo ""
  exit 0
fi

# ── 列出将部署的用户 ──
echo -e "${BOLD}  将部署策略的用户：${NC}"
for user in "${will_deploy[@]}"; do
  echo "    $user"
done
echo ""

# ── 执行部署 ──
if [[ "$EXECUTE" == true ]]; then
  echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}  开始部署...${NC}"
  echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
  echo ""

  deployed=0
  failed=0

  for user in "${will_deploy[@]}"; do
    printf "  部署到 %s ... " "$user"

    result=$(aws_cmd iam put-user-policy \
      --user-name "$user" \
      --policy-name "$POLICY_NAME" \
      --policy-document "$POLICY_DOC" 2>&1)

    if [[ $? -eq 0 ]]; then
      echo -e "${GREEN}成功${NC}"
      deployed=$((deployed + 1))
    else
      echo -e "${RED}失败${NC}: $result"
      failed=$((failed + 1))
    fi
  done

  echo ""
  echo "  部署成功: $deployed，失败: $failed"
else
  echo -e "  ${CYAN}以上为 dry-run 结果。加 --execute 参数实际部署。${NC}"
fi

echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo -e "  完成 — $(date '+%Y-%m-%d %H:%M:%S')"
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo ""
