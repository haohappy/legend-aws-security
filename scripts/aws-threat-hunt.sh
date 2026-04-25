#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# AWS CloudTrail 威胁狩猎
#
# 在全部 AWS Region 的 CloudTrail 中搜索可疑活动。
# 支持两种搜索模式：
#   1. 按可疑 IP 搜索 — 找出某个 IP 在所有 Region 做了什么
#   2. 按高危事件搜索 — 找出谁执行了 ImportKeyPair/RunInstances 等危险操作
#
# 用法:
#   # 模式 1：搜索可疑 IP 的全部活动
#   ./scripts/aws-threat-hunt.sh --ip 216.126.225.20 --profile legend-security-hao
#
#   # 模式 1：搜索多个可疑 IP
#   ./scripts/aws-threat-hunt.sh --ip 216.126.225.20,18.144.153.92 --profile legend-security-hao
#
#   # 模式 2：搜索高危事件（默认搜索 ImportKeyPair, RunInstances, CreateUser, CreateAccessKey）
#   ./scripts/aws-threat-hunt.sh --events --profile legend-security-hao
#
#   # 模式 2：自定义事件名
#   ./scripts/aws-threat-hunt.sh --events "ImportKeyPair,RunInstances,DeleteBucket" --profile legend-security-hao
#
#   # 自定义时间范围（默认 7 天）
#   ./scripts/aws-threat-hunt.sh --ip 216.126.225.20 --days 30 --profile legend-security-hao
#
# 参数:
#   --ip <ip1,ip2,...>      按 IP 地址搜索（逗号分隔多个 IP）
#   --events [evt1,evt2]    按事件名搜索（不带参数则用默认高危事件列表）
#   --days <n>              CloudTrail 回溯天数（默认 7）
#   --profile <name>        AWS CLI profile
#   --regions <r1,r2,...>   指定 Region（默认全部 15 个商用 Region）
#   --output <file>         输出结果到文件
#   --help, -h              显示帮助
# ============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ── 默认高危事件列表 ──
# 这些事件通常出现在凭据泄露后的攻击链中
DEFAULT_EVENTS="ImportKeyPair,RunInstances,CreateUser,CreateAccessKey,AttachUserPolicy,AttachRolePolicy,CreateRole,PutUserPolicy,AuthorizeSecurityGroupIngress"

# ── 默认 Region 列表 ──
ALL_REGIONS="us-east-1,us-east-2,us-west-1,us-west-2,eu-west-1,eu-west-2,eu-west-3,eu-central-1,eu-north-1,ap-southeast-1,ap-southeast-2,ap-northeast-1,ap-northeast-2,ap-south-1,sa-east-1,ca-central-1"

# ── 参数解析 ──
PROFILE_OPT=""
SEARCH_IPS=""
SEARCH_EVENTS=""
MODE=""
DAYS=7
REGIONS="$ALL_REGIONS"
OUTPUT_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) PROFILE_OPT="--profile $2"; shift 2 ;;
    --ip) SEARCH_IPS="$2"; MODE="ip"; shift 2 ;;
    --events)
      MODE="events"
      # --events 后面可以带参数，也可以不带
      if [[ $# -gt 1 && ! "$2" =~ ^-- ]]; then
        SEARCH_EVENTS="$2"; shift 2
      else
        SEARCH_EVENTS="$DEFAULT_EVENTS"; shift
      fi
      ;;
    --days) DAYS="$2"; shift 2 ;;
    --regions) REGIONS="$2"; shift 2 ;;
    --output) OUTPUT_FILE="$2"; shift 2 ;;
    --help|-h)
      sed -n '2,/^# =====/p' "$0" | head -n -1 | sed 's/^# \?//'
      exit 0
      ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

if [[ -z "$MODE" ]]; then
  echo -e "${RED}错误：必须指定 --ip 或 --events${NC}"
  echo "用法: $0 --ip <ip> [--profile <profile>]"
  echo "      $0 --events [event1,event2] [--profile <profile>]"
  exit 1
fi

aws_cmd() {
  aws $PROFILE_OPT "$@" 2>&1
}

if [[ -n "$OUTPUT_FILE" ]]; then
  exec > >(tee >(sed 's/\x1b\[[0-9;]*m//g' > "$OUTPUT_FILE"))
fi

# ── 计算时间范围 ──
start_time=$(date -u -v-${DAYS}d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "${DAYS} days ago" +%Y-%m-%dT%H:%M:%SZ)
end_time=$(date -u +%Y-%m-%dT%H:%M:%SZ)

echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  AWS CloudTrail 威胁狩猎${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo "  模式:       $([ "$MODE" = "ip" ] && echo "按 IP 搜索" || echo "按事件搜索")"
echo "  时间范围:   $start_time → $end_time（${DAYS} 天）"

if [[ "$MODE" == "ip" ]]; then
  echo "  搜索 IP:    $SEARCH_IPS"
else
  echo "  搜索事件:   $SEARCH_EVENTS"
fi
echo ""

total_hits=0

# ── 将逗号分隔转为数组 ──
IFS=',' read -ra REGION_LIST <<< "$REGIONS"

if [[ "$MODE" == "ip" ]]; then
  # ═══════════════════════════════════════
  # 模式 1：按 IP 搜索
  # ═══════════════════════════════════════
  IFS=',' read -ra IP_LIST <<< "$SEARCH_IPS"

  for region in "${REGION_LIST[@]}"; do
    printf "\r  搜索中... %s          " "$region" >&2

    # CloudTrail lookup-events 不支持按 IP 过滤，需要拉取全部再筛选
    events=$(aws_cmd cloudtrail lookup-events \
      --region "$region" \
      --start-time "$start_time" \
      --end-time "$end_time" \
      --max-results 50 \
      --output json 2>/dev/null || echo '{"Events":[]}')

    # 用 python 过滤匹配的 IP
    hits=$(echo "$events" | python3 -c "
import json, sys
bad_ips = set('${SEARCH_IPS}'.split(','))
data = json.load(sys.stdin)
results = []
for e in data.get('Events', []):
    ct = json.loads(e.get('CloudTrailEvent', '{}'))
    ip = ct.get('sourceIPAddress', '')
    if ip in bad_ips:
        user = ct.get('userIdentity', {}).get('userName', ct.get('userIdentity', {}).get('arn', '?'))
        results.append({
            'time': e.get('EventTime', '?'),
            'event': e.get('EventName', '?'),
            'user': user,
            'ip': ip,
            'region': '$region'
        })
if results:
    for r in results:
        print(f\"  {r['time']}  {r['event']:<30s}  User: {r['user']:<40s}  IP: {r['ip']}\")
" 2>/dev/null)

    if [[ -n "$hits" ]]; then
      echo ""
      echo -e "  ${RED}=== $region ===${NC}"
      echo "$hits"
      hit_count=$(echo "$hits" | wc -l | tr -d ' ')
      total_hits=$((total_hits + hit_count))
    fi
  done

elif [[ "$MODE" == "events" ]]; then
  # ═══════════════════════════════════════
  # 模式 2：按事件名搜索
  # ═══════════════════════════════════════
  IFS=',' read -ra EVENT_LIST <<< "$SEARCH_EVENTS"

  for region in "${REGION_LIST[@]}"; do
    region_hits=""

    for event_name in "${EVENT_LIST[@]}"; do
      printf "\r  搜索中... %s / %s          " "$region" "$event_name" >&2

      events=$(aws_cmd cloudtrail lookup-events \
        --region "$region" \
        --lookup-attributes "AttributeKey=EventName,AttributeValue=$event_name" \
        --start-time "$start_time" \
        --end-time "$end_time" \
        --max-results 20 \
        --output json 2>/dev/null || echo '{"Events":[]}')

      hits=$(echo "$events" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for e in data.get('Events', []):
    ct = json.loads(e.get('CloudTrailEvent', '{}'))
    ip = ct.get('sourceIPAddress', '?')
    user = ct.get('userIdentity', {}).get('userName', ct.get('userIdentity', {}).get('arn', '?'))
    error = ct.get('errorCode', '')
    error_str = f'  ERROR: {error}' if error else ''
    print(f\"  {e.get('EventTime','?')}  {e.get('EventName','?'):<30s}  User: {user:<40s}  IP: {ip}{error_str}\")
" 2>/dev/null)

      if [[ -n "$hits" ]]; then
        region_hits="${region_hits}${hits}\n"
        hit_count=$(echo "$hits" | wc -l | tr -d ' ')
        total_hits=$((total_hits + hit_count))
      fi
    done

    if [[ -n "$region_hits" ]]; then
      echo ""
      echo -e "  ${RED}=== $region ===${NC}"
      echo -e "$region_hits"
    fi
  done
fi

printf "\r  搜索完成。                                    \n" >&2
echo ""

# ── 汇总 ──
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
if [[ "$total_hits" -eq 0 ]]; then
  echo -e "  ${GREEN}全部 ${#REGION_LIST[@]} 个 Region 扫描完毕，未发现匹配记录。${NC}"
else
  echo -e "  ${RED}共发现 ${total_hits} 条匹配记录！${NC}"
  echo ""
  echo -e "  建议后续操作："
  echo "    1. 确认相关 IP 是否属于本组织"
  echo "    2. 禁用受影响用户的 Access Key"
  echo "    3. 检查是否有残留资源（EC2 实例、Key Pair 等）"
  echo "    4. 使用 aws-user-audit.sh 对受影响用户做深度审计"
fi
echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
echo ""
