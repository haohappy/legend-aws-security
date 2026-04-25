# AWS 安全审计工具使用指南

本项目提供一组 Bash 脚本，用于 AWS IAM 安全审计和加固。以下是各脚本的用途、参数说明和推荐工作流。

## 前置条件

- AWS CLI v2 已安装并配置
- 审计用 IAM 用户需具备 `IAMReadOnlyAccess` + `CloudTrailReadOnlyAccess` 权限
- 加固操作（部署策略、禁用 Key）需具备 `IAMFullAccess` 权限
- 依赖工具：`jq`、`python3`

## 脚本一览

| 脚本 | 用途 | 类型 |
|------|------|------|
| `aws-user-audit.sh` | 单用户深度审计 | 审计 |
| `aws-account-audit.sh` | 全账户批量扫描 | 审计 |
| `aws-threat-hunt.sh` | CloudTrail 威胁狩猎 | 审计 |
| `aws-zombie-keys.sh` | 僵尸 Key 检测与清理 | 加固 |
| `aws-deploy-ip-policy.sh` | IP 限制策略批量部署 | 加固 |

---

## 1. aws-user-audit.sh — 单用户深度审计

**场景**：收到 AWS 异常通知、怀疑某个用户的 Key 泄露时，对单个用户做深度审计。

```bash
# 基本用法
./scripts/aws-user-audit.sh lending_ses_prod --profile legend-security-hao

# 查看最近 30 天的 CloudTrail 记录
./scripts/aws-user-audit.sh lending_ses_prod --profile legend-security-hao --days 30
```

**输出内容**：
- 用户基本信息（ARN、创建时间、Console 最后登录）
- Access Key 状态（每个 Key 的最后使用时间/服务/区域）
- 权限策略（托管策略、内联策略、所属组）
- MFA 状态
- CloudTrail 近期 API 调用（按 IP 和 API 统计）
- 异常检测（多活跃 Key、无 MFA、未轮换、无 IP 限制）

**判断泄露的关键指标**：
- CloudTrail 中出现不认识的来源 IP
- Key 最后使用的服务/区域与预期不符（如 SES 用户调了 EC2）
- CloudTrail 中出现 `ImportKeyPair`、`RunInstances`、`CreateUser` 等敏感操作

---

## 2. aws-account-audit.sh — 全账户批量扫描

**场景**：定期安全审计、安全事件后全面排查、新接手 AWS 账户时的初始评估。

```bash
# 基本用法（扫描全部用户）
./scripts/aws-account-audit.sh --profile legend-security-hao

# 自定义阈值
./scripts/aws-account-audit.sh \
  --profile legend-security-hao \
  --zombie-days 90 \
  --rotation-days 60

# 结果保存到文件
./scripts/aws-account-audit.sh \
  --profile legend-security-hao \
  --output audit-$(date +%Y%m%d).txt
```

**输出内容**：
1. 账户概览 — 用户总数、Key 总数、MFA 覆盖率、IP 限制覆盖率
2. 高危用户 — 有 Active Key 但无 MFA 且无 IP 限制
3. 僵尸 Key — Active 但长期未使用（默认 180 天）
4. 未轮换 Key — Active 且超期未轮换（默认 90 天）
5. 服务异常 — Key 使用的服务与用户名推断的用途不匹配
6. Console 风险 — 有 Console 登录权限但无 MFA

**注意**：扫描 60+ 用户约需 5-10 分钟（受 AWS API 速率限制）。

---

## 3. aws-threat-hunt.sh — CloudTrail 威胁狩猎

**场景**：发现泄露后追踪攻击者在所有 Region 的活动、主动搜索高危事件。

### 模式 1：按可疑 IP 搜索

```bash
# 搜索单个 IP
./scripts/aws-threat-hunt.sh \
  --ip 216.126.225.20 \
  --profile legend-security-hao

# 搜索多个 IP
./scripts/aws-threat-hunt.sh \
  --ip 216.126.225.20,18.144.153.92,103.137.247.47 \
  --profile legend-security-hao

# 扩大时间范围到 30 天
./scripts/aws-threat-hunt.sh \
  --ip 216.126.225.20 \
  --days 30 \
  --profile legend-security-hao
```

### 模式 2：按高危事件搜索

```bash
# 搜索默认高危事件列表
# （ImportKeyPair, RunInstances, CreateUser, CreateAccessKey 等 9 个事件）
./scripts/aws-threat-hunt.sh \
  --events \
  --profile legend-security-hao

# 自定义事件列表
./scripts/aws-threat-hunt.sh \
  --events "ImportKeyPair,RunInstances,DeleteBucket" \
  --profile legend-security-hao

# 只扫描特定 Region
./scripts/aws-threat-hunt.sh \
  --events \
  --regions "us-west-2,us-east-1" \
  --profile legend-security-hao
```

**默认搜索的高危事件**：
- `ImportKeyPair` — 导入 SSH 密钥对（启动挖矿机前奏）
- `RunInstances` — 启动 EC2 实例
- `CreateUser` — 创建 IAM 用户（持久化后门）
- `CreateAccessKey` — 创建 Access Key（持久化后门）
- `AttachUserPolicy` / `AttachRolePolicy` — 提权
- `CreateRole` — 创建角色（横向移动）
- `PutUserPolicy` — 附加策略（提权）
- `AuthorizeSecurityGroupIngress` — 开放安全组端口

---

## 4. aws-zombie-keys.sh — 僵尸 Key 检测与清理

**场景**：清理长期不用但仍 Active 的 Key，缩小攻击面。

```bash
# dry-run：查看哪些是僵尸 Key（默认 180 天未使用）
./scripts/aws-zombie-keys.sh --profile legend-security-hao

# 降低阈值到 90 天
./scripts/aws-zombie-keys.sh --days 90 --profile legend-security-hao

# 实际禁用（逐个确认）
./scripts/aws-zombie-keys.sh --execute --profile legend-security-hao

# 实际禁用（跳过确认）
./scripts/aws-zombie-keys.sh --execute --yes --profile legend-security-hao

# 排除特定用户
./scripts/aws-zombie-keys.sh \
  --exclude "monitor,netops_tao" \
  --execute \
  --profile legend-security-hao
```

**安全设计**：
- 默认 **dry-run** 模式，不修改任何资源
- `--execute` 模式默认逐个确认，`--yes` 跳过确认
- 只做 **禁用**（Inactive），不删除，方便回滚
- 如果误禁用，可用 `aws iam update-access-key --status Active` 恢复

---

## 5. aws-deploy-ip-policy.sh — IP 限制策略批量部署

**场景**：批量为 IAM 用户加上 IP 白名单限制，作为 MFA 之外的安全补偿控制。

```bash
# dry-run：查看哪些用户会被部署
./scripts/aws-deploy-ip-policy.sh \
  --ips "124.195.223.66/32,150.228.211.208/32" \
  --profile legend-security-hao

# 实际部署到全账户（跳过已有策略的用户）
./scripts/aws-deploy-ip-policy.sh \
  --ips "124.195.223.66/32,150.228.211.208/32" \
  --execute \
  --profile legend-security-hao

# 只部署到指定用户
./scripts/aws-deploy-ip-policy.sh \
  --ips "124.195.223.66/32" \
  --users "lending_ses_prod,flashwire-prod" \
  --execute \
  --profile legend-security-hao

# 排除特定用户
./scripts/aws-deploy-ip-policy.sh \
  --ips "124.195.223.66/32" \
  --exclude "AmazonSSM_Claude_Code_Hao" \
  --execute \
  --profile legend-security-hao

# 覆盖已有策略（谨慎使用）
./scripts/aws-deploy-ip-policy.sh \
  --ips "124.195.223.66/32,NEW_IP/32" \
  --force \
  --execute \
  --profile legend-security-hao
```

**重要提醒**：
- 部署前确认白名单 IP 包含所有合法的服务器 IP（CI/CD、生产服务器等）
- 建议先在 1-2 个非关键用户上测试，确认不影响业务
- 如果管理员 IP 变化，可通过 YubiKey MFA 恢复访问（参考 `docs/yubikey-mfa-guide.md`）

---

## 推荐工作流

### 日常巡检（建议每周执行）

```bash
# 1. 全账户扫描
./scripts/aws-account-audit.sh --profile legend-security-hao --output audit-$(date +%Y%m%d).txt

# 2. 搜索高危事件
./scripts/aws-threat-hunt.sh --events --profile legend-security-hao
```

### 安全事件响应

```bash
# 1. 对可疑用户深度审计
./scripts/aws-user-audit.sh <username> --profile legend-security-hao --days 30

# 2. 用攻击者 IP 全 Region 搜索
./scripts/aws-threat-hunt.sh --ip <attacker_ip> --profile legend-security-hao --days 30

# 3. 搜索高危事件确认影响范围
./scripts/aws-threat-hunt.sh --events --days 30 --profile legend-security-hao

# 4. 禁用泄露的 Key
aws iam update-access-key --user-name <user> --access-key-id <key> --status Inactive --profile legend-security-hao
```

### 初始安全加固

```bash
# 1. 全账户扫描，了解现状
./scripts/aws-account-audit.sh --profile legend-security-hao --output baseline.txt

# 2. 清理僵尸 Key
./scripts/aws-zombie-keys.sh --execute --profile legend-security-hao

# 3. 部署 IP 限制策略
./scripts/aws-deploy-ip-policy.sh \
  --ips "YOUR_IP/32" \
  --execute \
  --profile legend-security-hao

# 4. 再次扫描，确认改善
./scripts/aws-account-audit.sh --profile legend-security-hao --output after-hardening.txt
```
