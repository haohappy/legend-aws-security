# AWS 安全加固计划

## Context

2026-04-25 对 AWS 账号 647828570435 完成了架构盘点，发现 15 项安全风险（2 严重 + 4 高危 + 7 中危 + 2 低危）。最紧急的问题是 8 个公网 NLB 暴露 MySQL 端口和 96 条 0.0.0.0/0 安全组规则。本计划按优先级分 4 个阶段执行。

**约束**：所有操作需在维护窗口执行，先在非生产环境验证，避免影响业务连续性。

---

## P0 — 立即执行（24 小时内）

### 1.1 关闭公网数据库暴露

**问题**：8 个 internet-facing NLB 将 MySQL 3306 端口直接暴露到公网。

| NLB | Region | 操作 |
|-----|--------|------|
| lg-rds-mysql | us-east-1 | 改为 internal 或删除 |
| flashwire-staging-mysql | us-east-1 | 改为 internal 或删除 |
| test-mariadb-zingpays-conn | us-east-1 | 删除（test 前缀，确认后删除） |
| test-flashwire-staging-db | us-east-1 | 删除（test 前缀，确认后删除） |
| replica-lg-rds-production | ap-southeast-1 | 改为 internal 或删除 |
| lending-apiweb-mysql | ap-southeast-1 | 改为 internal 或删除 |
| staging-lending-apiweb-mysql | ap-southeast-1 | 改为 internal 或删除 |
| replica-flashwire-staging-mysql | ap-southeast-1 | 改为 internal 或删除 |

**替代方案**：如需远程访问数据库，使用：
- SSM Session Manager 端口转发：`aws ssm start-session --target <instance-id> --document-name AWS-StartPortForwardingSessionToRemoteHost --parameters host=<rds-endpoint>,portNumber=3306,localPortNumber=3306`
- 或通过 VPN Hub (vpn-sg-vpc) 访问

**验证**：`aws elbv2 describe-load-balancers` 确认无 internet-facing NLB 暴露 3306 端口。

### 1.2 收紧高危安全组

**立即处理（数据库和管理端口）**：

| 安全组 | Region | 当前开放 | 操作 |
|--------|--------|---------|------|
| HomeDevelopment | us-east-1 | SSH(22), MySQL(3306), Redis(6379) → 0.0.0.0/0 | 限制为 VPN/办公 IP 或删除规则 |
| ZING_Dev | us-east-1 | SSH(22), MySQL(3306) → 0.0.0.0/0 | 限制为 VPN/办公 IP |
| Red Cherry Server | us-east-1 | MySQL(3306) → 0.0.0.0/0 | 限制为内部 CIDR |
| d-9067972a2b_controllers | us-east-1 | 13 AD/LDAP 端口 → 0.0.0.0/0 | 限制为内部 CIDR 10.0.0.0/8 |
| payment-dev-needs | ap-southeast-1 | SSH(22), MySQL(3306), 3000, 3001 → 0.0.0.0/0 | 限制为 VPN/办公 IP |
| windows-remote-desktop | ap-southeast-1 | RDP(3389) → 0.0.0.0/0 | 限制为 VPN IP 或改用 SSM |

**原则**：
- SSH/RDP → 仅限 VPN CIDR (10.101.0.0/24) 或指定办公 IP
- MySQL/Redis/AD → 仅限内部 VPC CIDR (10.0.0.0/8)
- HTTP/HTTPS → 仅在面向用户的 LB 上保留 0.0.0.0/0

**验证**：`aws ec2 describe-security-groups --filters "Name=ip-permission.cidr,Values=0.0.0.0/0"` 确认敏感端口已收紧。

---

## P1 — 本周内完成

### 2.1 IAM MFA 强制启用

**现状**：67 用户，仅 2 个有 MFA（3%），55 个有活跃 Access Key。

**步骤**：
1. 创建 IAM Policy `ForceMFA`，拒绝无 MFA 的操作（除 MFA 自配置外）
2. 附加到所有 IAM 用户组
3. 通知所有用户在 48 小时内配置 MFA
4. 审计 55 个活跃 Access Key：
   - 删除 90 天未使用的 Key
   - 轮换超过 180 天的 Key
5. 长期：迁移到 IAM Identity Center (SSO)

**验证**：`aws iam generate-credential-report` → 确认 MFA 覆盖率 >95%。

### 2.2 启用 GuardDuty（全部 5 个活跃 Region）

**操作**（每个 region）：
```
aws guardduty create-detector --enable --finding-publishing-frequency FIFTEEN_MINUTES \
  --region <region> --profile legend-security-hao
```

**Regions**：us-east-1, eu-west-1, ap-southeast-1, ap-northeast-1, eu-west-3

**配置**：
- 启用 S3 Protection
- 启用 EKS Audit Log Monitoring（us-east-1 有 EKS）
- 启用 Malware Protection
- 配置 SNS 通知 HIGH/CRITICAL findings

**验证**：`aws guardduty list-detectors --region <region>` 确认每个 region 有 detector。

### 2.3 启用 Security Hub

**操作**（每个 region）：
```
aws securityhub enable-security-hub \
  --enable-default-standards \
  --region <region> --profile legend-security-hao
```

**启用标准**：
- AWS Foundational Security Best Practices v1.0.0
- CIS AWS Foundations Benchmark v1.4.0

**验证**：`aws securityhub describe-hub --region <region>`。

### 2.4 EC2 绑定 IAM Instance Profile（ap-southeast-1）

**受影响实例**（10 台，全部无 IAM Role）：

| 实例 | 建议 Role |
|------|----------|
| lending-web01 / lending-web02 / lending-staging01 | lending-ec2-role（SSM + CloudWatch + S3 读取） |
| cobo-mpc01/02/testing01 | mpc-ec2-role（SSM + KMS + 最小权限） |
| is-1token-app / is-1token-auth | internal-sys-ec2-role |
| payment-dev-windows / payment-dev01 | payment-dev-ec2-role |

**步骤**：
1. 为每类实例创建最小权限 IAM Role
2. 所有 Role 都包含 SSM managed policy（`AmazonSSMManagedInstanceCore`）
3. 关联 Instance Profile 并绑定
4. 排查并删除实例上硬编码的 Access Key

**验证**：`aws ec2 describe-instances --query 'Reservations[].Instances[].IamInstanceProfile' --region ap-southeast-1`。

---

## P2 — 两周内完成

### 3.1 续期过期 ACM 证书

- **证书**：`*.zingpays.com`（ap-southeast-1）
- **过期日期**：2026-02-02（已过期 82 天）
- **操作**：申请新证书或续期，替换绑定资源

### 3.2 统一启用 CloudTrail 日志验证

- **问题**：`management-events` trail 未启用 LogFileValidation
- **操作**：`aws cloudtrail update-trail --name management-events --enable-log-file-validation`

### 3.3 启用 AWS Config

**操作**（每个活跃 region）：
1. 创建 Config Recorder + S3 Delivery Channel
2. 部署托管规则：
   - `restricted-ssh`（检测 SSH 0.0.0.0/0）
   - `rds-instance-public-access-check`
   - `iam-user-mfa-enabled`
   - `encrypted-volumes`
   - `s3-bucket-public-read-prohibited`
   - `guardduty-enabled-centralized`

### 3.4 部署 WAF

**优先保护对象**：
1. CloudFront 分发（10 个）→ 全局 WAF
2. us-east-1 internet-facing ALB → Regional WAF
3. ap-southeast-1 internet-facing ALB → Regional WAF

**规则集**：
- AWS Managed Rules: Core Rule Set, Known Bad Inputs, SQL Database
- Rate limiting: 2000 req/5min per IP

### 3.5 清理未使用资源

| 资源 | Region | 操作 |
|------|--------|------|
| lg-va-test-deletion-20251216 | us-east-1 | 确认后删除 RDS |
| lg-ie-test-deletion-20251216 | eu-west-1 | 确认后删除 RDS |
| 11 stopped EC2 | us-east-1 | 逐一评估，删除不需要的 |
| 8 stopped EC2 | ap-southeast-1 | 逐一评估，删除不需要的 |
| 9 expired ACM certs | ap-southeast-1 | 删除过期证书 |

### 3.6 收紧 S3 VPC Endpoint Policy（eu-west-3）

- **当前**：`Allow */*`（完全开放）
- **改为**：仅允许访问本账号的特定 bucket

### 3.7 审计剩余 0.0.0.0/0 安全组规则

- 处理 P0 遗留的其他规则（us-east-1 共 96 条）
- 仅保留面向用户的 HTTP/HTTPS 0.0.0.0/0
- 所有管理端口（SSH/RDP/DB）限制为内部网段

---

## P3 — 按计划排期（30 天内）

### 4.1 确认跨 Region VPN/Peering 路由

- 验证 vpn-sg-vpc 到 us-east-1 三个 VPC 的 peering 路由表完整性
- 确认流量走 AWS 骨干网而非公网

### 4.2 检查 S3 Bucket 安全配置

- 排查 4 个 AccessDenied 的 bucket 的加密和公开访问状态
- 对所有 52 个 bucket 确认 Block Public Access 已启用

### 4.3 评估 ECS EXTERNAL Launch Type

- ap-southeast-1 的 17 个 ECS tasks 使用 EXTERNAL launch type
- 评估迁移到 Fargate 的可行性
- 若保留 EXTERNAL，确保外部计算资源的安全配置

### 4.4 建立持续安全监控

- 配置 GuardDuty findings → SNS → Slack/Email 告警
- Security Hub 每周自动报告
- Config 不合规项自动通知
- 每月 IAM credential report 审计

---

## 验证 Checklist

完成全部加固后，重新运行以下检查：

```bash
# 1. 无公网暴露数据库端口
aws elbv2 describe-load-balancers --query 'LoadBalancers[?Scheme==`internet-facing`]' | grep -c "3306"
# 期望：0

# 2. 敏感端口无 0.0.0.0/0 规则
aws ec2 describe-security-groups --filters "Name=ip-permission.cidr,Values=0.0.0.0/0" \
  --query 'SecurityGroups[].IpPermissions[?FromPort==`22` || FromPort==`3306` || FromPort==`6379` || FromPort==`3389`]'
# 期望：空

# 3. MFA 覆盖率
aws iam generate-credential-report && aws iam get-credential-report --query 'Content' --output text | base64 -d | grep -c "false.*false"
# 期望：0（无 MFA=false 且 active 的用户）

# 4. GuardDuty 全部启用
for r in us-east-1 eu-west-1 ap-southeast-1 ap-northeast-1 eu-west-3; do
  echo "$r: $(aws guardduty list-detectors --region $r --query 'DetectorIds' --output text)"
done
# 期望：每个 region 有 detector ID

# 5. 重新运行完整安全扫描
# 使用相同的 legend-security-hao profile 重新执行架构盘点
# 对比 risks.md 确认所有 P0/P1 项已关闭
```

---

## 时间线总结

| 阶段 | 时限 | 项目数 | 关键动作 |
|------|------|--------|---------|
| P0 | 24h | 2 | 关闭公网 NLB + 收紧高危 SG |
| P1 | 7 天 | 4 | MFA + GuardDuty + SecurityHub + IAM Role |
| P2 | 14 天 | 7 | ACM + CloudTrail + Config + WAF + 清理 + S3 endpoint + SG 审计 |
| P3 | 30 天 | 4 | VPN 路由 + S3 审计 + ECS 评估 + 持续监控 |
