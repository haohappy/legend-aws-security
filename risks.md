# AWS 风险点与建议

Account: 647828570435 | Scan Date: 2026-04-25

---

## 严重 (Critical)

### 1. 数据库端口公网暴露

**us-east-1** 和 **ap-southeast-1** 均存在 internet-facing NLB 直接暴露 MySQL/MariaDB 端口（3306）到公网。

| Region | NLB 名称 | 后端目标 | 端口 |
|--------|---------|---------|------|
| us-east-1 | lg-rds-mysql | RDS lg-rds-production | 3306 |
| us-east-1 | flashwire-staging-mysql | RDS flashwire-staging-env | 3306 |
| us-east-1 | test-mariadb-zingpays-conn | RDS mariadb-zingpays | 3306 |
| us-east-1 | test-flashwire-staging-db | RDS flashwire-staging | 3306 |
| ap-southeast-1 | replica-lg-rds-production | RDS replication-lg-rds-production | 3306 |
| ap-southeast-1 | lending-apiweb-mysql | RDS lending-web-production | 3306 |
| ap-southeast-1 | staging-lending-apiweb-mysql | EC2 lending-staging01 | 3306 |
| ap-southeast-1 | replica-flashwire-staging-mysql | EC2 lending-staging01 | 3307 |

**风险**: 数据库可被互联网任意扫描和暴力攻击，可能导致数据泄露。
**建议**: 立即改为 internal NLB 或通过 VPN/堡垒机访问。如需远程访问，使用 SSM Session Manager 或 SSH 隧道。

---

### 2. 安全组过度开放 (0.0.0.0/0)

**us-east-1 有 96 条 0.0.0.0/0 入站规则**，包括敏感端口：

| 安全组 | 开放端口 | 风险级别 |
|--------|---------|---------|
| HomeDevelopment | SSH(22), MySQL(3306), Redis(6379) | 严重 |
| ZING_Dev | SSH(22), MySQL(3306), HTTP/S | 严重 |
| Red Cherry Server | MySQL(3306) | 严重 |
| d-9067972a2b_controllers | 13个 AD/LDAP 端口 | 严重 |
| payment-dev-needs (ap-southeast-1) | SSH(22), MySQL(3306), HTTP/S, 3000, 3001 | 严重 |
| windows-remote-desktop (ap-southeast-1) | RDP(3389) | 严重 |

**建议**: 
- 将 SSH/RDP 访问限制为特定 IP 或通过 SSM Session Manager
- 数据库端口（3306, 6379）不应对公网开放
- AD/LDAP 端口不应对公网开放
- 立即审查并收紧所有 0.0.0.0/0 规则

---

## 高危 (High)

### 3. IAM 用户 MFA 覆盖率极低

67 个 IAM 用户中**仅 2 个启用了 MFA**（3% 覆盖率），55 个用户拥有活跃的 Access Key。

**风险**: Access Key 泄露后无二次验证，攻击者可直接使用。
**建议**: 
- 对所有有控制台访问权限的用户强制 MFA
- 清理不再使用的 Access Key
- 考虑迁移到 IAM Identity Center (SSO)

### 4. GuardDuty 未启用

所有 5 个活跃 region 均未启用 GuardDuty 威胁检测。

**风险**: 无法检测异常 API 调用、恶意 IP 访问、加密货币挖矿等威胁。
**建议**: 在所有活跃 region 启用 GuardDuty，启用成本较低但检测价值很高。

### 5. Security Hub 未启用/不可访问

us-east-1 和 eu-west-1 均返回 InvalidAccessException。

**建议**: 启用 Security Hub 并开启 AWS Foundational Security Best Practices 标准。

### 6. EC2 实例无 IAM Instance Profile (ap-southeast-1)

ap-southeast-1 的全部 10 个 EC2 实例均未绑定 IAM Instance Profile。

**风险**: 实例可能在使用硬编码的 Access Key 而非 IAM Role。
**建议**: 为每个实例创建最小权限的 IAM Role 并绑定。

---

## 中危 (Medium)

### 7. ACM 证书过期仍在使用

ap-southeast-1 的 `*.zingpays.com` 证书已于 2026-02-02 过期，但 InUse 标记仍为 true。

**建议**: 检查并续期该证书，或替换为新证书。

### 8. 资源未及时清理

- `lg-va-test-deletion-20251216` (us-east-1) 和 `lg-ie-test-deletion-20251216` (eu-west-1) 标记为待删除已超过 4 个月
- 多个 stopped EC2 实例（ap-southeast-1 有 8 个）
- us-east-1 有 11 个 stopped 实例

**建议**: 审查并删除不再需要的资源，减少攻击面和成本。

### 9. CloudTrail 日志验证未统一启用

`management-events` trail 的日志文件验证（LogFileValidation）未启用，而 `data-events` trail 已启用。

**建议**: 对所有 trail 启用日志文件验证，确保日志完整性。

### 10. 无 AWS Config 规则

各 region 均未配置 Config Recorders 或 Config Rules。

**建议**: 启用 AWS Config 并配置合规性规则，持续监控资源配置变更。

### 11. ECS EXTERNAL Launch Type (ap-southeast-1)

ap-southeast-1 的 ECS 服务全部使用 EXTERNAL launch type，表示任务运行在 AWS 外部基础设施上。

**风险**: AWS 无法管理这些计算资源的安全性。
**建议**: 评估是否可以迁移到 Fargate 或 EC2 launch type。

### 12. S3 VPC Endpoint 策略过于宽松 (eu-west-3)

eu-west-3 的 S3 Gateway VPC Endpoint 策略为 `Allow */*`，未限制可访问的 bucket。

**建议**: 收紧 VPC Endpoint 策略，仅允许访问必要的 bucket。

### 13. 无 WAF 保护

CloudFront 级别无 WAF Web ACL。us-east-1 有 1 个 regional WAF ACL，其余 region 均无。

**建议**: 为面向公网的 ALB 和 CloudFront 配置 WAF 规则。

---

## 低危 (Low)

### 14. 跨 Region 流量走公网

eu-west-3 到 us-east-1 和 eu-west-1 的 VPC Peering 已建立（走 AWS 骨干网，安全）。
但 ap-southeast-1 的 VPN Hub (vpn-sg-vpc) 到 us-east-1 的 3 个 VPC 的 peering 连接需确认是否全部正常路由。

### 15. 多个 S3 bucket 无法检查加密状态

4 个 S3 bucket 返回 AccessDenied，无法确认加密和公开访问状态。

**建议**: 确认这 4 个 bucket 的安全配置。
