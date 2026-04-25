# AWS 安全审计报告

| 项目 | 内容 |
|------|------|
| **报告标题** | Legend AWS 账户 IAM 安全审计报告 |
| **审计范围** | AWS 账户 `647828570435`，全部 15 个商用 Region，IAM 服务 |
| **覆盖服务** | IAM、STS、EC2、CloudTrail |
| **审计日期** | 2026-04-25 |
| **审计人** | Legend Security Team |
| **报告版本** | v1.0 |
| **机密等级** | **CONFIDENTIAL — 仅限内部技术团队与管理层** |

---

## 2. 执行摘要（Executive Summary）

### 审计范围与目标

对 AWS 账户 `647828570435` 下全部 62 个 IAM 用户进行凭据安全审计，重点检查 Access Key 泄露、MFA 启用率、IP 访问限制、密钥轮换合规性。

### 整体安全态势评分

**2.5 / 10（高危）**

| 严重程度 | 发现数量 |
|----------|----------|
| Critical | 1 |
| High | 3 |
| Medium | 2 |
| Low | 1 |
| **合计** | **7** |

### Top 5 关键风险

| # | 风险 | 业务影响 |
|---|------|----------|
| 1 | 3 个 IAM 用户 Access Key 已被外部攻击者利用 | 攻击者可启动 EC2 挖矿、窃取数据、横向移动 |
| 2 | 97% 的 IAM 用户未启用 MFA | 凭据泄露后无第二道防线，攻击者可直接使用 |
| 3 | 98% 的 IAM 用户无 IP 访问限制 | 全球任意 IP 均可使用泄露的凭据调用 AWS API |
| 4 | 40+ 个 Active Key 超过 90 天未轮换，最长达 2185 天 | 长期凭据暴露窗口极大，泄露概率随时间线性增长 |
| 5 | 17+ 个 Active Key 已超 180 天未使用（僵尸凭据） | 无业务用途但持续暴露攻击面 |

### 30 天优先行动项

1. **立即**：禁用已确认泄露的 `flashwire-prod` 和 `legend_sqs_development` 的 Active Key
2. **7 天内**：禁用全部 17 个僵尸 Key（Active 但超过 180 天未使用）
3. **14 天内**：对全部 IAM 用户部署 `DenyWithoutIPorMFA` IP 限制策略
4. **30 天内**：建立 90 天 Key 自动轮换机制，清理不再需要的用户账户

---

## 3. 审计方法与依据

### 参考标准

- CIS AWS Foundations Benchmark v3.0
- AWS Well-Architected Framework — Security Pillar
- NIST SP 800-53 Rev.5（AC、IA 控制族）
- ISO 27001:2022（A.9 Access Control）

### 审计工具与覆盖范围

| 工具 | 用途 |
|------|------|
| AWS CLI (`iam`, `sts`, `cloudtrail`) | IAM 用户枚举、Key 状态查询、CloudTrail 事件检索 |
| `aws-user-audit.sh`（自研脚本） | 单用户深度审计（Key 状态、最后使用、MFA、权限、异常检测） |
| 批量扫描脚本 | 全账户 62 用户并行审计 |
| CloudTrail `lookup-events` | 全 15 Region 攻击者活动追踪、`ImportKeyPair` 事件搜索 |

### 审计时间窗口与数据采集

- **IAM 数据**：实时查询（2026-04-25）
- **CloudTrail 数据**：2026-04-17 至 2026-04-25（8 天窗口）
- **覆盖 Region**：us-east-1, us-east-2, us-west-1, us-west-2, eu-west-1, eu-west-2, eu-west-3, eu-central-1, eu-north-1, ap-southeast-1, ap-southeast-2, ap-northeast-1, ap-northeast-2, ap-south-1, sa-east-1, ca-central-1

---

## 4. 风险分级标准

| 等级 | CVSS 3.1 分值 | 判定依据 |
|------|---------------|----------|
| **Critical** | 9.0 - 10.0 | 已被利用的漏洞、可直接导致数据泄露或服务接管 |
| **High** | 7.0 - 8.9 | 高概率被利用、缺失关键安全控制 |
| **Medium** | 4.0 - 6.9 | 需要特定条件才能被利用、扩大攻击面 |
| **Low** | 0.1 - 3.9 | 最佳实践偏差、信息泄露风险较低 |
| **Informational** | 0.0 | 建议改进项，无直接安全风险 |

**业务影响维度**：数据泄露、服务中断、合规违规、横向移动风险。

---

## 5. 详细发现

---

### AWS-IAM-001：多个 IAM 用户 Access Key 已被外部攻击者利用

**严重程度**：Critical  
**CVSS 3.1**：`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` — **9.8**

#### 受影响资源

| IAM 用户 | Access Key ID | Key 年龄（天） | 攻击者 IP | 攻击行为 | Key 当前状态 |
|----------|--------------|---------------|-----------|----------|-------------|
| `lending_ses_prod` | `AKIAZNVMXQFBROVA2FP7` | 1191 | 216.126.225.20 (US) | ImportKeyPair, DescribeInstances | **已禁用** |
| `flashwire-prod` | `AKIAZNVMXQFBU7OZX3JH` | 1565 | 216.126.225.20 (US) | ImportKeyPair | **仍 Active** |
| `legend_sqs_development` | `AKIAZNVMXQFB7IWI2U7B` | 716 | 18.144.153.92, 103.137.247.47 | DescribeInstances, DescribeSecurityGroups | **仍 Active** |

#### 问题描述

三个 IAM 用户的长期 Access Key 被外部攻击者获取并用于 AWS API 调用。攻击者执行了 EC2 侦察操作（`DescribeInstances`、`DescribeSecurityGroups`）和攻击准备操作（`ImportKeyPair`——导入 SSH 密钥对以便后续启动 EC2 实例）。攻击模式符合典型的被盗凭据启动挖矿实例攻击链。

`lending_ses_prod` 和 `flashwire-prod` 被同一攻击者 IP `216.126.225.20` 在 2 秒内先后利用（04-25 02:47:10 和 02:47:12 UTC+5），表明攻击者持有多个泄露凭据并批量扫描。

#### 风险与潜在影响

- **业务**：攻击者可启动大量 EC2 实例用于加密货币挖矿，产生巨额 AWS 账单（已知案例可达数万美元/天）
- **数据**：若用户附加策略权限过宽，攻击者可访问 S3、RDS 等服务中的业务数据
- **合规**：未经授权的外部访问违反数据保护法规，可能触发安全事件通报义务

#### 证据

CloudTrail 查询命令：

```bash
aws cloudtrail lookup-events \
  --region us-west-2 \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ImportKeyPair \
  --start-time "2026-04-17T00:00:00Z" \
  --end-time "2026-04-25T23:59:59Z" \
  --profile legend-security-hao
```

输出（已脱敏处理）：

```
2026-04-25T02:47:12+05:00  User: lending_ses_prod    IP: 216.126.225.20
2026-04-25T02:47:10+05:00  User: flashwire-prod      IP: 216.126.225.20
```

```bash
aws cloudtrail lookup-events \
  --region us-east-1 \
  --lookup-attributes AttributeKey=Username,AttributeValue=legend_sqs_development \
  --start-time "2026-04-18T00:00:00Z" \
  --end-time "2026-04-25T23:59:59Z" \
  --profile legend-security-hao
```

输出：

```
2026-04-24T09:39:57+05:00  DescribeSecurityGroups   IP: 103.137.247.47
2026-04-19T19:36:04+05:00  DescribeInstances        IP: 18.144.153.92
2026-04-19T19:27:22+05:00  DescribeInstances        IP: 18.144.153.92
```

#### 复现步骤

1. 使用具有 CloudTrail 读权限的凭据
2. 对全部 15 个 Region 执行 `lookup-events`，按 `EventName=ImportKeyPair` 过滤
3. 对可疑用户按 `Username` 过滤，检查 `sourceIPAddress` 是否为组织已知 IP

#### 合规映射

| 标准 | 控制项 |
|------|--------|
| CIS AWS v3.0 | 1.4 — Ensure no root or IAM access key exists that is unrestricted |
| NIST SP 800-53 | AC-2(4) Automated Audit Actions, IR-5 Incident Monitoring |
| ISO 27001:2022 | A.5.28 Collection of Evidence, A.8.15 Logging |

#### 修复建议

**短期缓解（立即）**：

```bash
# 禁用 flashwire-prod 的 Key
aws iam update-access-key \
  --user-name flashwire-prod \
  --access-key-id AKIAZNVMXQFBU7OZX3JH \
  --status Inactive \
  --profile legend-security-hao

# 禁用 legend_sqs_development 的 Key
aws iam update-access-key \
  --user-name legend_sqs_development \
  --access-key-id AKIAZNVMXQFB7IWI2U7B \
  --status Inactive \
  --profile legend-security-hao
```

**长期根治**：

1. 排查泄露渠道（代码仓库、CI/CD 日志、配置文件、.env 文件）
2. 为需要恢复服务的用户创建新 Key 并附加 IP 限制策略
3. 部署 AWS GuardDuty 实现自动化异常检测
4. 考虑使用 IAM Role + STS 临时凭证替代长期 Access Key

Terraform 示例（IP 限制策略）：

```hcl
resource "aws_iam_user_policy" "deny_without_ip_or_mfa" {
  name   = "DenyWithoutIPorMFA"
  user   = aws_iam_user.service_user.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowGetSessionTokenAnywhere"
        Effect   = "Allow"
        Action   = "sts:GetSessionToken"
        Resource = "*"
      },
      {
        Sid       = "DenyUnlessWhitelistedIPorMFA"
        Effect    = "Deny"
        NotAction = "sts:GetSessionToken"
        Resource  = "*"
        Condition = {
          NotIpAddress = {
            "aws:SourceIp" = var.allowed_ips
          }
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
          Bool = {
            "aws:ViaAWSService" = "false"
          }
        }
      }
    ]
  })
}

variable "allowed_ips" {
  type    = list(string)
  default = ["124.195.223.66/32", "150.228.211.208/32"]
}
```

#### 参考资料

- [AWS: What to Do If You Inadvertently Expose an AWS Access Key](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#securing_access-keys)
- [AWS: Remediating Compromised AWS Credentials](https://docs.aws.amazon.com/guardduty/latest/ug/compromised-creds.html)

#### 建议修复时限

**立即（0 天）** — 两个仍 Active 的泄露 Key 必须在本报告发出后立即禁用。

---

### AWS-IAM-002：97% 的 IAM 用户未启用多因素认证（MFA）

**严重程度**：High  
**CVSS 3.1**：`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` — **8.8**

#### 受影响资源

62 个 IAM 用户中，仅 2 个启用了 MFA：

| 已启用 MFA | 未启用 MFA |
|-----------|-----------|
| `kaiqiang.qiao`、`netops_tao` | 其余 60 个用户 |

**MFA 启用率：3.2%**

#### 问题描述

绝大多数 IAM 用户（包括具有管理员权限、KMS 密钥管理权限、生产环境 S3/SES 访问权限的用户）未启用任何形式的 MFA。一旦 Access Key 或 Console 密码泄露，攻击者可直接使用凭据，无需通过第二因素验证。

#### 风险与潜在影响

- **业务**：如 AWS-IAM-001 所示，缺少 MFA 的凭据泄露已导致实际攻击事件
- **数据**：攻击者获取凭据后可直接访问所有该用户有权限的 AWS 资源
- **合规**：违反 CIS AWS Foundations Benchmark 强制要求，不满足 SOC 2 Type II 和 ISO 27001 的访问控制要求

#### 证据

```bash
# 检查单个用户 MFA 状态
aws iam list-mfa-devices --user-name <username> --profile legend-security-hao

# 批量统计
aws iam generate-credential-report --profile legend-security-hao
aws iam get-credential-report --profile legend-security-hao --output text --query Content | base64 -d | cut -d',' -f1,8
```

#### 复现步骤

1. 执行 `aws iam list-mfa-devices --user-name <username>`
2. 返回空数组 `[]` 即表示未启用 MFA

#### 合规映射

| 标准 | 控制项 |
|------|--------|
| CIS AWS v3.0 | 1.5 — Ensure MFA is enabled for the root user |
| CIS AWS v3.0 | 1.6 — Ensure MFA is enabled for all IAM users with console access |
| NIST SP 800-53 | IA-2(1) Multi-factor Authentication to Privileged Accounts |
| ISO 27001:2022 | A.8.5 Secure Authentication |

#### 修复建议

**短期缓解**：对人类用户（如 `kaiqiang.qiao`、`netops_tao`、`legend-security-hao`）部署硬件 MFA（YubiKey），参考项目内 `docs/yubikey-mfa-guide.md`。

**长期根治**：

- 服务账户（程序化访问）：通过 IP 限制策略（`DenyWithoutIPorMFA`）补偿 MFA 缺失
- 人类用户：强制 MFA + IP 限制双重保护
- 使用 SCP（Service Control Policy）在组织级别强制 MFA

```hcl
# Terraform: 组织级 SCP 强制 MFA
resource "aws_organizations_policy" "require_mfa" {
  name    = "RequireMFA"
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyAllExceptSTSWithoutMFA"
        Effect    = "Deny"
        NotAction = ["sts:GetSessionToken", "iam:CreateVirtualMFADevice", "iam:EnableMFADevice"]
        Resource  = "*"
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      }
    ]
  })
}
```

#### 参考资料

- [AWS: Enabling MFA Devices for Users in AWS](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable.html)
- [CIS AWS Foundations Benchmark v3.0 — Section 1.5, 1.6](https://www.cisecurity.org/benchmark/amazon_web_services)

#### 建议修复时限

**14 天** — 人类用户优先，服务账户通过 IP 限制策略补偿。

---

### AWS-IAM-003：98% 的 IAM 用户无 IP 访问限制策略

**严重程度**：High  
**CVSS 3.1**：`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` — **8.1**

#### 受影响资源

62 个 IAM 用户中，仅 1 个配置了 IP 限制策略：

| 已配置 IP 限制 | 未配置 IP 限制 |
|---------------|---------------|
| `legend-security-hao` | 其余 61 个用户 |

**IP 限制覆盖率：1.6%**

#### 问题描述

几乎所有 IAM 用户的 Access Key 可从全球任意 IP 地址调用 AWS API，无源 IP 限制。即使凭据只需在特定服务器或办公网络使用，也未通过 IAM Policy Condition 限制 `aws:SourceIp`。

#### 风险与潜在影响

- **业务**：凭据泄露后攻击者可从任意位置发起攻击，无地理限制
- **数据**：结合 AWS-IAM-002（无 MFA），凭据泄露 = 完全接管
- **合规**：未实施网络层访问控制，不满足零信任架构基本要求

#### 证据

```bash
aws iam list-user-policies --user-name flashwire-prod --profile legend-security-hao
# 返回: []（无 inline policy）
```

#### 合规映射

| 标准 | 控制项 |
|------|--------|
| CIS AWS v3.0 | 1.22 — Ensure IAM policies that allow full administrative privileges are not attached |
| NIST SP 800-53 | AC-3(7) Role-Based Access Control, AC-6 Least Privilege |
| ISO 27001:2022 | A.8.3 Information Access Restriction |

#### 修复建议

**短期缓解**：批量部署 `DenyWithoutIPorMFA` 策略至所有用户：

```bash
#!/bin/bash
POLICY='{
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
          "aws:SourceIp": ["124.195.223.66/32", "150.228.211.208/32"]
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
}'

for user in $(aws iam list-users --query 'Users[].UserName' --output text --profile legend-security-hao); do
  echo "Applying policy to $user..."
  aws iam put-user-policy \
    --user-name "$user" \
    --policy-name DenyWithoutIPorMFA \
    --policy-document "$POLICY" \
    --profile legend-security-hao
done
```

> **注意**：批量部署前需确认白名单 IP 包含所有合法服务器 IP（CI/CD、生产服务器等），避免中断业务。建议先在非生产用户上测试。

**长期根治**：使用 IAM Group 统一管理策略，新用户自动继承。

#### 参考资料

- [AWS: IAM Policy Condition Keys — aws:SourceIp](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-sourceip)

#### 建议修复时限

**14 天** — 需要先收集所有合法服务器 IP，避免误伤业务。

---

### AWS-IAM-004：40+ 个 Active Access Key 超过 90 天未轮换

**严重程度**：High  
**CVSS 3.1**：`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` — **8.1**

#### 受影响资源

以下为 Key 年龄最长的 Top 15（全部为 Active 状态）：

| IAM 用户 | Access Key ID | Key 年龄（天） | 最后使用 |
|----------|--------------|---------------|----------|
| `s3sandbox` | `AKIAZNVMXQFB6LDH4BAH` | 2185 | 2023-05-11 |
| `ses_zing` | `AKIAZNVMXQFBZGNBWT5X` | 1736 | 2022-10-04 |
| `zing_s3_prod` | `AKIAZNVMXQFBQPMKUGV3` | 1732 | 2022-12-09 |
| `bankdev-zingpays` | `AKIAZNVMXQFB7EISKVOL` | 1681 | 2025-04-08 |
| `flashwire-prod` | `AKIAZNVMXQFBU7OZX3JH` | 1565 | 2026-04-25 |
| `flashwire-stag` | `AKIAZNVMXQFB6STJNR5O` | 1539 | 2022-11-28 |
| `netops_tao` | `AKIAZNVMXQFB6FKRCRC4` | 1449 | 2023-10-04 |
| `legend_ses_sandbox` | `AKIAZNVMXQFB2RVWQZ4E` | 1411 | 2022-06-29 |
| `legend_ses_production_queue` | `AKIAZNVMXQFBUNLNAW43` | 1411 | 2023-04-21 |
| `legend_ses_development` | `AKIAZNVMXQFBRPEDGUVH` | 1411 | 2023-04-07 |
| `legend_ses_development_controller` | `AKIAZNVMXQFB47LC4OTF` | 1381 | 2022-09-28 |
| `kaiqiang.qiao` | `AKIAZNVMXQFB7BL3N6PN` | 1290 | 2026-04-07 |
| `monitor` | `AKIAZNVMXQFB3H2DND57` | 1290 | 2026-04-07 |
| `flashwire-publics3-devtest` | `AKIAZNVMXQFB65WFX5QK` | 1276 | 2026-04-17 |
| `lendingprod-s3` | `AKIAZNVMXQFB33OUOF2J` | 1255 | 2023-06-28 |

**完整列表**：共 46 个 Active Key 超过 90 天未轮换。

#### 问题描述

AWS 安全最佳实践要求 Access Key 每 90 天轮换一次。当前账户下 46 个 Active Key 超过 90 天未轮换，平均 Key 年龄约 950 天（2.6 年），最长达 2185 天（约 6 年）。长期有效的凭据显著增加了泄露概率和泄露后的影响窗口。

#### 风险与潜在影响

- **业务**：Key 存续时间越长，通过代码仓库历史、日志、备份等渠道泄露的概率越高
- **数据**：如 AWS-IAM-001 所示，年龄超 1000 天的 Key 已实际被攻击者利用
- **合规**：直接违反 CIS AWS Benchmark 1.14

#### 合规映射

| 标准 | 控制项 |
|------|--------|
| CIS AWS v3.0 | 1.14 — Ensure access keys are rotated every 90 days or less |
| NIST SP 800-53 | IA-5(1) Password-Based Authentication — Authenticator Management |
| ISO 27001:2022 | A.5.17 Authentication Information |

#### 修复建议

**短期缓解**：按风险优先级轮换——先轮换已泄露用户的 Key，再轮换年龄最长的 Key。

```bash
# 轮换步骤（以 flashwire-prod 为例）
# 1. 创建新 Key
aws iam create-access-key --user-name flashwire-prod --profile legend-security-hao

# 2. 在应用中更新为新 Key（需要业务团队配合）

# 3. 确认新 Key 正常工作后禁用旧 Key
aws iam update-access-key \
  --user-name flashwire-prod \
  --access-key-id AKIAZNVMXQFBU7OZX3JH \
  --status Inactive \
  --profile legend-security-hao

# 4. 观察 7 天无异常后删除旧 Key
aws iam delete-access-key \
  --user-name flashwire-prod \
  --access-key-id AKIAZNVMXQFBU7OZX3JH \
  --profile legend-security-hao
```

**长期根治**：

- 部署 AWS Config 规则 `access-keys-rotated`，自动检测超期 Key
- 使用 IAM Role + STS 临时凭证替代长期 Access Key（适用于 EC2/ECS/Lambda 上的应用）
- 建立 Key 轮换 SOP 和 Calendar 提醒

```hcl
# Terraform: AWS Config 规则 — Key 轮换检测
resource "aws_config_config_rule" "access_key_rotation" {
  name = "access-keys-rotated"
  source {
    owner             = "AWS"
    source_identifier = "ACCESS_KEYS_ROTATED"
  }
  input_parameters = jsonencode({
    maxAccessKeyAge = "90"
  })
}
```

#### 参考资料

- [AWS: Rotating Access Keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_RotateAccessKey)
- [AWS Config Managed Rule: access-keys-rotated](https://docs.aws.amazon.com/config/latest/developerguide/access-keys-rotated.html)

#### 建议修复时限

**30 天** — 分批轮换，优先处理生产环境和高权限用户。

---

### AWS-IAM-005：17+ 个 Active Access Key 超过 180 天未使用（僵尸凭据）

**严重程度**：Medium  
**CVSS 3.1**：`CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` — **5.9**

#### 受影响资源

| IAM 用户 | Access Key ID | 最后使用时间 | 闲置天数 |
|----------|--------------|-------------|----------|
| `flashwire-stag` | `AKIAZNVMXQFB6STJNR5O` | 2022-11-28 | 1244 |
| `legend_ses_development_controller` | `AKIAZNVMXQFB47LC4OTF` | 2022-09-28 | 1305 |
| `legend_ses_sandbox` | `AKIAZNVMXQFB2RVWQZ4E` | 2022-06-29 | 1396 |
| `ses_zing` | `AKIAZNVMXQFBZGNBWT5X` | 2022-10-04 | 1299 |
| `zing_s3_prod` | `AKIAZNVMXQFBQPMKUGV3` | 2022-12-09 | 1233 |
| `legend_ses_production_queue` | `AKIAZNVMXQFBUNLNAW43` | 2023-04-21 | 1100 |
| `legend_les_development` | `AKIAZNVMXQFBRPEDGUVH` | 2023-04-07 | 1114 |
| `test-opensearch-serverless` | `AKIAZNVMXQFB2E56JEMX` | 2023-05-18 | 1073 |
| `lendingprod-s3` | `AKIAZNVMXQFB33OUOF2J` | 2023-06-28 | 1032 |
| `stellapay_s3_pkgupload_prod` | `AKIAZNVMXQFBZV7SSXPQ` | 2023-07-05 | 1026 |
| `ecr-frontend-team-read` | `AKIAZNVMXQFB5WDBGWKJ` | 2023-07-13 | 1018 |
| `stellapay_s3_pkgupload_dev` | `AKIAZNVMXQFBXAX5GLG6` | 2023-08-22 | 977 |
| `s3sandbox` | `AKIAZNVMXQFB6LDH4BAH` | 2023-05-11 | 1079 |
| `netops_tao` | `AKIAZNVMXQFB6FKRCRC4` | 2023-10-04 | 934 |
| `legend_sns_production_www` | `AKIAZNVMXQFBVU34BK3S` | 2023-11-27 | 880 |
| `bankdev-zingpays` | `AKIAZNVMXQFB7EISKVOL` | 2025-04-08 | 382 |
| `jenkins-eks-user` | `AKIAZNVMXQFB33IWTM6P` | 2025-01-22 | 458 |

#### 问题描述

17 个 Active Access Key 在过去 180 天内未被任何 AWS 服务调用，但仍保持 Active 状态。这些凭据无当前业务用途，却持续暴露攻击面。部分 Key 已超过 3 年未使用。

#### 风险与潜在影响

- **业务**：无当前用途的凭据被攻击者获取后，可能不会被业务团队察觉
- **数据**：取决于附加权限，可能导致未授权数据访问
- **合规**：违反最小权限原则和账户生命周期管理要求

#### 合规映射

| 标准 | 控制项 |
|------|--------|
| CIS AWS v3.0 | 1.12 — Ensure credentials unused for 45 days or greater are disabled |
| NIST SP 800-53 | AC-2(3) Disable Accounts |
| ISO 27001:2022 | A.5.18 Access Rights — Review and Removal |

#### 修复建议

**短期缓解**：立即禁用全部僵尸 Key。

```bash
# 禁用所有超过 180 天未使用的 Active Key
ZOMBIE_KEYS=(
  "flashwire-stag:AKIAZNVMXQFB6STJNR5O"
  "legend_ses_development_controller:AKIAZNVMXQFB47LC4OTF"
  "legend_ses_sandbox:AKIAZNVMXQFB2RVWQZ4E"
  "ses_zing:AKIAZNVMXQFBZGNBWT5X"
  "zing_s3_prod:AKIAZNVMXQFBQPMKUGV3"
  "legend_ses_production_queue:AKIAZNVMXQFBUNLNAW43"
  "legend_ses_development:AKIAZNVMXQFBRPEDGUVH"
  "test-opensearch-serverless:AKIAZNVMXQFB2E56JEMX"
  "lendingprod-s3:AKIAZNVMXQFB33OUOF2J"
  "stellapay_s3_pkgupload_prod:AKIAZNVMXQFBZV7SSXPQ"
  "ecr-frontend-team-read:AKIAZNVMXQFB5WDBGWKJ"
  "stellapay_s3_pkgupload_dev:AKIAZNVMXQFBXAX5GLG6"
  "s3sandbox:AKIAZNVMXQFB6LDH4BAH"
  "netops_tao:AKIAZNVMXQFB6FKRCRC4"
  "legend_sns_production_www:AKIAZNVMXQFBVU34BK3S"
  "bankdev-zingpays:AKIAZNVMXQFB7EISKVOL"
  "jenkins-eks-user:AKIAZNVMXQFB33IWTM6P"
)

for entry in "${ZOMBIE_KEYS[@]}"; do
  USER="${entry%%:*}"
  KEY="${entry##*:}"
  echo "Disabling $KEY for $USER..."
  aws iam update-access-key \
    --user-name "$USER" \
    --access-key-id "$KEY" \
    --status Inactive \
    --profile legend-security-hao
done
```

**长期根治**：部署 AWS Config 规则 `iam-user-unused-credentials-check` 自动检测。

#### 参考资料

- [AWS: Finding Unused Credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_finding-unused.html)

#### 建议修复时限

**7 天** — 僵尸 Key 无业务依赖，禁用风险极低。

---

### AWS-IAM-006：部分用户最后使用服务与命名用途不匹配

**严重程度**：Medium  
**CVSS 3.1**：`CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N` — **4.2**

#### 受影响资源

| IAM 用户 | 命名推断用途 | 最后使用服务 | 风险判定 |
|----------|------------|------------|----------|
| `legend_sqs_development` | SQS | **ec2** | **已确认泄露（见 AWS-IAM-001）** |
| `lending_ses_prod` | SES | **ec2** | **已确认泄露（见 AWS-IAM-001）** |
| `legend_ses_development_controller` | SES | **iam** | 待确认 |
| `legend_sns_dev` | SNS | **s3** | 待确认（可能合法跨服务使用） |
| `s3dev`（旧 Key） | S3 | **route53domains** | 待确认 |

#### 问题描述

部分 IAM 用户的实际 API 调用服务与其命名约定暗示的用途不一致。其中 2 个已通过 CloudTrail 确认为凭据泄露（归入 AWS-IAM-001），其余 3 个需要业务团队确认是否为合法使用。

#### 风险与潜在影响

- **业务**：可能是权限配置过宽导致的合法跨服务调用，也可能是早期未发现的泄露
- **合规**：如果非预期使用，说明权限未遵循最小权限原则

#### 修复建议

1. 业务团队确认 `legend_ses_development_controller`、`legend_sns_dev`、`s3dev` 的实际用途
2. 如确认为权限过宽，收紧 IAM Policy 至最小必要权限
3. 对可疑用户执行 CloudTrail 深度分析

#### 建议修复时限

**14 天** — 需业务团队配合确认。

---

### AWS-IAM-007：Root 账户安全基线合规

**严重程度**：Informational  
**CVSS 3.1**：N/A — **0.0**（合规项）

#### 状态

| 检查项 | 状态 |
|--------|------|
| Root MFA | 已启用 |
| Root Access Key | 不存在 |

#### 说明

Root 账户安全基线已达标。MFA 已启用，无长期 Access Key 存在。符合 CIS AWS Foundations Benchmark 1.4 和 1.5 要求。

#### 合规映射

| 标准 | 控制项 | 状态 |
|------|--------|------|
| CIS AWS v3.0 | 1.4 — Ensure no root account access key exists | 通过 |
| CIS AWS v3.0 | 1.5 — Ensure MFA is enabled for the root account | 通过 |

---

## 6. 按服务分类汇总

### IAM

本次审计核心对象。发现 7 项问题，其中 1 项 Critical、3 项 High、2 项 Medium、1 项 Informational。详见第 5 章。

### EC2

攻击者在 `us-west-2` 执行了 `ImportKeyPair`（2 次）和 `DescribeInstances`（1 次），在 `us-east-1` 执行了 `DescribeInstances`（2 次）和 `DescribeSecurityGroups`（1 次）。未成功启动实例，未发现残留资源。

### CloudTrail

CloudTrail 在审计涉及的 Region 均已启用，成功提供了攻击者活动记录。CloudTrail 配置是否覆盖全部 Region、是否启用日志文件完整性验证——**待补充**（需进一步审计）。

### S3 / RDS / VPC / Lambda / KMS / Secrets Manager / API Gateway / ECS/EKS

本次审计范围仅覆盖 IAM 用户凭据安全，以上服务**未纳入本次审计范围**，建议在后续审计中覆盖。

---

## 7. 合规性矩阵

| 发现编号 | CIS AWS v3.0 | NIST SP 800-53 | ISO 27001:2022 | 状态 |
|---------|-------------|----------------|---------------|------|
| AWS-IAM-001 | 1.4 | AC-2(4), IR-5 | A.5.28, A.8.15 | 不合规 |
| AWS-IAM-002 | 1.5, 1.6 | IA-2(1) | A.8.5 | 不合规 |
| AWS-IAM-003 | 1.22 | AC-3(7), AC-6 | A.8.3 | 不合规 |
| AWS-IAM-004 | 1.14 | IA-5(1) | A.5.17 | 不合规 |
| AWS-IAM-005 | 1.12 | AC-2(3) | A.5.18 | 不合规 |
| AWS-IAM-006 | 1.22 | AC-6(5) | A.8.2 | 待确认 |
| AWS-IAM-007 | 1.4, 1.5 | IA-2(1) | A.8.5 | **合规** |

---

## 8. 修复路线图

### 立即修复（0-7 天）— Critical + 僵尸 Key

| 优先级 | 操作 | 负责人 | 关联发现 |
|--------|------|--------|----------|
| P0 | 禁用 `flashwire-prod` Key `AKIAZNVMXQFBU7OZX3JH` | 安全团队 | AWS-IAM-001 |
| P0 | 禁用 `legend_sqs_development` Key `AKIAZNVMXQFB7IWI2U7B` | 安全团队 | AWS-IAM-001 |
| P0 | 排查泄露渠道（代码仓库、CI/CD、配置文件） | 安全团队 + DevOps | AWS-IAM-001 |
| P1 | 禁用全部 17 个僵尸 Key | 安全团队 | AWS-IAM-005 |

### 短期修复（7-30 天）— High

| 优先级 | 操作 | 负责人 | 关联发现 |
|--------|------|--------|----------|
| P2 | 对全部用户部署 `DenyWithoutIPorMFA` IP 限制策略 | 安全团队 | AWS-IAM-003 |
| P2 | 人类用户启用 YubiKey MFA | 各用户 + 安全团队 | AWS-IAM-002 |
| P2 | 启动 Key 轮换计划（优先生产环境 Key） | DevOps + 业务团队 | AWS-IAM-004 |

### 中期修复（30-90 天）— Medium + 架构优化

| 优先级 | 操作 | 负责人 | 关联发现 |
|--------|------|--------|----------|
| P3 | 确认 AWS-IAM-006 中异常用户的实际用途 | 业务团队 | AWS-IAM-006 |
| P3 | 部署 AWS Config 规则自动检测 Key 过期和闲置 | DevOps | AWS-IAM-004, 005 |
| P3 | 评估 IAM Role + STS 临时凭证替代长期 Key 的可行性 | 架构团队 | AWS-IAM-004 |
| P3 | 启用 AWS GuardDuty 自动化威胁检测 | 安全团队 | AWS-IAM-001 |

### 长期改进（90 天+）— 架构层面

| 操作 | 说明 |
|------|------|
| 全面迁移至 IAM Role + 临时凭证 | 消除长期 Access Key 的系统性风险 |
| 部署 AWS Organizations SCP | 在组织级别强制 MFA、限制高危操作 |
| 建立 IAM 用户生命周期管理流程 | 入职/离职/项目结束时自动创建/清理凭据 |
| 扩展审计范围至 S3、VPC、RDS 等服务 | 全面覆盖 AWS 安全基线 |

---

## 9. 附录

### 9.1 术语表

| 术语 | 说明 |
|------|------|
| Access Key | AWS IAM 长期凭据，由 Access Key ID 和 Secret Access Key 组成 |
| MFA | Multi-Factor Authentication，多因素认证 |
| STS | AWS Security Token Service，用于获取临时安全凭证 |
| SCP | Service Control Policy，AWS Organizations 服务控制策略 |
| CIS | Center for Internet Security，互联网安全中心 |
| CVSS | Common Vulnerability Scoring System，通用漏洞评分系统 |
| CloudTrail | AWS 的 API 调用审计日志服务 |
| GuardDuty | AWS 的智能威胁检测服务 |
| ImportKeyPair | EC2 API，用于导入 SSH 公钥到 EC2 Key Pair，常被攻击者用于准备启动实例 |

### 9.2 审计原始数据索引

| 数据 | 位置 |
|------|------|
| 全用户扫描结果 | 本次审计会话记录 |
| lending_ses_prod 事件报告 | `docs/reports/ses_key_breach_04252026.md` |
| 审计脚本 | `scripts/aws-user-audit.sh` |
| IP 限制配置文档 | `docs/aws-ip-restriction.md` |
| YubiKey MFA 指南 | `docs/yubikey-mfa-guide.md` |

### 9.3 已扫描且通过的控制项

| 控制项 | 状态 |
|--------|------|
| Root 账户 MFA | 通过 |
| Root 账户 Access Key | 通过（不存在） |
| CloudTrail 事件记录可用性 | 通过 |

### 9.4 扫描命令清单

```bash
# 1. 列出全部 IAM 用户
aws iam list-users --query 'Users[].UserName' --output text --profile legend-security-hao

# 2. 检查 Root Access Key 是否存在
aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent' --profile legend-security-hao

# 3. 单用户深度审计
bash scripts/aws-user-audit.sh <username> --profile legend-security-hao

# 4. 批量检查 Key 状态
aws iam list-access-keys --user-name <username> --profile legend-security-hao
aws iam get-access-key-last-used --access-key-id <key-id> --profile legend-security-hao

# 5. 检查 MFA 状态
aws iam list-mfa-devices --user-name <username> --profile legend-security-hao

# 6. 检查 IP 限制策略
aws iam list-user-policies --user-name <username> --profile legend-security-hao

# 7. CloudTrail 事件查询
aws cloudtrail lookup-events \
  --region <region> \
  --lookup-attributes AttributeKey=Username,AttributeValue=<username> \
  --start-time "2026-04-17T00:00:00Z" \
  --end-time "2026-04-25T23:59:59Z" \
  --profile legend-security-hao

# 8. 全 Region ImportKeyPair 事件搜索
aws cloudtrail lookup-events \
  --region <region> \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ImportKeyPair \
  --start-time "2026-04-17T00:00:00Z" \
  --end-time "2026-04-25T23:59:59Z" \
  --profile legend-security-hao
```

---

*报告结束。本报告基于 2026-04-25 审计数据生成，发现和建议应在对应修复时限内完成。*
