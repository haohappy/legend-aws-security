# AWS IP 访问限制配置

本文档记录 HAO 平台的 AWS 安全加固措施：通过 Security Group 限制 SSH 访问，通过 IAM Policy 限制 API 调用，均绑定到管理员的公网 IP。

## 1. 背景

HAO 部署在两个 EC2 节点：

| 节点 | 公网 IP | 区域 | Security Group |
|------|---------|------|----------------|
| SG (主节点) | 52.74.102.64 | ap-southeast-1 | `sg-0a3ac64c0487f58b7` |
| US (副节点) | 54.174.189.178 | us-east-1 | `sg-0bc9a0e8d80724f24` |

此前 SSH 对全网开放 (`0.0.0.0/0`)，IAM 用户无 IP 限制。这意味着任何获取到 SSH 密钥或 AWS Access Key 的人都可以从任意位置访问。

## 2. Security Group — SSH IP 白名单

### 2.1 原理

AWS Security Group 是实例级别的虚拟防火墙。通过将 SSH (port 22) 的入站规则从 `0.0.0.0/0` 改为特定 IP，只有白名单内的 IP 才能建立 SSH 连接。

### 2.2 操作步骤

**第一步：获取管理员公网 IP**

```bash
curl -s https://checkip.amazonaws.com
# 返回: 150.228.211.208

curl -s https://ifconfig.me
# 返回: 124.195.223.66
```

> 注意：部分 ISP 使用多出口 NAT，同一台机器通过不同服务检测到的 IP 可能不同。必须将所有出口 IP 都加入白名单，否则 SSH 连接会间歇性失败。

**第二步：删除旧的开放规则**

```bash
# SG 节点
aws ec2 revoke-security-group-ingress \
  --group-id sg-0a3ac64c0487f58b7 \
  --protocol tcp --port 22 --cidr 0.0.0.0/0 \
  --region ap-southeast-1 --profile tokenrouter-deploy

# US 节点
aws ec2 revoke-security-group-ingress \
  --group-id sg-0bc9a0e8d80724f24 \
  --protocol tcp --port 22 --cidr 0.0.0.0/0 \
  --region us-east-1 --profile tokenrouter-deploy
```

**第三步：添加白名单 IP**

```bash
# SG 节点 — 两个出口 IP
aws ec2 authorize-security-group-ingress \
  --group-id sg-0a3ac64c0487f58b7 \
  --protocol tcp --port 22 --cidr 124.195.223.66/32 \
  --region ap-southeast-1 --profile tokenrouter-deploy

aws ec2 authorize-security-group-ingress \
  --group-id sg-0a3ac64c0487f58b7 \
  --protocol tcp --port 22 --cidr 150.228.211.208/32 \
  --region ap-southeast-1 --profile tokenrouter-deploy

# US 节点 — 同样两个 IP
aws ec2 authorize-security-group-ingress \
  --group-id sg-0bc9a0e8d80724f24 \
  --protocol tcp --port 22 --cidr 124.195.223.66/32 \
  --region us-east-1 --profile tokenrouter-deploy

aws ec2 authorize-security-group-ingress \
  --group-id sg-0bc9a0e8d80724f24 \
  --protocol tcp --port 22 --cidr 150.228.211.208/32 \
  --region us-east-1 --profile tokenrouter-deploy
```

**第四步：验证连接**

```bash
ssh -i ~/.ssh/tokenrouter-sg-key.pem ec2-user@52.74.102.64 "echo ok"
ssh -i ~/.ssh/tokenrouter-key.pem ec2-user@54.174.189.178 "echo ok"
```

### 2.3 最终状态

| 节点 | Port 22 允许 IP |
|------|----------------|
| SG | `124.195.223.66/32`, `150.228.211.208/32` |
| US | `124.195.223.66/32`, `150.228.211.208/32` |

HTTP/HTTPS (port 80/443) 不受影响，仍对外开放。

## 3. IAM Policy — AWS API IP 白名单

### 3.1 原理

通过给 IAM 用户附加一个 Deny 策略，当请求不满足安全条件时拒绝 AWS API 调用。当前使用"IP 或 MFA 二选一"方案（方案 B）：白名单 IP 上直接操作，换了 IP 时可通过 YubiKey MFA 认证继续访问。

### 3.2 策略内容

策略名称：`DenyWithoutIPorMFA`，以 inline policy 形式附加到 `admin` 用户。

```json
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
          "aws:SourceIp": [
            "124.195.223.66/32",
            "150.228.211.208/32"
          ]
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
```

**关键设计：**

- **"二选一"逻辑**：Deny 条件中 `NotIpAddress` 和 `BoolIfExists` 是 AND 关系，即 IP 不在白名单 **且** 没有 MFA 时才 Deny。满足其一即放行
- **`AllowGetSessionTokenAnywhere`**：允许从任意 IP 调用 `sts:GetSessionToken`（MFA 认证入口），否则换了 IP 后无法获取 MFA 临时凭据
- **`aws:ViaAWSService: false`**：排除 AWS 服务间的内部调用（如 EC2 调 Bedrock、SES 等）
- **Deny 优先**：IAM 中 Deny 优先于任何 Allow，即使有 `AdministratorAccess`

### 3.3 操作命令

```bash
aws iam put-user-policy \
  --user-name admin \
  --policy-name DenyWithoutIPorMFA \
  --policy-document '{
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
          "BoolIfExists": {"aws:MultiFactorAuthPresent": "false"},
          "Bool": {"aws:ViaAWSService": "false"}
        }
      }
    ]
  }' \
  --profile tokenrouter-deploy
```

> 关于 YubiKey MFA 的完整配置步骤，见 [yubikey-mfa-guide.md](yubikey-mfa-guide.md)。

### 3.4 验证

```bash
# 从白名单 IP 调用 — 应返回正常结果
aws sts get-caller-identity --profile tokenrouter-deploy

# 从非白名单 IP 调用 — 应返回 Access Denied
```

## 4. IP 变更时的更新流程

ISP 更换公网 IP 后，SSH 和 AWS CLI 都会失效。按以下步骤恢复：

### 4.1 获取新 IP

```bash
curl -s https://checkip.amazonaws.com
curl -s https://ifconfig.me
```

### 场景 A：CLI 还能用（至少一个旧 IP 仍有效）

**第一步：更新 IAM Policy（先改这个，否则后续 CLI 命令可能被拒）**

```bash
aws iam put-user-policy --user-name admin \
  --policy-name DenyNonWhitelistedIP \
  --policy-document '{
    "Version":"2012-10-17",
    "Statement":[{
      "Sid":"DenyAllExceptFromWhitelistedIP",
      "Effect":"Deny","Action":"*","Resource":"*",
      "Condition":{
        "NotIpAddress":{"aws:SourceIp":["<新IP1>/32","<新IP2>/32"]},
        "Bool":{"aws:ViaAWSService":"false"}
      }
    }]
  }' --profile tokenrouter-deploy
```

**第二步：更新 Security Group（SG 节点）**

```bash
# 删除旧 IP
aws ec2 revoke-security-group-ingress \
  --group-id sg-0a3ac64c0487f58b7 \
  --protocol tcp --port 22 --cidr <旧IP>/32 \
  --region ap-southeast-1 --profile tokenrouter-deploy

# 添加新 IP
aws ec2 authorize-security-group-ingress \
  --group-id sg-0a3ac64c0487f58b7 \
  --protocol tcp --port 22 --cidr <新IP>/32 \
  --region ap-southeast-1 --profile tokenrouter-deploy
```

**第三步：更新 Security Group（US 节点）**

```bash
# 删除旧 IP
aws ec2 revoke-security-group-ingress \
  --group-id sg-0bc9a0e8d80724f24 \
  --protocol tcp --port 22 --cidr <旧IP>/32 \
  --region us-east-1 --profile tokenrouter-deploy

# 添加新 IP
aws ec2 authorize-security-group-ingress \
  --group-id sg-0bc9a0e8d80724f24 \
  --protocol tcp --port 22 --cidr <新IP>/32 \
  --region us-east-1 --profile tokenrouter-deploy
```

**第四步：验证**

```bash
# AWS CLI
aws sts get-caller-identity --profile tokenrouter-deploy

# SSH
ssh -i ~/.ssh/tokenrouter-sg-key.pem ec2-user@52.74.102.64 "echo ok"
ssh -i ~/.ssh/tokenrouter-key.pem ec2-user@54.174.189.178 "echo ok"
```

### 场景 B：CLI 被锁死（所有旧 IP 都失效了）

当 ISP 更换了所有出口 IP，AWS CLI 会返回 Access Denied，无法执行任何命令。此时需要通过浏览器恢复：

1. 浏览器登录 [AWS Console](https://console.aws.amazon.com)（用 **root 账号**，root 不受 IAM Policy 限制）
2. 进入 **IAM → Users → admin → Permissions policies**
3. 找到 `DenyNonWhitelistedIP` → 点击 **Edit**
4. 将 `aws:SourceIp` 中的 IP 地址替换为新 IP
5. 保存后，CLI 立即恢复
6. 用 CLI 更新 Security Group（参照场景 A 的第二、三步）

> **重要**：确保 root 账号的登录凭据（邮箱 + 密码 + MFA）安全保存。这是 CLI 被锁死时唯一的恢复入口。

### 快捷方式：让 Claude Code 帮你改

如果你使用 Claude Code，直接说"IP 变了"即可。Claude Code 会自动：
1. 检测你的新公网 IP
2. 更新 IAM Policy
3. 更新两个节点的 Security Group
4. 验证连接

## 5. 涉及的 AWS Profile

| Profile | IAM User | 用途 |
|---------|----------|------|
| `tokenrouter-deploy` | `admin` | 部署、EC2 管理、Route 53、IAM |
| `default` | `AmazonSSM_Claude_Code_Hao` | Claude Code 使用（未加 IP 限制） |
| `tokenrouter-ses` | — | SES 邮件发送 |

目前仅对 `admin` 用户加了 IP 限制。如需对其他用户也加限制，使用相同的 `put-user-policy` 命令。

## 6. 安全效果总结

| 攻击场景 | 加固前 | 加固后 |
|---------|-------|-------|
| SSH 密钥泄露 | 攻击者可从任意 IP 登录服务器 | 只有白名单 IP 可连接 |
| AWS Access Key 泄露 | 攻击者可从任意位置调用 AWS API | 非白名单 IP 全部 Deny |
| 暴力破解 SSH | 全球 IP 均可尝试 | 非白名单 IP 在网络层即被拒绝 |
