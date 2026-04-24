# YubiKey MFA 配置指南

本文档说明如何为 AWS IAM 用户配置 YubiKey 硬件 MFA，以保护 Console 登录和 CLI 访问。

## 1. 背景

当前安全方案是 IP 白名单限制（见 `aws-ip-restriction.md`），已覆盖大部分风险。YubiKey MFA 是可选的额外防护层，适用于以下场景：

- 频繁更换 IP，不想反复更新 IP 限制策略
- 需要在公共网络环境下操作 AWS
- 希望实现"IP 限制 + 物理设备"双重防护

## 2. 前置条件

- 一把 YubiKey 5 系列（支持 TOTP）
- USB-A 转 USB-C 转换头（如果 MacBook 只有 USB-C 口而 YubiKey 是 USB-A 接口）
- macOS 安装 `ykman`（YubiKey Manager CLI）

```bash
# 安装 ykman
brew install ykman

# 插入 YubiKey 后验证识别
ykman info

# 应输出类似:
# Device type: YubiKey 5 NFC
# Serial number: 12345678
# Firmware version: 5.4.3
# ...
```

## 3. 注册 YubiKey 为 IAM 虚拟 MFA 设备

### 3.1 创建虚拟 MFA 设备

```bash
aws iam create-virtual-mfa-device \
  --virtual-mfa-device-name admin-yubikey \
  --outfile /tmp/mfa-secret.png \
  --bootstrap-method QRCodePNG \
  --profile tokenrouter-deploy
```

这会输出一个 MFA ARN（如 `arn:aws:iam::527302818462:mfa/admin-yubikey`）和一个 QR 码图片。

### 3.2 提取 Base32 Secret

如果需要纯文本 secret（用于 ykman 或 oathtool），改用：

```bash
aws iam create-virtual-mfa-device \
  --virtual-mfa-device-name admin-yubikey \
  --outfile /tmp/mfa-secret.txt \
  --bootstrap-method Base32StringSeed \
  --profile tokenrouter-deploy
```

`/tmp/mfa-secret.txt` 的内容就是 Base32 编码的 secret key。

### 3.3 将 Secret 写入 YubiKey

```bash
# 读取 secret
MFA_SECRET=$(cat /tmp/mfa-secret.txt)

# 写入 YubiKey（需要插入 YubiKey）
ykman oath accounts add -t "aws-admin" "$MFA_SECRET"

# 验证：生成一个测试码（触摸 YubiKey）
ykman oath accounts code aws-admin
```

### 3.4 激活 MFA 设备

需要连续提供两个不同的动态码（间隔 30 秒）：

```bash
# 第一个码（触摸 YubiKey）
CODE1=$(ykman oath accounts code -s aws-admin)

# 等 30 秒
sleep 30

# 第二个码（再次触摸 YubiKey）
CODE2=$(ykman oath accounts code -s aws-admin)

# 激活
aws iam enable-mfa-device \
  --user-name admin \
  --serial-number arn:aws:iam::527302818462:mfa/admin-yubikey \
  --authentication-code1 "$CODE1" \
  --authentication-code2 "$CODE2" \
  --profile tokenrouter-deploy
```

### 3.5 清理 Secret 文件

```bash
rm -f /tmp/mfa-secret.txt /tmp/mfa-secret.png
```

Secret 已存储在 YubiKey 硬件中，本地不再需要保留。

## 4. 强制 CLI 使用 MFA

### 4.1 添加 IAM Policy

在 `admin` 用户上添加内联策略，拒绝未经 MFA 认证的请求：

```bash
aws iam put-user-policy \
  --user-name admin \
  --policy-name RequireMFA \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "AllowGetSessionToken",
        "Effect": "Allow",
        "Action": "sts:GetSessionToken",
        "Resource": "*"
      },
      {
        "Sid": "DenyAllWithoutMFA",
        "Effect": "Deny",
        "NotAction": "sts:GetSessionToken",
        "Resource": "*",
        "Condition": {
          "BoolIfExists": {
            "aws:MultiFactorAuthPresent": "false"
          }
        }
      }
    ]
  }' \
  --profile tokenrouter-deploy
```

这个策略的逻辑：
- 允许 `sts:GetSessionToken`（获取临时凭据时不需要 MFA，否则死锁）
- 其他所有操作，如果没有 MFA 认证，全部拒绝

### 4.2 获取 MFA 临时凭据

```bash
# 触摸 YubiKey 获取动态码
CODE=$(ykman oath accounts code -s aws-admin)

# 获取临时凭据（最长 36 小时）
aws sts get-session-token \
  --serial-number arn:aws:iam::527302818462:mfa/admin-yubikey \
  --token-code "$CODE" \
  --duration-seconds 129600 \
  --profile tokenrouter-deploy \
  --output json
```

返回：

```json
{
  "Credentials": {
    "AccessKeyId": "ASIAXXX...",
    "SecretAccessKey": "xxx...",
    "SessionToken": "xxx...",
    "Expiration": "2026-04-26T16:00:00Z"
  }
}
```

### 4.3 配置临时 Profile

将临时凭据写入 `~/.aws/credentials`：

```ini
[tokenrouter-mfa]
aws_access_key_id = ASIAXXX...
aws_secret_access_key = xxx...
aws_session_token = xxx...
```

之后所有操作使用 `--profile tokenrouter-mfa`。

## 5. 自动化脚本

为了简化日常操作，创建一个 helper 脚本：

```bash
#!/usr/bin/env bash
# scripts/aws-mfa-login.sh
# 用法: ./scripts/aws-mfa-login.sh

set -euo pipefail

MFA_SERIAL="arn:aws:iam::527302818462:mfa/admin-yubikey"
SOURCE_PROFILE="tokenrouter-deploy"
TARGET_PROFILE="tokenrouter-mfa"
DURATION=129600  # 36 小时

echo "请触摸 YubiKey..."
CODE=$(ykman oath accounts code -s aws-admin)

CREDS=$(aws sts get-session-token \
  --serial-number "$MFA_SERIAL" \
  --token-code "$CODE" \
  --duration-seconds "$DURATION" \
  --profile "$SOURCE_PROFILE" \
  --output json)

AK=$(echo "$CREDS" | jq -r '.Credentials.AccessKeyId')
SK=$(echo "$CREDS" | jq -r '.Credentials.SecretAccessKey')
ST=$(echo "$CREDS" | jq -r '.Credentials.SessionToken')
EXP=$(echo "$CREDS" | jq -r '.Credentials.Expiration')

aws configure set aws_access_key_id "$AK" --profile "$TARGET_PROFILE"
aws configure set aws_secret_access_key "$SK" --profile "$TARGET_PROFILE"
aws configure set aws_session_token "$ST" --profile "$TARGET_PROFILE"

echo "✓ 临时凭据已写入 profile: $TARGET_PROFILE"
echo "  过期时间: $EXP"
echo ""
echo "使用方式:"
echo "  aws s3 ls --profile $TARGET_PROFILE"
echo "  ./deploy/deploy.sh 需要修改为使用 --profile $TARGET_PROFILE"
```

每天开始工作时运行一次：

```bash
./scripts/aws-mfa-login.sh
# 触摸 YubiKey
# ✓ 临时凭据已写入 profile: tokenrouter-mfa
#   过期时间: 2026-04-26T16:00:00Z
```

## 6. 在 Claude Code 中使用

### 6.1 工作流程

```
你（每天一次）                    Claude Code（全天）
────────────                    ──────────────────
运行 aws-mfa-login.sh           使用 tokenrouter-mfa profile
触摸 YubiKey                    deploy、Route53、IAM 等操作
凭据写入 tokenrouter-mfa         无需额外操作
                                36 小时后过期 → 你再跑一次
```

### 6.2 修改 deploy.sh

将 `deploy.sh` 中的 profile 改为 `tokenrouter-mfa`，或添加环境变量支持：

```bash
# deploy.sh 中添加
AWS_PROFILE="${AWS_PROFILE:-tokenrouter-mfa}"
```

### 6.3 Claude Code 调用示例

Claude Code 正常执行命令，只需使用 `--profile tokenrouter-mfa`：

```bash
# 部署
bash deploy/deploy.sh all

# DNS 操作
aws route53 change-resource-record-sets ... --profile tokenrouter-mfa

# Security Group 操作
aws ec2 authorize-security-group-ingress ... --profile tokenrouter-mfa
```

如果凭据过期，Claude Code 会收到 `ExpiredToken` 错误，此时提示你运行 `./scripts/aws-mfa-login.sh` 即可。

## 7. 与 IP 限制的组合方式

### 方案 A：双重防护（IP + MFA 同时满足）

最高安全级别。攻击者必须同时拥有：正确 IP + 物理 YubiKey + Access Key。

```
请求 → IP 白名单检查 → MFA 认证检查 → 执行
        ↓ 不在白名单     ↓ 没有 MFA
        Deny             Deny
```

IAM 用户上两个独立的内联策略：
- `DenyNonWhitelistedIP` — IP 限制
- `RequireMFA` — MFA 强制

两个策略各自独立 Deny，必须同时通过。

### 方案 B：二选一（IP 或 MFA 满足其一即可）

更灵活的方案。在白名单 IP 上直接操作（零摩擦），换了 IP 时用 YubiKey 认证也能访问。

```
请求 → IP 在白名单？ ─── 是 → 执行
        │
        否
        │
        └→ 有 MFA 认证？ ─── 是 → 执行
                │
                否
                │
                Deny
```

将 `DenyNonWhitelistedIP` 和 `RequireMFA` 合并为一个策略：

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
            "aws:SourceIp": [
              "124.195.223.66/32",
              "150.228.211.208/32"
            ]
          },
          "BoolIfExists": {
            "aws:MultiFactorAuthPresent": "false"
          }
        }
      }
    ]
  }' \
  --profile tokenrouter-deploy
```

**关键原理**：IAM Condition 中多个条件键之间是 **AND** 关系。这个 Deny 语句的含义是：当 IP 不在白名单 **且** 没有 MFA 认证时才 Deny。换言之，满足其中任意一个条件就放行。

> 注意：如果从方案 A 切换到方案 B，需要先删除旧的两个独立策略：
> ```bash
> aws iam delete-user-policy --user-name admin --policy-name DenyNonWhitelistedIP --profile tokenrouter-deploy
> aws iam delete-user-policy --user-name admin --policy-name RequireMFA --profile tokenrouter-deploy
> ```

### 方案对比

| | 方案 A（双重） | 方案 B（二选一） |
|--|---------------|----------------|
| 白名单 IP 上操作 | 还需要 MFA | 直接操作，零摩擦 |
| 非白名单 IP 操作 | 不可能 | 用 YubiKey 获取临时凭据即可 |
| IP 变了 | 被锁死，需要 Console 改 Policy | 用 YubiKey 继续工作，不受影响 |
| Access Key 泄露 | 攻击者需要正确 IP + YubiKey | 攻击者需要正确 IP 或 YubiKey |
| 安全级别 | 最高 | 高（推荐） |
| 日常摩擦 | 每天按一次 YubiKey | 仅换 IP 时需要按 YubiKey |

**推荐方案 B**：日常在固定 IP 上零摩擦操作，出差/换网络时用 YubiKey 兜底，不会被锁死。

## 8. 回退方案

### 8.1 YubiKey 丢失

1. 用 root 账号登录 AWS Console
2. IAM → Users → admin → Security credentials
3. 删除旧 MFA 设备
4. 移除 `RequireMFA` 策略（否则 CLI 完全无法使用）
5. 用新 YubiKey 重新注册

### 8.2 临时禁用 MFA 要求

```bash
# 用 root 或其他有权限的用户
aws iam delete-user-policy \
  --user-name admin \
  --policy-name RequireMFA
```

### 8.3 建议

- 保留 root 账号的登录凭据（邮箱 + 密码 + root MFA），仅用于紧急恢复
- 考虑注册一把备用 YubiKey

## 9. 时间线参考

| 持续时间设置 | 每天按 YubiKey 次数 | 适用场景 |
|-------------|-------------------|---------|
| 129600s (36h) | 不到 1 次 | 日常开发（推荐） |
| 86400s (24h) | 1 次 | 每天工作开始时 |
| 43200s (12h) | 1-2 次 | 较高安全要求 |
| 3600s (1h) | 多次 | 高安全环境 |
