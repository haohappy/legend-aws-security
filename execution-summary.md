# 执行总结

**Scan Date**: 2026-04-25
**Profile**: legend-security-hao
**Account**: 647828570435 (Hao Chen)

## 执行概况

| 指标 | 数量 |
|------|------|
| 探测 Region 数 | 17 |
| 活跃 Region 数 | 5 |
| 深度盘点 Region 数 | 5 |
| 执行的 AWS API 调用 | ~400+ |
| 产出 raw JSON 文件 | ~250+ |
| 产出报告文件 | 6 |
| Permission Gap | 2 (SecurityHub in us-east-1 + eu-west-1) |

## 产出文件清单

| 文件 | 说明 |
|------|------|
| `architecture.md` | 主架构报告 |
| `active-regions.md` | 活跃 Region 清单 |
| `dependencies.csv` | 依赖关系邻接表 (draw.io 输入) |
| `risks.md` | 风险点与建议 (15 项) |
| `permission-gaps.md` | 无权限 API 记录 |
| `execution-summary.md` | 本文件 |
| `raw/global/` | 全局服务 raw JSON (11 文件) |
| `raw/us-east-1/` | us-east-1 raw JSON (~62 文件) |
| `raw/eu-west-1/` | eu-west-1 raw JSON (~62 文件) |
| `raw/ap-southeast-1/` | ap-southeast-1 raw JSON (~75 文件) |
| `raw/ap-northeast-1/` | ap-northeast-1 raw JSON (~43 文件) |
| `raw/eu-west-3/` | eu-west-3 raw JSON (~43 文件) |

## 最值得关注的 5 个发现

### 1. 数据库端口公网暴露 — 严重
8 个 internet-facing NLB 直接将 MySQL/MariaDB 3306 端口暴露到公网 (us-east-1 + ap-southeast-1)。这是最紧急需要修复的安全问题。

### 2. IAM 用户 MFA 覆盖率仅 3% — 高危
67 个 IAM 用户中仅 2 个启用了 MFA，55 个拥有活跃 Access Key。一旦 Key 泄露即可直接操作 AWS 资源。

### 3. 多 Region 数据复制架构
Legend Trading 核心数据库 (lg-rds-production) 从 us-east-1 复制到 eu-west-1 和 ap-southeast-1，eu-west-1 又复制到 eu-west-3，形成 4 region 数据复制链。这是有意为之的灾备架构。

### 4. ap-southeast-1 VPN Hub 架构
vpn-sg-vpc (10.101.0.0/24) 作为 VPN 枢纽，通过 10 个 VPC Peering 连接本地 4 个业务 VPC + 远程 us-east-1 的 3 个 VPC。是全架构的网络核心节点。

### 5. GuardDuty / Security Hub 全部未启用
5 个活跃 Region 均无威胁检测能力。结合前述的开放安全组和公网暴露数据库，安全态势堪忧。

## CIDR 规划总结

```
10.0.0.0/16    us-east-1     lgvpc (Legend Trading VA)
10.1.0.0/16    eu-west-1     legendtrading-IE-vpc
10.2.0.0/16    eu-west-3     legendtrading-FR-vpc
10.10.0.0/16   us-east-1     flashwire
10.20.0.0/16   ap-southeast-1 internal-system
10.21.0.0/16   ap-southeast-1 mpc
10.22.0.0/16   ap-southeast-1 crossborder-payment
10.30.0.0/16   ap-southeast-1 lending
10.100.0.0/16  us-east-1     zingpays-vpc
10.101.0.0/24  ap-southeast-1 vpn-sg-vpc (Hub)
10.200.0.0/16  ap-northeast-1 test
172.30.0.0/16  us-east-1     legacy
192.168.0.0/16 ap-northeast-1 terraform-test
```
