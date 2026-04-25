# AWS 架构盘点报告

**Account**: 647828570435 (Hao Chen)  
**Organization**: o-8k3iudj281 (单账号, SCP 已启用)  
**Scan Date**: 2026-04-25  
**Profile**: legend-security-hao  

---

## 1. Executive Summary

| 维度 | 数量 |
|------|------|
| AWS 账号 | 1 |
| 活跃 Region | 5 (us-east-1, eu-west-1, ap-southeast-1, ap-northeast-1, eu-west-3) |
| 生产 Region | 3 (us-east-1, eu-west-1, ap-southeast-1) |
| VPC (自定义) | 15 |
| EC2 实例 | 56 (35 running, 21 stopped) |
| ECS 集群 | 7 (us-east-1: 5, ap-southeast-1: 2) |
| RDS 实例 | 15 |
| 负载均衡器 | 36 |
| S3 Bucket | 52 |
| IAM 用户 | 67 (MFA: 仅 2) |
| IAM 角色 | 145 |
| Route53 域名 | 8 |
| CloudFront 分发 | 10 |

### 核心业务系统识别

| 系统 | 主 Region | 备注 |
|------|----------|------|
| **Legend Trading** | us-east-1 + eu-west-1 + eu-west-3 | 主业务，ECS 36 tasks，跨 3 region 数据复制 |
| **Flashwire / Stellapay** | us-east-1 + ap-southeast-1 | 支付系统，ECS + EC2 混合 |
| **ZingPays** | us-east-1 | MariaDB 为后端 |
| **Lending** | ap-southeast-1 | 借贷系统，独立 VPC |
| **MPC/Custody** (SafeHeron/Cobo) | us-east-1 + ap-southeast-1 | 加密货币托管，MPC 签名 |
| **InfraPay** | eu-west-1 | 独立支付服务 |
| **CuteID** | us-east-1 | AI 相关 |
| **FlowMind** | us-east-1 (Valkey) | 知识管理 |

---

## 2. us-east-1 (N. Virginia) — 主 Region

### 2.1 VPC 拓扑

| VPC ID | Name | CIDR | Subnet 数 | IGW | NAT GW | 用途 |
|--------|------|------|-----------|-----|--------|------|
| vpc-0cc2aa7ac68fbaf61 | lgvpc | 10.0.0.0/16 | 16 | Yes | 3 | Legend Trading 主 VPC |
| vpc-0a8e8be43ee21c493 | zingpays-vpc | 10.100.0.0/16 | 6 | Yes | 2 | ZingPays |
| vpc-0ef64137b97e9eb00 | flashwire | 10.10.0.0/16 | 9 | Yes | 2 | Flashwire |
| vpc-8bd220f2 | (legacy) | 172.30.0.0/16 | 5 | Yes | 0 | 旧 VPC |

### 2.2 EC2 实例 (37 台: 26 running, 11 stopped)

**Production 实例：**

| Name | Type | AZ | State | VPC | 用途 |
|------|------|----|-------|-----|------|
| legend-webapi-amzn2-prod01 | m5a.large | us-east-1a | running | lgvpc | API 服务 |
| legend-webapi-amzn2-prod02 | c5a.xlarge | us-east-1b | running | lgvpc | API 服务 |
| flashwire-prod-web1 | — | us-east-1a | running | flashwire | Web 服务 |
| flashwire-prod-web2 | — | us-east-1b | running | flashwire | Web 服务 |
| flashwire-prod-crontab | — | us-east-1a | running | flashwire | 定时任务 |
| legend-safeheron-mpc01 | — | us-east-1a | running | lgvpc | MPC 签名 |
| legendpay-ai01 | — | us-east-1a | running | lgvpc | AI 工作负载 |
| claudecode-dev-hao | m6i.4xlarge | us-east-1a | running | lgvpc | 开发机 |

### 2.3 ECS 集群 (5 集群, 43 running tasks)

| Cluster | Tasks | Services | 说明 |
|---------|-------|----------|------|
| legendtrading | 36 | 15 | **主生产集群** |
| flashwire | 6 | 3 | Flashwire 生产 |
| lg-ops-cluster | 1 | 1 | 运维 API (Fargate) |
| test-lg | 0 | 0 | 测试 |
| test-cluster | 0 | 0 | 测试 |

**EKS**: 1 个集群

### 2.4 负载均衡器 (25 ELBv2)

| 类型 | Scheme | 数量 | 说明 |
|------|--------|------|------|
| ALB | internet-facing | ~12 | 主要流量入口 |
| ALB | internal | ~6 | 内部服务 |
| NLB | internet-facing | ~7 | **含暴露数据库端口!** |

**流量路径 (外网 → 内部)：**

```
Route53 (legendtrading.com)
  → CloudFront (asset.legendtrading.com)
    → S3 Origin (静态资源)

Route53 (legendtrading.com)
  → ALB-legendtrading-com (internet-facing, HTTPS 443)
    → Target Group
      → ECS-legendtrading (36 tasks)
        → RDS-lg-rds-production (MySQL 8.0, Multi-AZ)
        → ElastiCache-legendtrading (Redis)

Route53 (flashwire.com)
  → ALB-flashwire-web-lb
    → EC2-flashwire-prod-web1/web2
      → RDS-lg-rds-production
```

### 2.5 数据层

**RDS (6 实例)：**

| Identifier | Engine | Class | Multi-AZ | 状态 | 说明 |
|------------|--------|-------|----------|------|------|
| lg-rds-production | MySQL 8.0.45 | db.m6g.xlarge | Yes | available | **主生产库** |
| replica-lg-rds-production | MySQL 8.0.45 | db.t4g.medium | No | available | 读副本 |
| legend-us-production-backup | MySQL | db.t3.medium | No | available | 备份 |
| flashwire-staging-env | MySQL | db.t3.medium | No | available | Staging |
| mariadb-zingpays | MariaDB 10.6.25 | db.t3.small | No | available | ZingPays |
| lg-va-test-deletion-20251216 | — | — | — | stopped | 待删除 |

**ElastiCache**: 7 节点 (6x Redis cache.r6g.large + 1x Valkey cache.t4g.micro "flowmind")

**OpenSearch**: 2 域 (movies: m6g.large + ses-monitor: t3.small)

**EFS**: 3 文件系统 (legend-dev, flashwireasset, legendasset)

### 2.6 安全状况

- **96 条 0.0.0.0/0 入站规则** — SSH, MySQL, Redis, RDP, AD 端口全部对公网开放
- **4 个 NLB 公网暴露 MySQL** — 严重风险
- GuardDuty: **未启用**
- WAF: 1 个 regional ACL
- CloudTrail: 2 trails (multi-region)
- Secrets Manager: 14 secrets
- SSM Parameters: 32
- KMS: 17 keys
- CloudWatch: 29 alarms, 43 log groups

---

## 3. eu-west-1 (Ireland) — DR / 欧洲节点

### 3.1 VPC 拓扑

| VPC ID | Name | CIDR | Subnet 数 | IGW | NAT GW |
|--------|------|------|-----------|-----|--------|
| vpc-03cc70f7b5668f3c7 | legendtrading-IE-vpc | 10.1.0.0/16 | 8 | Yes | 3 |
| vpc-7317ed16 | (default) | 172.31.0.0/16 | 3 | Yes | 0 |

### 3.2 EC2 实例 (9 台: 7 running, 2 stopped)

| Name | Type | State | 用途 |
|------|------|-------|------|
| IE-legend-api-prod01 | — | running | 爱尔兰 API 服务 |
| IE-legend-api-prod02 | — | running | 爱尔兰 API 服务 |
| IE-legend-queue-prod01 | — | running | 队列处理 |
| IE-legend-backend-sandbox01 | — | running | Sandbox |
| IE-legend-backend-dev01 | — | running | 开发 |
| EU-IE-legend-infrapay-prod-web01 | — | running | InfraPay 生产 |
| EU-IE-legend-infrapay-prod-queue01 | — | running | InfraPay 队列 |

### 3.3 负载均衡

- 1 个 **internal ALB** (`legend`)，1 个 Target Group
- 无 internet-facing LB（流量通过其他方式进入）

### 3.4 数据层

**RDS (6 实例)：**

| Identifier | Class | Multi-AZ | 说明 |
|------------|-------|----------|------|
| lg-ie-production | db.m6g.large | Yes | **IE 生产主库** |
| replica-lg-rds-production-global | db.m6g.large | Yes | **从 us-east-1 跨 region 复制** |
| replica-lg-ie-production-data-analysis | db.t4g.medium | No | 分析副本 |
| lg-ie-development | db.t4g.medium | No | 开发 |
| lg-ie-development-global-read | db.t4g.small | No | 全局读副本 |
| lg-ie-test-deletion-20251216 | — | — | 待删除 |

**ElastiCache**: 2 Redis 节点 (cache.m7g.large, replication group "legendtrading")

### 3.5 安全状况

- 仅 3 条 0.0.0.0/0 规则 (HTTP 80, HTTPS 443, SSH 22) — 相对安全
- GuardDuty: **未启用**
- WAF: 无
- CloudTrail: 共享 multi-region trails

---

## 4. ap-southeast-1 (Singapore) — 亚太节点

### 4.1 VPC 拓扑

| VPC ID | Name | CIDR | Subnet 数 | IGW | NAT GW | 用途 |
|--------|------|------|-----------|-----|--------|------|
| vpc-0e8a205860906c944 | lending | 10.30.0.0/16 | 10 | Yes | 2 | 借贷系统 |
| vpc-021391a2d0eadb6b1 | mpc | 10.21.0.0/16 | 6 | Yes | 2 | MPC 签名 |
| vpc-0b7fe214033d48811 | internal-system | 10.20.0.0/16 | 3 | Yes | 1 | 内部系统 |
| vpc-0a772f108977d9208 | crossborder-payment | 10.22.0.0/16 | 1 | Yes | 0 | 跨境支付 |
| vpc-0c3712644ef5a4efb | vpn-sg-vpc | 10.101.0.0/24 | 2 | No | 0 | **VPN Hub** |
| vpc-84f318e1 | (default) | 172.31.0.0/16 | 3 | Yes | 0 | 默认 |

### 4.2 VPC Peering — VPN Hub 架构

**vpn-sg-vpc (10.101.0.0/24)** 是连接枢纽，有 **10 个活跃 Peering 连接**：

```
                    ┌─────────────────────┐
                    │   vpn-sg-vpc        │
                    │   10.101.0.0/24     │
                    │   (VPN Hub, No IGW) │
                    └──────┬──────────────┘
                           │
        ┌──────────┬───────┼───────┬──────────┐
        ▼          ▼       ▼       ▼          ▼
  internal-sys  lending   mpc   crossborder  ┌──────────────┐
  10.20.0.0/16  10.30/16  10.21  10.22/16    │ us-east-1    │
                                              │ lgvpc 10.0/16│
                                              │ flashwire    │
                                              │ zingpays     │
                                              └──────────────┘
```

### 4.3 EC2 实例 (10 台: 2 running, 8 stopped)

| Name | Type | State | VPC |
|------|------|-------|-----|
| lending-web01 | t3.medium | **running** | lending |
| lending-staging01 | t3.small | **running** | lending |
| cobo-mpc01/02/testing01 | c6i.xlarge | stopped | mpc |
| is-1token-app/auth | c5.2xlarge/c5.large | stopped | internal-system |
| payment-dev-windows | c5.xlarge | stopped | crossborder-payment |
| lending-web02 | t3.medium | stopped | lending |

### 4.4 ECS (2 集群, 17 running tasks)

| Cluster | Tasks | Services | Launch Type |
|---------|-------|----------|-------------|
| flashwire | 16 | 6 | **EXTERNAL** |
| flashwire-lending | 1 | 1 | EXTERNAL |

Services: mps-admin, stellapay-mobile, flashwire-zingtech, cadvisor, stellapay-admin, stellapay-mini-app, lending-admin

### 4.5 负载均衡器 (10 ELBv2)

- 3 ALB (internet-facing): lending, camapp, lending-staging
- 7 NLB (internet-facing): **4 个暴露 MySQL 端口!**

### 4.6 数据层

**RDS (3 实例):**

| Identifier | Class | Multi-AZ | 说明 |
|------------|-------|----------|------|
| replication-lg-rds-production | db.m6g.large | Yes | **从 us-east-1 跨 region 复制** |
| lending-web-production | db.t4g.small | No | Lending 生产库 |
| replica-flashwire-staging-env | db.t3.medium | No | Flashwire staging 副本 |

**ElastiCache**: 1 Redis (cache.t3.micro, "lending")
**OpenSearch**: flashwire-logs (m6g.large)

### 4.7 安全状况

- **payment-dev-needs SG**: MySQL(3306), SSH(22), HTTP/S, 3000, 3001 全部对公网开放
- **windows-remote-desktop SG**: RDP(3389) 对公网开放
- **4 个 NLB 公网暴露 MySQL**
- EC2 无 IAM Instance Profile
- GuardDuty: **未启用**
- 过期 ACM 证书仍在使用

---

## 5. ap-northeast-1 (Tokyo) — 测试环境

### 5.1 VPC 拓扑

| VPC ID | Name | CIDR | 说明 |
|--------|------|------|------|
| vpc-06105f1cfd173e343 | terraform-test | 192.168.0.0/16 | Terraform 测试，2 subnet |
| vpc-0ed8b0c85bd3d6ee2 | test | 10.200.0.0/16 | VPN 测试，1 subnet |
| vpc-a3be4fc6 | (default) | 172.31.0.0/16 | 默认 |

**无任何计算、数据、负载均衡资源。** 纯测试 VPC，无实际工作负载。

---

## 6. eu-west-3 (Paris) — 数据复制节点

### 6.1 VPC 拓扑

| VPC ID | Name | CIDR | 说明 |
|--------|------|------|------|
| vpc-02775b0dac0fb2ea5 | legendtrading-FR-vpc | 10.2.0.0/16 | 4 subnet (2 public + 2 private) |
| vpc-e720338e | (default) | 172.31.0.0/16 | 默认 |

### 6.2 跨 Region 连接

```
legendtrading-FR-vpc (10.2.0.0/16)
  ├── VPC Peering → lgvpc us-east-1 (10.0.0.0/16)     "FR-to-VA"
  └── VPC Peering → legendtrading-IE eu-west-1 (10.1.0.0/16)  "FR-to-IE"
```

### 6.3 数据层

- **RDS**: `replica-lg-ie-production` (db.t4g.micro, MySQL 8.0.45) — 从 eu-west-1 跨 region 复制
- **KMS**: 1 key (用于 RDS 加密)
- 无计算资源

---

## 7. 全局视图

### 7.1 跨 Region 数据流

```
                    ┌──────────────────┐
                    │   us-east-1      │
                    │ lg-rds-production│
                    │ (Primary, M-AZ)  │
                    └────┬────────┬────┘
                         │        │
              RDS Replica│        │RDS Replica
                         ▼        ▼
              ┌──────────────┐  ┌──────────────────┐
              │ eu-west-1    │  │ ap-southeast-1   │
              │ replica-     │  │ replication-     │
              │ global       │  │ lg-rds-prod      │
              │ (M-AZ)       │  │ (M-AZ)           │
              └──────┬───────┘  └──────────────────┘
                     │
           RDS Replica│
                     ▼
              ┌──────────────┐
              │ eu-west-3    │
              │ replica-     │
              │ lg-ie-prod   │
              └──────────────┘
```

### 7.2 VPC CIDR 分配矩阵

| Region | VPC Name | CIDR | 说明 |
|--------|----------|------|------|
| us-east-1 | lgvpc | 10.0.0.0/16 | 主 VPC |
| us-east-1 | flashwire | 10.10.0.0/16 | Flashwire |
| us-east-1 | zingpays-vpc | 10.100.0.0/16 | ZingPays |
| us-east-1 | (legacy) | 172.30.0.0/16 | 旧 VPC |
| eu-west-1 | legendtrading-IE-vpc | 10.1.0.0/16 | 爱尔兰 |
| eu-west-3 | legendtrading-FR-vpc | 10.2.0.0/16 | 巴黎 |
| ap-southeast-1 | internal-system | 10.20.0.0/16 | 内部系统 |
| ap-southeast-1 | mpc | 10.21.0.0/16 | MPC 签名 |
| ap-southeast-1 | crossborder-payment | 10.22.0.0/16 | 跨境支付 |
| ap-southeast-1 | lending | 10.30.0.0/16 | 借贷 |
| ap-southeast-1 | vpn-sg-vpc | 10.101.0.0/24 | VPN Hub |
| ap-northeast-1 | terraform-test | 192.168.0.0/16 | 测试 |
| ap-northeast-1 | test | 10.200.0.0/16 | 测试 |

CIDR 规划清晰：10.0/16 (VA), 10.1/16 (IE), 10.2/16 (FR), 10.20-30/16 (SG), 10.100/16 (ZingPays)

### 7.3 IAM 信任关系摘要

| 信任类型 | 数量 | 说明 |
|----------|------|------|
| AWS 服务 | 127 | EKS, ECS, Lambda, EC2, SSM 等标准服务角色 |
| Cognito Identity | 9 | OpenSearch + Identity Pool |
| EKS OIDC | 5 | EKS Workload Identity |
| SAML/SSO | 2 | AWSReservedSSO 角色 |
| 同账号 IAM | 5 | 内部跨角色信任 |
| 外部账号 | 0 | 无外部账号信任 |

### 7.4 Route53 域名

| 域名 | 类型 | Records | 主要用途 |
|------|------|---------|---------|
| legendtrading.com | public | 11 | 主业务域名 |
| flashwire.com | — | — | 支付平台 |
| flowmind.life | public | 25 | 知识管理 |
| rpzzing.net | public | 18 | — |
| mybrains.app | public | 9 | — |
| legendpay.com | public | 3 | 支付 |
| hot.bot | public | 3 | — |
| legendtrading.co.za | public | 2 | 南非 |
| us-east-1.aoss.amazonaws.com | **private** | 3 | OpenSearch Serverless |

### 7.5 CloudFront 分发

| 域名 | Origin | 说明 |
|------|--------|------|
| static.flashwire.com | S3 | 静态资源 |
| asset.flashwire.com | S3 | 资产 |
| asset.legendtrading.com | S3 | 资产 |
| asset.treasurebox.com | S3 | 资产 |
| download.stellapay.io | S3 | 下载 |
| nexus.legendpay.com / nexus2 | ALB | 动态请求 |
| 4 distributions | — | 无自定义域名 |

---

## 8. 依赖关系邻接表 (Draw.io 关键输入)

完整邻接表见 [dependencies.csv](dependencies.csv)。核心依赖：

| 源资源 | 目标资源 | 关系类型 | 说明 |
|--------|---------|---------|------|
| Route53 | CloudFront | alias | DNS → CDN |
| CloudFront | S3 | origin | 静态资源 |
| CloudFront-nexus | ALB | origin | 动态请求 |
| ALB-legendtrading | ECS-legendtrading | forward | HTTPS 443 |
| ALB-flashwire | EC2-flashwire-prod | forward | HTTPS 443 |
| ECS-legendtrading | RDS-lg-rds-production | egress | MySQL 3306 |
| ECS-legendtrading | ElastiCache | egress | Redis 6379 |
| RDS-prod(us-east-1) | RDS-replica(eu-west-1) | replication | 跨 region |
| RDS-prod(us-east-1) | RDS-replica(ap-southeast-1) | replication | 跨 region |
| RDS-ie-prod(eu-west-1) | RDS-replica(eu-west-3) | replication | 跨 region |
| VPC-FR | VPC-VA | peering | 10.2↔10.0 |
| VPC-FR | VPC-IE | peering | 10.2↔10.1 |
| vpn-sg-vpc | 6 VPCs | peering | VPN Hub |
| NLB (多个) | RDS/EC2 | forward | **MySQL 公网暴露!** |

---

## 9. 风险点摘要

详见 [risks.md](risks.md)。

| 级别 | 数量 | 最重要的 |
|------|------|---------|
| **严重** | 2 | 数据库端口公网暴露 (8 个 NLB)、安全组 96 条 0.0.0.0/0 规则 |
| **高危** | 4 | IAM MFA 3% 覆盖率、GuardDuty 未启用、Security Hub 不可用、EC2 无 IAM Role |
| **中危** | 7 | 过期证书、资源未清理、CloudTrail 验证缺失、无 Config、ECS EXTERNAL、S3 endpoint 宽松、无 WAF |
| **低危** | 2 | 跨 region 路由确认、S3 bucket 检查 |
