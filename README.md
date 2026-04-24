# Legend AWS 架构安全加固项目

AWS 基础架构安全加固的文档、工具和脚本集合。

## 目录结构

```
├── docs/          # 安全加固文档、方案和报告
├── scripts/       # 自动化脚本（审计、加固、修复）
├── tools/         # 安全工具和配置
├── policies/      # IAM 策略、SCP、安全策略模板
└── terraform/     # IaC 安全基线配置
```

## 涵盖范围

- IAM 权限最小化与策略审计
- 网络安全（VPC、Security Group、NACL）
- 数据加密（S3、EBS、RDS、KMS）
- 日志与监控（CloudTrail、GuardDuty、Config）
- 合规检查（CIS Benchmark、AWS Well-Architected）
- 应急响应流程

## 使用方式

详见各子目录下的 README。
