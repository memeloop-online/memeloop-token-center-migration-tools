# Memeloop Token Center migration tools

这是一个私有、一次性、离线于生产请求数据面的迁移工具仓库。它保存从旧系统导出、校验、导入、回放和回滚数据所需的 TypeScript 工具、声明式 SQL、合成测试夹具与操作说明。

“离线”表示这些工具不属于 Token Center 运行时，也不会被网关、控制面或 worker 调用；部分获批的迁移步骤仍会连接受控的源、目标数据库或控制 API。仓库本身不包含部署、集群清单、CI 自动部署、真实数据、Secret、密文或可用凭据。

## 安全边界

- 所有脚本只能使用 TypeScript；SQL 只作为声明式迁移输入。
- `tests/fixtures` 整体只含合成数据；其中类似凭据的值带 `fixture-only` 标记，其他标识符和地址也只用于测试，不是可用凭据。
- 凭据只能在获批执行时通过权限收紧的文件或 Secret 管理器注入，禁止提交、打印或放入命令行参数。
- 工具默认 dry-run；任何 apply、restore 或不可逆操作都必须基于已审批的输入摘要、回滚点和迁移窗口单独授权。
- 本仓库不包含 Kubernetes、Argo CD、Helm 或其他部署资源，也不构成任何运行时依赖。

## 来源与完整性

精确来源、Apache-2.0 许可和逐文件 SHA-256 见 [`SOURCE-MANIFEST.json`](SOURCE-MANIFEST.json)。复制的来源文件保持原始字节；本仓库新增的说明、策略和包元数据不列入来源清单。

尚未搬入的 Rust 产品运行时/导入器、历史证据和部署模板见 [`docs/extraction-boundaries.md`](docs/extraction-boundaries.md)。在最终数据对账与双仓审查完成前，不得据此从产品仓库删除源文件。

原样迁入文件中的环境硬编码和大型单体债务见 [`docs/engineering-debt.md`](docs/engineering-debt.md)；在实际复用前必须独立评审，不能因保留了来源校验哈希就视为已经符合当前工程标准。

## 工具范围

- CPAMP 历史与缓存计价修正：`ops/migrate-cpamp.ts`、`ops/sql/cpamp/`。
- CPA 会话增量导出、归档导入包装和迁移对账。
- 最终 session/archive snapshot+delta 封存、审批导入、回放幂等与聚合收据：`ops/finalize-session-archive-delta.ts`；操作边界见 [`docs/final-session-archive-reconciliation.md`](docs/final-session-archive-reconciliation.md)。
- 旧凭据、策略、模型路由和上游账户的严格导入；动态 CPA 源路由清单导出见 [`docs/operations/cpa-source-route-inventory.md`](docs/operations/cpa-source-route-inventory.md)。
- 活跃迁移主键到目标正式余额不受限策略的查询、原子 CAS 迁移和计数/摘要收据。
- 成对 PostgreSQL/对象存储备份、恢复和证据收据。
- 对应的 TypeScript 契约测试与完全合成 fixtures。

## 本地静态验证

需要 Node.js 24.18.0。安装依赖后可运行：

```text
npm run policy
npm run typecheck
npm test
```

PostgreSQL acceptance 默认跳过，只有显式提供隔离 schema 的测试环境变量时才会执行。`ops/import-cpa-session-archive.ts` 目前仍依赖尚未提取的 Rust 可执行导入器，因此只能在边界关闭后作为完整链路使用。
