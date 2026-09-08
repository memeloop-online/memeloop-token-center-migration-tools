# Memeloop Token Center migration tools

这是一个公开可复用、一次性、隔离于生产请求数据面的迁移工具仓库。它提供严格的 TypeScript 工具、声明式 SQL 输入、合成测试夹具与操作说明，用于在一次经过审批的迁移窗口内导出、校验、导入、回放和对账。

“一次性”表示每次执行都绑定到一组明确的 owner-reviewed 输入、摘要和回滚边界；它不是常驻服务或通用数据同步器。“隔离”表示这些工具不属于 Token Center 运行时，也不会被网关、控制面或 worker 调用；获批的迁移步骤仍可能连接受控的源、目标数据库或控制 API。仓库本身不包含部署、集群清单、真实业务数据、Secret、密文、可用凭据或运行时证据。

## 安全边界

- 所有脚本只能使用 TypeScript；SQL 只作为声明式迁移输入。
- `tests/fixtures` 整体只含合成数据；其中类似凭据的值带 `fixture-only` 标记，其他标识符和地址也只用于测试，不是可用凭据。
- 凭据只能在获批执行时通过权限收紧的文件或 Secret 管理器注入，禁止提交、打印或放入命令行参数。
- 工具默认 dry-run；任何 apply、restore 或不可逆操作都必须基于已审批的输入摘要、回滚点和迁移窗口单独授权。
- 本仓库不包含 Kubernetes、Argo CD、Helm 或其他部署资源，也不构成任何运行时依赖。

## 公开复用与数据边界

公开的是代码、文档、许可证和合成 fixtures，不是任何环境的访问权。以下内容永远留在获批的外部证据/Secret 系统，不得提交到本仓库：

- 业务数据库、SQLite/CPAMP/archive 导出、请求/会话/对象内容、生产 key、grant、余额和身份映射；
- API key、OAuth/API/数据库/对象存储凭据、私钥、密文、PGPASS、Kubernetes Secret 值和 registry 登录材料；
- 动态 source/target inventory、route/policy mapping、checkpoint、plan、receipt、运行日志、截图及其他迁移 evidence。

运行时只接收 owner-approved、权限收紧且通常为 `0600` 的输入文件或 Secret 引用。输出仅允许写入受保护的临时/证据目录；公共仓库最多记录不含业务内容的规范、版本和摘要规则。动态数量不能变成 CI 或 manifest 中的固定成功条件。

## 来源与完整性

精确来源、Apache-2.0 许可和逐文件 SHA-256 见 [`SOURCE-MANIFEST.json`](SOURCE-MANIFEST.json)。复制的来源文件保持原始字节；本仓库新增的说明、策略和包元数据不列入来源清单。

尚未搬入的 Rust 产品运行时/导入器、历史证据和部署模板见 [`docs/extraction-boundaries.md`](docs/extraction-boundaries.md)。在最终数据对账与双仓审查完成前，不得据此从产品仓库删除源文件。

原样迁入文件中的环境硬编码和大型单体债务见 [`docs/engineering-debt.md`](docs/engineering-debt.md)；在实际复用前必须独立评审，不能因保留了来源校验哈希就视为已经符合当前工程标准。

当前 CLI、文件名和输入字段仍保留 `Memeloop Token Center`/`CPA` 的来源专名，以保持正在进行的迁移链路兼容。去除这些专名、引入通用 provider/source/target 适配层、或改变命令别名属于明确的后续兼容性工作；在独立版本化适配器、迁移夹具和双仓审查完成前，不要重命名现有 CLI 或文件。

## 工具范围

- CPAMP 历史与缓存计价修正：`ops/migrate-cpamp.ts`、`ops/sql/cpamp/`。
- CPA 会话增量导出、归档导入包装和迁移对账。
- 最终 session/archive snapshot+delta 封存、审批导入、回放幂等与聚合收据：`ops/finalize-session-archive-delta.ts`；操作边界见 [`docs/final-session-archive-reconciliation.md`](docs/final-session-archive-reconciliation.md)。
- 旧凭据、策略、模型路由和上游账户的严格导入；动态 CPA 源路由清单导出见 [`docs/operations/cpa-source-route-inventory.md`](docs/operations/cpa-source-route-inventory.md)。
- Provider-exact 策略输入生成器在已审核的原生路由回放后，交叉校验完整源策略、源清单、原生候选池、路由清单和目标路由回执，再生成待复核的路由清单/策略映射；它不写目标 API，也不会把任何源密钥散列写入输出。
- 活跃迁移主键到目标正式余额不受限策略的查询、原子 CAS 迁移和计数/摘要收据。
- 成对 PostgreSQL/对象存储备份、恢复和证据收据。
- 对应的 TypeScript 契约测试与完全合成 fixtures。

## CI 验证

完整验证只在 CI 的干净 checkout 中运行；CI 使用 Node.js 24.18.0，安装锁定依赖后执行：

```text
npm run policy
npm run typecheck
npm test
```

PostgreSQL acceptance 默认跳过，只有显式提供隔离 schema 的测试环境变量时才会执行。`ops/import-cpa-session-archive.ts` 目前仍依赖尚未提取的 Rust 可执行导入器，因此只能在边界关闭后作为完整链路使用。本地不安装依赖、不拉取源码、不接触真实源/目标数据；本地验证仅限 `git diff --check`。

## 固定 digest 的执行模型

正式执行应使用 CI 为某个完整 Git revision 构建并验证的容器 digest，以及对应的 immutable manifest、SBOM 和 provenance。部署或迁移记录应保存 revision、image digest 和非敏感 evidence digest；禁止使用 mutable tag、未经验证的重建镜像或把公共仓库内容当作运行时输入。

依赖在 CI/build 阶段由锁定的 `package-lock.json` 解析，最终镜像只复制经过 allowlist 的 TypeScript entrypoints 和必要运行库。不要在通用 `node` 镜像中启动时 `git clone`、下载源码、运行 `npm install`/`npm ci` 或解析未锁定依赖：这会使同一 revision 得到不同代码/依赖闭包，扩大运行时网络和凭据暴露面，并绕过镜像 digest、SBOM 与 provenance 的审计边界。CI 是唯一可复现的验证/执行入口；本地仅做 `git diff --check`。
