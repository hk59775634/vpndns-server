# 管理控制台 UI（云控制台风格）

静态资源位于 `cmd/server/web/static/`：`index.html` + `css/console.css`，由 `cmd/server` 嵌入，**不增加独立前端构建链**。

## 组件结构（概念）

- **Shell**：`#app-layout`（侧栏可折叠 `sidebar-collapsed`）+ `header.console-topbar` + `main`
- **导航**：`aside nav button[data-page]`，分组标签 `.nav-group-label`
- **顶栏**：`#page-title`、`#console-region-label` / `#console-region-sub`（来自 `GET /api/v1/meta` 的 `listen`）、`#health-pill`、用户菜单 `#user-menu-dd`
- **抽屉**：`#drawer-backdrop` + `#app-drawer`（白名单查看/编辑）
- **确认框**：`#confirm-modal` + `openConfirm(message)`（Promise）
- **DNS 白名单**：`#wl-table` + `#wl-list-tbody`（查看 / 编辑 / 删除 / 更多·复制）
- **DNS 缓存表**：`parseDnsCacheKey` 解析 `dns:域名:类型:global|ecs:…` 展示域名、类型、TTL、来源

## API

与此前完全一致：`/api/v1/*`、Cookie 会话、可选 `X-API-Key`。

## 若将来迁移到 React / Vue

可将上述区域拆为 `Layout`、`SideNav`、`TopBar`、`DataTable`、`Drawer`、`ConfirmDialog`；数据层保持现有 `fetch` 封装与 URL 不变即可。
