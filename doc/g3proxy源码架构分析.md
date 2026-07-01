# g3proxy v1.12.3 源码架构分析

> 字节跳动开源 · Apache 2.0 · Rust Async 企业级代理解决方案

---

## 目录

1. [项目定位](#1-项目定位)
2. [整体架构](#2-整体架构)
3. [核心三大组件](#3-核心三大组件)
4. [启动流程（逐行解读）](#4-启动流程逐行解读)
5. [请求处理全链路](#5-请求处理全链路)
6. [模块详解](#6-模块详解)
7. [配置系统](#7-配置系统)
8. [依赖库生态](#8-依赖库生态)
9. [关键设计决策](#9-关键设计决策)
10. [快速速查表](#10-快速速查表)

---

## 1. 项目定位

g3proxy 是 G3 项目群中的旗舰应用——一个**用 Async Rust 编写**的企业级通用正向代理，同时附带 TCP 映射、TLS 卸载/封装、透明代理、简单反向代理等能力。

### 一句话概括

> 一个可以同时监听多种代理协议（HTTP/SOCKS/SNI/TCP），通过丰富的出口路由策略将流量转发到上游，并支持 TLS 中间人劫持 + ICAP 审计的企业级代理。

### 核心能力矩阵

| 能力 | 说明 |
|------|------|
| **入口协议** | HTTP/1.x 正向代理、SOCKS4/5 代理、SNI 代理、TCP 流代理、FTP 代理、透明代理（TPROXY） |
| **TLS 栈** | OpenSSL / BoringSSL / AWS-LC / AWS-LC-FIPS / Tongsuo（国密）、部分场景支持 rustls |
| **出口策略** | 18 种出口类型 + 9 种路由选择器，支持代理串联 |
| **TLS 中间人** | TLS 劫持、解密流量导出、HTTP1/HTTP2/IMAP/SMTP 协议解析 |
| **审计集成** | ICAP (REQMOD/RESPMOD) 适配，无缝对接第三方安全审计/杀毒产品 |
| **运维能力** | 优雅重载（SIGHUP）、热升级、Ansible 部署、Cap'n Proto 控制接口 |
| **用户管理** | 静态/Dynamic（Lua/Python/Redis 动态加载）用户源、站点级差异化配置 |
| **可观测性** | StatsD 打点、多维度指标（入口/出口/用户/站点）、多种日志后端 |

---

## 2. 整体架构

```
                        ┌──────────────────────────────────┐
                        │           g3proxy 主进程           │
                        │                                   │
    ┌───────┐           │  ┌─────────┐     ┌───────────┐   │
    │ 客户端  │──TCP/UDP──►│ Server  │────►│  Escaper  │───┼──► 目标服务器
    └───────┘           │  │ (15种)  │     │  (19种)   │   │
                        │  └────┬────┘     └─────┬─────┘   │
                        │       │                │         │
                        │       │    ┌───────────┘         │
                        │       ▼    ▼                     │
                        │  ┌──────────────┐                │
                        │  │   Resolver   │  DNS 解析       │
                        │  │    (4种)     │                │
                        │  └──────────────┘                │
                        │                                   │
                        │  ┌──────────────────────────────┐ │
                        │  │     Auditor (审计/拦截)       │ │
                        │  │  TLS 中间人 → ICAP 适配      │ │
                        │  └──────────────────────────────┘ │
                        │                                   │
                        │  ┌──────────────────────────────┐ │
                        │  │     UserGroup (认证/授权)     │ │
                        │  │  ACL / 限流 / 站点配置        │ │
                        │  └──────────────────────────────┘ │
                        └──────────────────────────────────┘
```

架构遵循 **组件化 + 依赖拓扑排序** 的设计理念：

- **Server（入口）** 负责接受连接、协议识别、用户认证
- **Escaper（出口）** 负责建立上游连接、路由选择
- **Resolver（解析）** 负责 DNS 解析
- **Auditor（审计）** 负责协议检测、TLS 拦截、ICAP 审计
- **UserGroup（用户）** 负责认证、ACL、限流

组件间**显式声明依赖关系**，通过 `TopoMap`（拓扑图）在加载/重载时自动按依赖顺序处理。

---

## 3. 核心三大组件

### 3.1 Server — 入口层（15 种）

每种 Server 对应一种入口协议或接入方式：

| Server 类型 | 用途 | 关键文件 |
|------------|------|---------|
| `http_proxy` | HTTP/HTTPS 正向代理（CONNECT 隧道） | `serve/http_proxy/` |
| `socks_proxy` | SOCKS4/4a/5 代理 | `serve/socks_proxy/` |
| `sni_proxy` | SNI 路由代理（按 TLS SNI 分流） | `serve/sni_proxy/` |
| `tcp_stream` | 原始 TCP 流代理 | `serve/tcp_stream/` |
| `tls_stream` | TLS 卸载/封装代理 | `serve/tls_stream/` |
| `ftp_proxy` | FTP 代理 | `serve/ftp_proxy/` |
| `intelli_proxy` | 智能多协议入口（自动检测协议类型） | `serve/intelli_proxy/` |
| `http_rproxy` | HTTP 反向代理 | `serve/http_rproxy/` |
| `tcp_tproxy` | TCP 透明代理（Linux/FreeBSD TPROXY） | `serve/tcp_tproxy/` |
| `plain_tcp_port` | 普通 TCP 端口监听 | `serve/plain_tcp_port/` |
| `plain_tls_port` | 普通 TLS 端口（rustls） | `serve/plain_tls_port/` |
| `native_tls_port` | 原生 TLS 端口（OpenSSL） | `serve/native_tls_port/` |
| `plain_quic_port` | QUIC 端口 | `serve/plain_quic_port/` |
| `dummy_close` | 虚拟关闭服务器（测试用） | `serve/dummy_close/` |

**核心 Trait：**

```rust
// src/serve/mod.rs
pub trait Server: BaseServer + AcceptTcpServer + AcceptQuicServer { }
pub(crate) trait ServerInternal: Send + Sync {
    fn name(&self) -> &str;
    fn version(&self) -> usize;
    /// 是否需要依赖其他 Server
    fn depends_on(&self) -> Option<&[Name]> { None }
    /// 启动 TCP 监听
    async fn run_tcp(self: Arc<Self>, listener: TcpListener, ...) -> Result<()>;
    /// 启动 QUIC 监听
    async fn run_quic(self: Arc<Self>, listener: QuicListener, ...) -> Result<()>;
    /// 热重载：根据新旧配置差异决定操作
    fn reload(self: Arc<Self>, new: AnyServerConfig) -> Result<ArcServer>;
}
```

### 3.2 Escaper — 出口层（19 种）

出口决定流量如何离开代理。分为**基础出口**和**路由出口**两类。

**基础出口（直接连接/代理串联）：**

| Escaper 类型 | 用途 |
|-------------|------|
| `direct_fixed` | 固定地址直连 |
| `direct_float` | 动态地址直连（解析后连接） |
| `divert_tcp` | TCP 分流 |
| `proxy_http` | 通过上游 HTTP 代理转发 |
| `proxy_https` | 通过上游 HTTPS 代理转发 |
| `proxy_socks5` | 通过上游 SOCKS5 代理转发 |
| `proxy_socks5s` | 通过上游 SOCKS5s（TLS）代理转发 |
| `proxy_float` | 动态选择上游代理 |
| `trick_float` | 欺骗性出口（测试用） |
| `dummy_deny` | 直接拒绝（黑名单） |
| `comply_audit` | 合规审计出口 |

**路由出口（流量分发）：**

| Route 类型 | 用途 |
|-----------|------|
| `route_client` | 按客户端 IP 地址路由 |
| `route_failover` | 故障转移（主备切换） |
| `route_geoip` | 按目标 GeoIP 归属路由 |
| `route_mapping` | 按用户指定规则路由 |
| `route_query` | 调用外部 Agent 查询路由决策 |
| `route_resolved` | 按 DNS 解析后 IP 路由 |
| `route_select` | 简单负载均衡（轮询/随机/一致性哈希） |
| `route_upstream` | 按目标地址（IP/端口）路由 |

**核心 Trait：**

```rust
// src/escape/mod.rs
pub trait Escaper: Send + Sync {
    fn name(&self) -> &str;
    /// 建立目标 TCP 连接
    async fn tcp_connect(&self, ctx: &EscaperContext, ...) -> TcpConnectResult;
    /// 建立目标 UDP 连接
    async fn udp_connect(&self, ctx: &EscaperContext, ...) -> UdpConnectResult;
}
```

### 3.3 Resolver — DNS 解析层（4 种）

| Resolver 类型 | 用途 | 特性 |
|--------------|------|------|
| `c_ares` | c-ares C 库异步解析 | 高性能、企业级 |
| `hickory` | Rust 原生 DNS 解析 | 支持 UDP/TCP/DoT/DoH/DoH3 |
| `fail_over` | 故障转移组合解析器 | 主备切换 |
| `deny_all` | 全拒绝解析器 | 测试/安全场景 |

**核心 Trait：**

```rust
// src/resolve/mod.rs
pub trait Resolver: Send + Sync {
    fn name(&self) -> &str;
    async fn resolve(&self, host: &Host, port: u16) -> ResolveResult;
}
```

---

## 4. 启动流程（逐行解读）

启动入口在 `g3proxy/src/main.rs`，流程如下：

```
main()
 │
 ├─[1] 初始化加密库
 │   ├── openssl_probe::init_openssl_env_vars()   # 探测 OpenSSL 环境变量
 │   ├── openssl::init()                          # 初始化 OpenSSL
 │   └── rustls 加密后端安装                       # aws-lc-rs / ring
 │
 ├─[2] 解析命令行参数
 │   └── g3proxy::opts::parse_clap()
 │       返回 ProcArgs { daemon_config, output_xxx_graph, ... }
 │
 ├─[3] 设置进程日志
 │   └── g3_daemon::log::process::setup()
 │
 ├─[4] 热升级场景：连接旧进程
 │   └── UpgradeActor::connect_to_old_daemon()
 │
 ├─[5] 加载配置
 │   └── g3proxy::config::load() → 返回 config_file 路径
 │       内部解析 YAML → 构建 TopoMap → 返回 main.yml
 │
 ├─[6] 可选输出
 │   ├── --test-config  → 验证配置格式后退出
 │   ├── --output-graphviz-graph
 │   ├── --output-mermaid-graph
 │   └── --output-plantuml-graph
 │
 ├─[7] Unix 守护进程化
 │   └── g3_daemon::daemonize::check_enter()
 │
 ├─[8] 启动 StatsD 统计线程
 │   └── g3proxy::stat::spawn_working_threads()
 │
 ├─[9] 启动 Worker 线程
 │   └── g3_daemon::runtime::worker::spawn_workers()
 │
 └─[10] 进入 Tokio 运行时 ─────────────────────┐
     │                                          │
     │  tokio_run() {                           │
     │    rt.block_on(async {                   │
     │      // 10.1 启动 Cap'n Proto RPC 控制    │
     │      capnp::spawn_working_thread()       │
     │      // 10.2 创建 UniqueController       │
     │      UniqueController::start()            │
     │      // 10.3 热升级：创建 DaemonController│
     │      // 10.4 启动 QuitActor               │
     │      QuitActor::tokio_spawn_run()         │
     │      // 10.5 注册信号处理器               │
     │      signal::register()  ← SIGHUP/SIGTERM/SIGQUIT│
     │      // 10.6 启动辅助运行时               │
     │      ├── limit_schedule_runtime           │
     │      ├── cert_generate_runtime            │
     │      └── ip_locate_runtime               │
     │      // 10.7 加载并启动所有组件           │
     │      load_and_spawn() {                  │
     │        resolve::spawn_all()  ← ① DNS解析器│
     │        escape::load_all()    ← ② 出口    │
     │        auth::load_all()      ← ③ 用户组  │
     │        audit::load_all()     ← ④ 审计器  │
     │        serve::spawn_all()    ← ⑤ 服务器  │
     │      }                                    │
     │      // 10.8 等待退出信号                 │
     │      unique_ctl.await                     │
     │    })                                     │
     │  }                                        │
     └──────────────────────────────────────────┘
```

### 热重载流程（SIGHUP 触发）

```
SIGHUP → signal::do_reload()
  │
  ├── config::reload()           # 重新解析 YAML
  ├── resolve::spawn_all()       # 差分更新解析器
  ├── escape::load_all()         # 差分更新出口
  ├── auth::load_all()           # 差分更新用户组
  ├── audit::load_all()          # 差分更新审计器
  └── serve::spawn_all()         # 差分更新服务器
       └── 拓扑排序级联：
            旧组件优雅关闭 → 新建组件接管监听 → 依赖链路更新
```

---

## 5. 请求处理全链路

```
客户端 TCP 连接
        │
        ▼
┌──────────────────────────────────────────────────┐
│ 1. Server 接受连接                                │
│    ├── accept tcp listener / quic endpoint        │
│    ├── 获取客户端地址 (RemoteAddr)                 │
│    └── 创建 ServerTaskNotes                       │
│        { task_id, client_addr, server_addr,       │
│          escaper, user_ctx, ... }                 │
├──────────────────────────────────────────────────┤
│ 2. 协议识别（IntelliProxy / Auditor）              │
│    ├── 检测 TLS ClientHello → SNI 提取            │
│    ├── 检测 HTTP 请求行                           │
│    ├── 检测 SOCKS 握手                            │
│    └── 检测 IMAP/SMTP/FTP 协议特征                │
├──────────────────────────────────────────────────┤
│ 3. 用户认证（如有 UserGroup 配置）                 │
│    ├── 解析 Proxy-Authorization 头               │
│    ├── 查找 Static/Dynamic 用户                   │
│    ├── 密码验证 / ACL 检查                        │
│    ├── 设置用户上下文 (UserContext)                │
│    └── 应用用户级别限流限速                        │
├──────────────────────────────────────────────────┤
│ 4. TLS 拦截（如有 Auditor 配置）                   │
│    ├── 对 CONNECT 隧道进行 TLS MITM               │
│    ├── 动态生成目标服务器伪造证书（g3fcgen）        │
│    ├── 解密 TLS 流量                              │
│    └── 可选：将解密流量导出 (Stream Detour)        │
├──────────────────────────────────────────────────┤
│ 5. Escaper 选择与连接建立                         │
│    ├── 路由选择（Route 类型 Escaper）              │
│    │   ├── GeoIP → 按目标地理位置选出口            │
│    │   ├── Failover → 主备切换                    │
│    │   ├── Resolved → 按 DNS 解析后 IP 选出口     │
│    │   └── Select → 轮询/随机/一致性哈希          │
│    ├── DNS 解析（调用 Resolver）                   │
│    ├── 建立上游 TCP/TLS 连接                      │
│    └── 代理串联（如有 Proxy 类型 Escaper）         │
├──────────────────────────────────────────────────┤
│ 6. 数据中继 (Bidirectional Relay)                 │
│    ├── 客户端 ←→ g3proxy ←→ 目标服务器             │
│    ├── HTTP 协议解析与审计（如需）                 │
│    ├── ICAP REQMOD / RESPMOD 适配                 │
│    └── 实时统计打点（StatsD）                      │
└──────────────────────────────────────────────────┘
```

### 关键数据结构

```rust
// 任务上下文（贯穿整个请求生命周期）
pub struct ServerTaskNotes {
    id: ServerTaskId,           // 唯一任务 ID
    server_addr: SocketAddr,     // 服务器本地地址
    client_addr: SocketAddr,     // 客户端地址
    escaper: Option<ArcEscaper>, // 选中的出口
    user_ctx: Option<ArcUserContext>, // 用户上下文
    tls_name: Option<String>,    // TLS SNI 名称
    alpn_protocol: Option<String>, // ALPN 协商协议
    // ... 更多字段
}

// TCP 连接结果
pub type TcpConnection = (
    Box<dyn AsyncRead + Unpin + Send + Sync>,
    Box<dyn AsyncWrite + Unpin + Send + Sync>,
);
```

---

## 6. 模块详解

### 6.1 `serve/` — 服务器模块

`src/serve/` 是最大的模块之一，因为每种 Server 类型都有独立的子模块。

**关键文件：**

| 文件 | 作用 |
|------|------|
| `mod.rs` | Server trait 定义、类型别名（`ArcServer`、`ArcServerInternal`） |
| `ops.rs` | 服务器生命周期管理：spawn / reload / stop / wait |
| `task.rs` | `ServerTaskNotes` 定义和 `ServerTaskStage` 枚举 |
| `idle_check.rs` | 空闲连接检查器 |

**Server 子模块设计模式（以 http_proxy 为例）：**

```
serve/http_proxy/
├── mod.rs       # HttpProxyServer 结构体 + Server trait 实现
├── task.rs      # HttpProxyTask → 处理单个 CONNECT/GET 请求
├── accept.rs    # TCP 连接接受逻辑
└── stats.rs     # HTTP 代理级别统计
```

### 6.2 `escape/` — 出口模块

出口设计区分 **基础出口**（直接/IP绑定）和 **路由出口**（包含其他出口引用）。

**关键文件：**

| 文件 | 作用 |
|------|------|
| `mod.rs` | Escaper trait、ArcEscaper 类型别名 |
| `ops.rs` | 出口加载/重载/依赖更新 |
| `registry.rs` | 出口注册表（名称 → ArcEscaper 映射） |
| `stats.rs` | 出口统计 |
| `egress_path.rs` | 出口路径选择逻辑 |

**路由出口的关键逻辑**（以 `route_failover` 为例）：

```
route_failover {
    primary: escaper_A,     # 主出口
    standby: escaper_B,     # 备用出口
    check_interval: 5s,     # 健康检查间隔
    max_fails: 3,           # 最大连续失败次数
}
→ 优先使用 escaper_A，连续失败 3 次后切换到 escaper_B
→ 定时探测 escaper_A 恢复后自动切回
```

### 6.3 `inspect/` — 协议检测模块

负责**识别流量协议类型**并执行拦截。这是 TLS 中间人攻击和 DPI 的核心。

```
inspect/
├── mod.rs         # StreamInspectContext — 协议检测总入口
├── stream/        # TCP 流透明转发处理
├── tls/           # TLS 握手拦截与证书伪造
├── start_tls/     # STARTTLS 协议升级检测（IMAP/SMTP）
├── http/          # HTTP/1.x 请求/响应拦截
├── websocket/     # WebSocket 升级检测
├── imap/          # IMAP 协议拦截
├── smtp/          # SMTP 协议拦截
└── ftp/           # FTP 协议拦截
```

### 6.4 `audit/` — 审计模块

审计模块将协议检测的结果与 ICAP 审计管道对接：

```
audit/
├── mod.rs         # Auditor 结构体定义
├── handle.rs      # AuditHandle — 每个连接独立的审计上下文
├── ops.rs         # 审计器加载/重载
├── registry.rs    # 审计器注册表
└── detour/        # Stream Detour（QUIC 特性，解密流量导出）
```

### 6.5 `auth/` — 认证授权模块

```
auth/
├── mod.rs         # UserGroup 定义、UserType (Static/Dynamic/Anonymous)
├── user.rs        # User 结构体、UserContext（每个连接的用户上下文）
├── site.rs        # UserSite — 用户级别的站点差异化配置
├── stats.rs       # 用户维度统计
├── ops.rs         # 用户组加载/重载
├── registry.rs    # 用户组注册表
└── source/        # 动态用户源
    ├── mod.rs     # trait DynamicUserSource
    ├── file.rs    # 从文件加载
    ├── lua.rs     # 从 Lua 脚本加载
    ├── python.rs  # 从 Python 脚本加载
    └── redis.rs   # 从 Redis 加载
```

### 6.6 `resolve/` — DNS 解析模块

```
resolve/
├── mod.rs         # Resolver trait、ResolveResult
├── ops.rs         # 解析器 spawn/reload
├── handle.rs      # IntegratedResolverHandle — 统一解析入口
├── c_ares/        # c-ares C 库异步解析
├── hickory/       # Hickory Rust 原生解析 (UDP/TCP/DoT/DoH/DoH3)
├── deny_all/      # 全拒绝解析器
└── fail_over/     # 故障转移组合解析器
```

### 6.7 其余模块

| 模块 | 作用 |
|------|------|
| `config/` | YAML 配置解析、TopoMap 构建、Graphviz/Mermaid/PlantUML 图输出 |
| `control/` | Cap'n Proto RPC 控制接口、UniqueController、DaemonController |
| `stat/` | StatsD 统计线程、多维度指标收集 |
| `log/` | 日志子系统（任务日志、出口日志、审计日志等） |
| `module/` | 通用连接模块：TCP 连接、HTTP 转发、UDP 中继、FTP-over-HTTP |
| `signal.rs` | Unix 信号处理（SIGHUP=reload, SIGTERM=graceful, SIGQUIT=force） |
| `opts.rs` | CLI 参数定义（clap derive） |
| `build.rs` | 构建信息常量（版本号、commit hash） |

---

## 7. 配置系统

### 7.1 配置文件组织

配置可以从**单个 main.yml** 加载，也可以拆分为多个独立文件：

```
main.yml                          # 顶层入口（运行时/日志/监控/控制器）
├── resolver/                     # DNS 解析器配置（可选独立文件）
│   ├── c_ares:
│   ├── hickory:
│   ├── fail_over:
│   └── deny_all:
├── escaper/                      # 出口配置（可选独立文件）
│   ├── direct_fixed:
│   ├── proxy_http:
│   └── route_failover:
├── user/ / user_group/          # 用户组配置（可选独立文件）
├── auditor/                      # 审计器配置（可选独立文件）
└── server/                       # 服务器配置（可选独立文件）
    ├── http_proxy:
    ├── socks_proxy:
    └── sni_proxy:
```

### 7.2 最小配置示例

```yaml
# main.yml — 最简 HTTP 正向代理
runtime:
  worker_threads: 4

resolver:
  c_ares:
    name: default
    servers: [8.8.8.8, 114.114.114.114]

escaper:
  direct_fixed:
    name: direct
    resolver: default

server:
  http_proxy:
    name: proxy
    listen:
      address: "0.0.0.0:8080"
    escaper: direct
```

### 7.3 依赖拓扑（TopoMap）

组件通过 `depends_on` 方法声明依赖关系：

```
resolver "default"              ← 无依赖
  ↑
escaper "direct"                ← 依赖 resolver "default"
  ↑
server "proxy"                  ← 依赖 escaper "direct"
```

加载顺序：`resolver → escaper → server`

重载时：
- 修改 escaper 配置 → 只需重载 escaper，级联更新依赖它的 server
- 修改 resolver 配置 → 重载 resolver，级联更新 escaper → server

### 7.4 配置差分策略

每个配置类型实现 `diff_action()` 返回重载策略：

```rust
pub enum DiffAction<T> {
    Reload,          // 原地重载（不中断服务）
    SpawnNew(T),     // 创建新实例、停旧起新
    NoAction,        // 无变化
    UpdateInPlace,   // 部分更新
}
```

---

## 8. 依赖库生态

g3proxy 依赖 **43 个自有 crate**（位于 `lib/` 目录），按层次分为：

### 运行时与进程管理

| Crate | 版本 | 职责 |
|-------|------|------|
| `g3-runtime` | 0.4 | Tokio 异步运行时配置（blended / unaided 模式） |
| `g3-daemon` | 0.3 | 守护进程管理：config、listen、log、metrics、signal、daemonize |

### 网络传输层

| Crate | 版本 | 职责 |
|-------|------|------|
| `g3-socket` | 0.5 | 跨平台 Socket 抽象（基于 socket2 + libc/windows-sys） |
| `g3-io-ext` | 0.8 | IO 扩展工具（限流调度运行时等） |
| `g3-io-sys` | 0.1 | 底层 IO 系统调用封装 |

### 协议层

| Crate | 版本 | 职责 |
|-------|------|------|
| `g3-http` | 0.4 | HTTP/1.x 协议编解码 |
| `g3-h2` | 0.2 | HTTP/2 辅助 |
| `g3-socks` | 0.3 | SOCKS4/4a/5 协议 |
| `g3-ftp-client` | 0.4 | FTP 客户端 |
| `g3-icap-client` | 0.3 | ICAP 客户端（REQMOD/RESPMOD） |
| `g3-imap-proto` | 0.2 | IMAP 协议解析 |
| `g3-smtp-proto` | 0.2 | SMTP 协议解析 |

### 安全与加密

| Crate | 版本 | 职责 |
|-------|------|------|
| `g3-tls-cert` | 0.6 | TLS 证书构建与管理（MITM 场景） |
| `g3-tls-ticket` | 0.2 | TLS Session Ticket |
| `g3-openssl` | 0.4 | OpenSSL 封装 |
| `g3-xcrypt` | 0.3 | 加密工具 |
| `g3-cert-agent` | 0.2 | 证书生成代理 |

### 流量识别与路由

| Crate | 版本 | 职责 |
|-------|------|------|
| `g3-dpi` | 0.2 | 深度包检测（协议识别器） |
| `g3-ip-locate` | 0.2 | IP 归属地查询 |
| `g3-geoip-db` | 0.3 | GeoIP 数据库 |
| `g3-geoip-types` | 0.2 | GeoIP 类型定义 |
| `g3-resolver` | 0.8 | DNS 解析抽象层（c-ares / Hickory） |
| `g3-hickory-client` | 0.2 | Hickory DNS 客户端封装 |

### 序列化与配置

| Crate | 版本 | 职责 |
|-------|------|------|
| `g3-yaml` | 0.6 | YAML 配置解析 |
| `g3-json` | 0.4 | JSON 序列化 |
| `g3-msgpack` | 0.3 | MessagePack 序列化 |
| `g3-types` | 0.6 | 通用类型定义 |

### 可观测性

| Crate | 版本 | 职责 |
|-------|------|------|
| `g3-statsd-client` | 0.2 | StatsD 客户端 |
| `g3-slog-types` | 0.2 | 结构化日志类型 |
| `g3-stdlog` | 0.2 | 标准日志适配 |
| `g3-syslog` | 0.7 | Syslog 输出 |
| `g3-journal` | 0.3 | Journald 输出 |
| `g3-fluentd` | 0.2 | Fluentd 输出 |
| `g3-histogram` | 0.2 | 直方图统计 |

### 其他

| Crate | 版本 | 职责 |
|-------|------|------|
| `g3-clap` | 0.2 | CLI 参数解析扩展 |
| `g3-ctl` | 0.2 | 控制接口库 |
| `g3-compat` | 0.2 | 兼容性适配 |
| `g3-datetime` | 0.2 | 日期时间工具 |
| `g3-macros` | 0.1 | 过程宏（AnyConfig 派生等） |
| `g3-std-ext` | 0.1 | 标准库扩展 |
| `g3-udpdump` | 0.2 | UDP 数据包导出 |
| `g3-redis-client` | 0.2 | Redis 客户端封装 |

---

## 9. 关键设计决策

### 9.1 Async Rust 全链路

整个系统基于 Tokio 异步运行时，从连接接受到数据中继全程非阻塞。Worker 线程池 + Tokio 多线程调度器实现高并发。

### 9.2 组件化 + 拓扑排序

Server / Escaper / Resolver 三大组件通过 trait 抽象，依赖关系显式声明。`TopoMap` 在加载和热重载时自动按依赖顺序处理，避免循环依赖。

### 9.3 配置差分重载

每种配置实现 `diff_action()` 方法，支持四种重载策略：`Reload`（原地）、`SpawnNew`（停旧起新）、`NoAction`（跳过）、`UpdateInPlace`（部分更新）。结合拓扑排序实现级联热更新。

### 9.4 Cap'n Proto 控制面

使用 Cap'n Proto RPC 作为控制接口，支持 `g3proxy-ctl` 工具远程管理。控制命令包括：reload、graceful quit、force quit、hot upgrade 等。

### 9.5 多 TLS 后端支持

通过 feature flags 在编译时选择 TLS 后端：OpenSSL（含 BoringSSL/AWS-LC/Tongsuo 变体）和 rustls（ring/aws-lc-rs）。支持国密 TLCP 协议（Tongsuo）。

### 9.6 动态用户源

用户不限于静态配置，支持 Lua 脚本、Python 脚本、Redis 动态加载，灵活适配企业级认证需求。

### 9.7 优雅升级

支持零中断热升级：新进程连接旧进程，旧进程将监听 socket 传给新进程，新进程接管后旧进程优雅关闭。

---

## 10. 快速速查表

### 关键文件索引

| 想了解... | 看这个文件 |
|----------|----------|
| 启动流程 | `g3proxy/src/main.rs` |
| 模块声明 | `g3proxy/src/lib.rs` |
| Server trait | `g3proxy/src/serve/mod.rs` |
| Escaper trait | `g3proxy/src/escape/mod.rs` |
| Resolver trait | `g3proxy/src/resolve/mod.rs` |
| 配置加载 | `g3proxy/src/config/mod.rs` |
| 请求处理 | `g3proxy/src/serve/task.rs` |
| 协议检测 | `g3proxy/src/inspect/mod.rs` |
| 审计器 | `g3proxy/src/audit/mod.rs` |
| 用户认证 | `g3proxy/src/auth/mod.rs` |
| 信号处理 | `g3proxy/src/signal.rs` |
| CLI 参数 | `g3proxy/src/opts.rs` |
| HTTP/1 协议 | `lib/g3-http/src/lib.rs` |
| SOCKS 协议 | `lib/g3-socks/src/lib.rs` |
| ICAP 客户端 | `lib/g3-icap-client/src/lib.rs` |
| DNS 解析 | `lib/g3-resolver/src/lib.rs` |
| DPI 引擎 | `lib/g3-dpi/src/lib.rs` |
| TLS 证书 | `lib/g3-tls-cert/src/lib.rs` |
| 守护进程 | `lib/g3-daemon/src/lib.rs` |
| Socket 抽象 | `lib/g3-socket/src/lib.rs` |
| 项目 README | `README.zh_CN.md` |
| 用户指南 | `g3proxy/UserGuide.zh_CN.md` |
| 开发环境 | `doc/dev-setup.md` |
| 构建打包 | `doc/build_and_package.md` |

### 编译运行

```bash
# 完整编译
cargo build --release

# 运行（需要配置文件）
./g3proxy -c etc/g3proxy.yaml

# 验证配置
./g3proxy -c etc/g3proxy.yaml --test-config

# 输出依赖图
./g3proxy -c etc/g3proxy.yaml --output-mermaid-graph

# TLS 拦截 + ICAP 审计场景
./g3fcgen -c g3fcgen/examples/simple/g3fcgen.yaml &   # 启动伪造证书服务
sudo /usr/sbin/c-icap -N -f /etc/c-icap.conf &        # 启动 ICAP 服务
./g3proxy -c g3proxy/examples/inspect_http_proxy/g3proxy.yaml
```

### 常用命令

| 命令 | 效果 |
|------|------|
| `kill -SIGHUP <pid>` | 热重载配置 |
| `kill -SIGTERM <pid>` | 优雅关闭 |
| `kill -SIGQUIT <pid>` | 强制关闭 |
| `g3proxy-ctl reload` | 通过 RPC 重载 |

---

> 文档基于 g3proxy v1.12.3 源码分析生成。项目地址：[github.com/bytedance/g3](https://github.com/bytedance/g3)
