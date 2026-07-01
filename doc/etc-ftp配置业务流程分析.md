# etc/ftp/ 配置业务流程分析

> 对应配置目录：`etc/ftp/` — FTP 客户端通过 HTTP CONNECT 代理访问 FTP 服务器

---

## 目录

1. [配置解读](#1-配置解读)
2. [架构总览](#2-架构总览)
3. [完整业务流程](#3-完整业务流程)
4. [FTPS 变体流程](#4-ftps-变体流程)
5. [核心数据结构](#5-核心数据结构)
6. [与 native ftp_proxy 的关键区别](#6-与-native-ftpproxy-的关键区别)
7. [代码路径索引](#7-代码路径索引)

---

## 1. 配置解读

### 1.1 入口配置 (`etc/ftp/g3proxy.yaml`)

```yaml
runtime:
  thread_number: 2        # 2 个 worker 线程

log: stdout               # 日志输出到标准输出

auditor: auditor.d/       # 审计器配置目录
server: server.d/         # 服务器配置目录
resolver: resolver.d/     # DNS 解析器配置目录
escaper: escaper.d/       # 出口路由配置目录
```

### 1.2 服务器配置 (`server.d/http_proxy.yaml`)

```yaml
name: http_proxy
type: http_proxy           # HTTP CONNECT 代理
escaper: default           # 出口引用
auditor: ftp_auditor       # 审计器引用

listen:
  address: "0.0.0.0:3128"  # 监听地址和端口

task_idle_max_count: 1800  # 任务空闲超时（次数）
tcp_sock_speed_limit: 200M # TCP 速度限制
tcp_copy_buffer_size: 32KB # 缓冲区大小
```

**关键点**：服务器类型是 `http_proxy`，而非 `ftp_proxy`。这意味着 FTP 客户端必须配置 HTTP 代理，通过 `CONNECT` 方法建立隧道。

### 1.3 审计器配置 (`auditor.d/ftp_auditor.yaml`)

```yaml
name: ftp_auditor

# === DPI 协议检测 ===
protocol_inspection:
  data0_buffer_size: 16KB
  inspect_max_depth: 5
  data0_wait_timeout: 5s
  data0_read_timeout: 5s
  data0_size_limit:
    ftp_server_greeting_msg: 2KB     # FTP 服务器问候语最大大小

# === TLS 中间人拦截（FTPS 上传审计需要）===
tls_cert_generator: { }              # TLS 证书生成器
tls_interception_client: { }         # TLS 拦截客户端
tls_ticketer: { }                    # TLS 会话票据

# === TLS KeyLog（FTPS 场景，ICAP 携带会话密钥）===
tls_keylog:
  enable: true                       # 启用 TLS KeyLog 捕获
  max_entries: 100                   # 每个连接最多 100 条 KeyLog

# === HTTP/1.1 拦截 ===
h1_interception:
  req_hasbody: true                  # 请求可能携带 body
  req_body_min_size: 8               # 最小 body 大小阈值

# === ICAP 审计 ===
icap_reqmod_service: icap://127.0.0.1:1344/echo   # ICAP REQMOD 服务地址
application_audit_ratio: 1.0                       # 审计比例（100%）
```

### 1.4 DNS 解析器配置 (`resolver.d/default.yaml`)

```yaml
name: default
type: c-ares                # 使用 c-ares 异步 DNS 解析
```

### 1.5 出口配置 (`escaper.d/default.yaml`)

```yaml
name: default
type: direct_fixed          # 直接连接（不经过其他代理）
resolver: default           # 使用 default 解析器
```

### 1.6 配置依赖拓扑

```
resolver "default"   ──────────┐
                               ▼
escaper "default"   ──────────┐│
                               ▼▼
auditor "ftp_auditor"  ───────┐││
                               ▼▼▼
server "http_proxy"  ←  依赖 escaper + auditor
```

加载顺序：`resolver → escaper → auditor → server`

---

## 2. 架构总览

```
┌─────────────────────────────────────────────────────────────────┐
│                        g3proxy :3128                             │
│                                                                  │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────────────┐  │
│  │ FTP 客户端 │────│  http_proxy  │────│     ftp_auditor      │  │
│  │          │    │              │    │                      │  │
│  │ CONNECT  │    │ 接受 CONNECT  │    │ DPI → 识别 FTP 协议   │  │
│  │ :21      │    │ 建立 TCP 隧道 │    │ FtpInterceptObject   │  │
│  │          │    │              │    │ 控制通道逐行检查       │  │
│  └──────────┘    └──────────────┘    └──────────────────────┘  │
│       │                                    │                    │
│       │          ┌─────────────────────────┘                    │
│       │          ▼                                               │
│       │    ┌──────────────────────────┐                         │
│  CONNECT    │   GlobalUploadState     │  全局状态——跨连接桥梁    │
│  :54321 ──►│  (client_ip,server_ip)   │                         │
│             │  → PendingUploadInfo    │                         │
│             └──────────────────────────┘                         │
│                          │                                       │
│                          ▼                                       │
│             ┌──────────────────────────┐                        │
│             │   run_ftp_upload_audit   │                        │
│             │   _or_relay_bidi()       │                        │
│             │   ICAP REQMOD 审计       │                        │
│             └──────────────────────────┘                        │
└─────────────────────────────────────────────────────────────────┘
```

**核心架构决策**：FTP 客户端的所有 TCP 流量都通过 HTTP CONNECT 隧道化。控制通道（端口 21）和数据通道（PASV 随机端口）是**两条独立的 CONNECT 连接**，之间没有上下文传递——全靠全局 `GlobalUploadState` 单例按 `(客户端IP, 服务器IP)` 做关联。

---

## 3. 完整业务流程

### 阶段一：控制通道 — DPI 协议识别 + 上传命令标记

#### 步骤 1：客户端建立控制通道

```
FTP 客户端 → CONNECT ftp.example.com:21 HTTP/1.1 → g3proxy :3128
```

**代码入口**：`g3proxy/src/serve/http_proxy/task/connect/task.rs`

http_proxy 接受 CONNECT 请求，通过 `direct_fixed` escaper 建立到上游 FTP 服务器的 TCP 连接（端口 21）。

#### 步骤 2：DPI 协议检测

**代码入口**：`g3proxy/src/inspect/ftp/object.rs → FtpInterceptObject::new()`

审计器 `ftp_auditor` 的 DPI 引擎（`g3-dpi`）开始检测协议：

| 检测数据 | 来源 | 内容 |
|----------|------|------|
| 上游初始数据 | FTP 服务器 | `220 Welcome to FTP server` |
| 客户端首条命令 | FTP 客户端 | `USER alex` |
| 后续命令 | FTP 客户端 | `PASS ***`、`PASV`、`STOR` 等 |

DPI 引擎通过端口（21）和内容特征（`220` 开头）识别为 FTP 协议，创建 `FtpInterceptObject` 进入拦截模式。

#### 步骤 3：控制通道中继（逐行检查）

**代码入口**：`FtpInterceptObject::relay_control_channel()`（`object.rs:260`）

```rust
loop {
    tokio::select! {
        // 读取客户端发送的 FTP 命令（逐行）
        n = read_line_limited(&mut clt_reader, &mut clt_line, 8192) => {
            if is_upload_command(&clt_line) {
                // STOR / STOU / APPE → 标记上传
                get_ftp_upload_state().mark_upload(
                    client_ip, server_ip, "STOR", "/path/to/file", 0
                );
                ups_writer.write_all(&clt_line).await;  // 转发给服务器
            } else if is_auth_tls_command(&clt_line) {
                // AUTH TLS → 触发 TLS 中间人拦截
                ups_writer.write_all(&clt_line).await;
                // 检查服务器回复 234 → 转 StartTlsInterceptObject
            } else {
                // USER/PASS/PASV/QUIT → 透传
                ups_writer.write_all(&clt_line).await;
            }
        }
        // 读取服务器回复 → 原样转发给客户端
        n = ups_reader.read(&mut ups_buf) => {
            clt_w.write_all(&ups_buf[..n]).await;
        }
        // 空闲超时检查
        _ = idle_interval.tick() => { ... }
    }
}
```

#### 命令分类处理

| FTP 命令 | 处理方式 | 说明 |
|----------|----------|------|
| `USER` / `PASS` / `ACCT` | 透传 | 认证信息原样中继 |
| `QUIT` / `NOOP` / `PWD` | 透传 | 普通命令原样中继 |
| `PASV` / `EPSV` | 透传 | **不重写响应**（与 ftp_proxy 的区别） |
| `AUTH TLS` | 透传 + 触发 TLS 拦截 | 如果服务器回复 234 → StartTls |
| `STOR` / `APPE` / `STOU` | 透传 + **标记上传** | 全局状态记录上传信息 |
| `RETR` / `LIST` / `NLST` | 透传 | 下载命令不拦截（当前版本） |

#### 步骤 4：上传标记写入全局状态

```rust
// inspect/ftp/object.rs:305
get_ftp_upload_state().mark_upload(
    client_ip,        // 客户端 IP（如 192.168.1.100）
    server_ip,        // FTP 服务器 IP（如 203.0.113.10）
    "STOR",           // FTP 命令名
    "/path/to/file",  // 文件路径
    0,                // 序号
);
```

此时控制通道的使命基本完成。数据通道的连接是**客户端根据 PASV 响应主动发起的第二条 HTTP CONNECT**。

---

### 阶段二：数据通道 — 第二条 CONNECT → 透明 TCP 中继（或 ICAP 审计）

#### 步骤 5：客户端建立数据通道

PASV/EPSV 响应被原样透传给客户端（包含真实服务器 IP:Port）。但因为客户端配置了 HTTP 代理，**不会直连那个地址**，而是发出第二条 CONNECT：

```
FTP 服务端 PASV 响应 → 代理原样透传 → 客户端
  227 Entering Passive Mode (10,20,79,186,68,70)

客户端:  "我要连 10.20.79.186:17478"
         → 实际发出: CONNECT 10.20.79.186:17478 HTTP/1.1
         → 发往代理 20.20.136.218:3128
         → 代理建立 TCP 连接到 10.20.79.186:17478
```

**代码入口**：`g3proxy/src/serve/http_proxy/task/connect/task.rs` → `relay()`（同一个文件，第二次进入）

#### 步骤 6：数据通道的路由判断（connect/task.rs:465-544）

```rust
let upstream_port = self.upstream.port();        // 17478
let is_ftp_control = upstream_port == 21 || upstream_port == 990;   // false
let ftps_domain = get_ftp_upload_state().get_ftps_domain(...);      // None（没走 AUTH TLS）
let is_ftps_data_channel = ftps_domain.is_some();                   // false
```

然后依次判断三个分支：

```
┌─ if is_ftp_control || is_ftps_data_channel
│     → DPI transit_with_inspection（重新协议检测）
│     → 不命中（非 21/990 端口，非 FTPS）        ← 跳过
│
├─ if consume_upload(client_ip, server_ip)      ← 命中？
│     ├─ 是上传(STOR) → 创建 FtpUploadAuditContext → ICAP REQMOD 审计
│     └─ 非上传(LIST/RETR) → None               ← 跳过
│
└─ self.transit_transparent(clt_r, clt_w, ups_r, ups_w)
      → 纯 TCP 双向中继，不做 FTP 协议感知        ← 🔴 最终路径
```

**关键结论**：数据通道**经过代理**——作为一条透明的 CONNECT 隧道。代理在客户端和服务器之间按字节双向拷贝，不做 FTP 协议解析。从服务器角度看，数据通道和控制通道来自**同一个 IP（代理的 IP）**，不会触发 `425 Bad IP connecting`。

#### 步骤 7：上传场景的 ICAP REQMOD 审计（仅 STOR/APPE/STOU 触发）

**代码入口**：`connect/task.rs:507-537` → `ftp_proxy/audit_bridge.rs`

当 `consume_upload()` 命中时（步骤 4 在控制通道标记过），创建完整的审计上下文：

```rust
// connect/task.rs:520-528 + audit_bridge.rs:32-43
let audit_ctx = FtpUploadAuditContext {
    icap_client,                              // ← ICAP REQMOD 客户端
    idle_wheel,
    copy_config,
    client_addr:  Some(client_addr),          // ← 客户端真实 IP（请求头 X-Client-IP）
    ftp_command:  "STOR",                     // ← FTP 命令名
    ftp_path:     "/path/to/file",            // ← 目标路径

    // 🔴 五元组（本地添加，wming/repid audit）
    data_channel_tuple: Some(ConnectionTuple {
        server_addr: proxy_local_addr,        // → ICAP 头: X-Proxy-IP / X-Proxy-PORT
        remote_addr: ftp_server_addr,         // → ICAP 头: X-Remote-IP / X-Remote-PORT
        protocol:     ConnectionProtocol::Tcp // → ICAP 头: X-Proto-P: 6
    }),

    // 🔴 TLS KeyLog（本地添加）
    keylog_buffer: self.keylog_buffer.clone(), // → ICAP 头: X-TLS-VERSION / X-TLS-CIPHER /
                                               //             X-TLS-SERVER_RANDOM / X-TLS-KeyLog-*
};
```

**传入 ICAP 适配器**（`audit_bridge.rs:230-259`）：

```rust
let mut adapter = icap_client.ftp_upload_audit_adapter(...).await?;

adapter.set_client_addr(addr);           // → X-Client-IP, X-Client-Port
adapter.set_connection_tuple(tuple);     // → X-Proxy-IP, X-Proxy-PORT, X-Remote-IP, X-Remote-PORT, X-Proto-P
adapter.set_keylog_buffer(keylog);       // → X-TLS-VERSION, X-TLS-CIPHER, X-TLS-SERVER_RANDOM, X-TLS-KeyLog-*

adapter.audit_and_forward(&mut state, clt_r, ups_w, "STOR", "/path/to/file").await;
```

**ICAP 请求头构造**（`lib/g3-icap-client/src/reqmod/ftp/mod.rs:132-167`）：

```
POST icap://127.0.0.1:1344/echo ICAP/1.0
Host: 127.0.0.1
Encapsulated: req-hdr=0, req-body=148

PUT /path/to/file FTP/1.0                     ← 合成的 HTTP 请求头（FtpUploadAdapter）
Content-Type: application/octet-stream
X-FTP-Command: STOR
Transfer-Encoding: chunked
X-Transformed-From: FTP                       ← FTP 审计标识
X-Client-IP: 192.168.1.100                   ← client_addr
X-Client-Port: 54321
X-Proxy-IP: 20.20.136.218                    ← ▲ 五元组 · 代理侧
X-Proxy-PORT: 44321
X-Remote-IP: 10.20.79.186                    ← ▲ 五元组 · 远端
X-Remote-PORT: 21
X-Proto-P: 6                                  ← ▲ 五元组 · TCP
X-TLS-VERSION: TLSv1.3                        ← █ TLS KeyLog (仅 FTPS)
X-TLS-CIPHER: TLS_AES_256_GCM_SHA384          ← █ TLS KeyLog
X-TLS-SERVER_RANDOM: <hex>                    ← █ TLS KeyLog
X-TLS-KeyLog-1: CLIENT_RANDOM <hex> <hex>     ← █ TLS 会话密钥
X-TLS-KeyLog-2: SERVER_HANDSHAKE_TRAFFIC_SECRET ...
                                               ← 数据走 chunked body 流式传输
```

**数据流**：文件数据同时走两条路径——① 原样转发上行（`ups_w.write_all`）② chunked 编码后发给 ICAP（`write_icap_chunk`）。ICAP 失败 **永不阻断上行**（fail-open 设计）。

#### 步骤 8：控制通道返回传输结果

#### 步骤 8：控制通道返回传输结果

```
FTP 服务器 → 226 Transfer complete → [控制通道透传] → FTP 客户端
```

---

## 4. FTPS 变体流程（AUTH TLS + g3fcgen 证书伪造）

当 FTP 服务器支持 FTPS（AUTH TLS）时，控制通道会经过 TLS 中间人拦截。g3proxy 使用 **g3fcgen 假证书生成服务** 动态伪造目标服务器的 TLS 证书。

### 4.1 整体架构

```
┌──────────┐         ┌──────────────────────────────────────┐         ┌──────────┐
│ FTP 客户端 │         │              g3proxy                  │         │ FTP 服务器│
│          │         │                                       │         │          │
│  (TLS)   │◄───────►│  StartTlsInterceptObject              │◄───────►│  (TLS)   │
│          │ 伪造证书 │  ┌─────────────────────────────────┐  │ 真实证书 │          │
│          │         │  │        TlsInterceptionContext     │  │         │          │
│          │         │  │  ┌─────────────────────────────┐ │  │         │          │
│          │         │  │  │      CertAgentHandle        │ │  │         │          │
│          │         │  │  │   (UDP MessagePack)         │ │  │         │          │
│          │         │  │  └──────────┬──────────────────┘ │  │         │          │
│          │         │  └─────────────┼────────────────────┘  │         │          │
│          │         └───────────────┼───────────────────────┘         │          │
│          │                         │                                  │          │
│          │              UDP :2999 │                                  │          │
│          │               ┌───────▼──────────┐                       │          │
│          │               │     g3fcgen       │                       │          │
│          │               │  (独立进程)        │                       │          │
│          │               │  伪造证书生成服务   │                       │          │
│          │               └──────────────────┘                       │          │
└──────────┘                                                        └──────────┘
```

### 4.2 触发条件

用户配置中必须启用 TLS 拦截（`etc/ftp/auditor.d/ftp_auditor.yaml`）：

```yaml
# 三个配置缺一不可
tls_cert_generator: { }       # → 内部启动 CertAgentHandle（连接 g3fcgen）
tls_interception_client: { }  # → 到上游的 TLS 客户端配置
tls_ticketer: { }             # → TLS 会话票据管理
```

`TlsInterceptionContext` 由这三个配置构造（`inspect/tls/mod.rs:92-128`）：

```rust
pub(crate) struct TlsInterceptionContext {
    cert_agent: Arc<CertAgentHandle>,                      // ← 连接 g3fcgen 的句柄
    client_config: Arc<OpensslInterceptionClientConfig>,   // ← 上游 TLS 客户端配置
    server_config: Arc<OpensslInterceptionServerConfig>,   // ← 面向客户端的 TLS 服务端配置
    stream_dumper: Arc<Vec<StreamDumper>>,                 // ← 可选：解密流量导出
}
```

### 4.3 AUTH TLS → StartTlsInterceptObject 的创建

当 `FtpInterceptObject` 在控制通道中继时检测到 `AUTH TLS` 命令且服务器回复 `234 Ready`：

**文件**：`inspect/ftp/object.rs:316-332`

```rust
} else if is_auth_tls_command(&clt_line) {
    // 转发 AUTH TLS 到上游
    if ups_writer.write_all(&clt_line).await.is_err() { break; }
    // 读取服务器响应
    if let Some(resp) = read_ftp_response(&mut ups_reader).await {
        let _ = clt_w.write_all(&resp).await;
        if resp.starts_with(b"234") {
            // 服务器同意升级 TLS → 构造 StartTlsInterceptObject
            let clt_r = clt_reader.into_inner();
            let ups_r = ups_reader;
            let ups_w = ups_writer;
            return Ok(FtpNextAction::StartTls {
                clt_r, clt_w, ups_r, ups_w,
            });
        }
    }
}
```

上层 `do_intercept()` 收到 `FtpNextAction::StartTls`（`object.rs:229-251`）：

```rust
FtpNextAction::StartTls { clt_r, clt_w, ups_r, ups_w } => {
    if let Some(tls_interception) = self.ctx.tls_interception() {
        let mut start_tls_obj = StartTlsInterceptObject::new(
            self.ctx.clone(),
            self.upstream.clone(),
            tls_interception,       // ← 包含 CertAgentHandle
            StartTlsProtocol::Ftp,  // ← 标记协议为 FTP
        );
        start_tls_obj.set_io(clt_r, clt_w, Box::new(ups_r), ups_w);
        Ok(Some(StreamInspection::StartTls(start_tls_obj)))
    } else {
        Ok(None)  // 没有配置 TLS 拦截则跳过
    }
}
```

### 4.4 TLS MITM 完整握手流程

**核心代码**：`inspect/start_tls/tls.rs:30-141` — `do_intercept_tls()`

以下是逐步详解：

#### 步骤 1：读取客户端 ClientHello

```rust
// start_tls/mod.rs:149-152
let client_hello = self.tls_interception
    .read_client_hello(&mut clt_r, &mut clt_r_buf)  // 解析 ClientHello 读取 SNI、ALPN
    .await?;
```

从客户端的 TLS ClientHello 中提取 **SNI 主机名** 和 **ALPN 协议列表**。

#### 步骤 2：创建 TLS KeyLog 缓冲 + 构造上游 SSL 上下文

```rust
// start_tls/tls.rs:56-79
// 🔴 根据 auditor 配置决定是否启用 TLS KeyLog
let keylog_buffer = if self.ctx.audit_handle.tls_keylog() {
    Some(Arc::new(TlsKeyLogBuffer::new_with_max(
        self.ctx.audit_handle.tls_keylog_max_entries(),  // 默认 128 条
    )))
} else {
    None
};

let ups_ssl = self.tls_interception.client_config
    .build_ssl(sni_hostname, &self.upstream, alpn_ext, keylog_buffer.clone())?;
```

**KeyLog 捕获原理**：`keylog_buffer` 通过 OpenSSL 的 `SSL_set_ex_data` + `SSL_CTX_set_keylog_callback` 注册到 SSL 上下文中。TLS 握手期间，OpenSSL 每产出一条 NSS KeyLog 格式的行（如 `CLIENT_RANDOM <hex> <hex>`），回调自动写入 buffer：

```rust
// lib/g3-types/src/net/openssl/client/intercept.rs:503-509
ctx_builder.set_keylog_callback(move |ssl, line| {
    if let Some(buffer) = ssl.ex_data(keylog_index) {
        if let Some(entry) = TlsKeyLogEntry::parse(line) {
            buffer.add_entry(entry);  // ← 非阻塞写入，满 128 条后丢弃
        }
    }
});
```

使用 SNI 主机名和 ALPN 构造到上游的 TLS 客户端 SSL 上下文（OpenSSL `Ssl` 对象）。

#### 步骤 3：与上游 TLS 握手（获取真实证书）

```rust
// start_tls/tls.rs:76-90
let ups_tls_connector = SslConnector::new(ups_ssl, tokio::io::join(ups_r, ups_w))?;
let ups_tls_stream = tokio::time::timeout(
    self.tls_interception.client_config.handshake_timeout,
    ups_tls_connector.connect(),
).await??;
```

代理作为 TLS 客户端与上游 FTP 服务器完成 TLS 握手。握手成功后拿到 `ups_tls_stream`。

#### 步骤 4：提取上游真实证书 + 请求 g3fcgen 生成伪造证书

```rust
// start_tls/tls.rs:92-113
let upstream_cert = ups_tls_stream.ssl().peer_certificate()  // 获取上游的真实 X.509 证书
    .ok_or_else(|| TlsInterceptionError::NoFakeCertGenerated(...))?;

let cert_domain = sni_hostname
    .map(|v| v.to_string())
    .unwrap_or_else(|| self.upstream.host().to_string());   // 从 SNI 或上游地址提取域名

// 🔴 核心：向 g3fcgen 请求生成伪造证书
let cert_pair = self.tls_interception.cert_agent
    .fetch(
        TlsServiceType::from(self.protocol),  // Ftp
        CERT_USAGE,                           // TlsServer
        Arc::from(cert_domain),               // "ftp.example.com"
        upstream_cert,                        // 上游真实证书（作为 mimic 模板）
    )
    .await
    .ok_or_else(|| TlsInterceptionError::NoFakeCertGenerated(...))?;
```

#### 步骤 4a：CertAgentHandle → g3fcgen 的通信协议

`cert_agent.fetch()` (`lib/g3-cert-agent/src/handle.rs:45-58`) 内部流程：

```
CertAgentHandle.fetch(service=Ftp, usage=TlsServer, host="ftp.example.com", mimic_cert)
    │
    ├─[1] 构造 CacheQueryKey { service, usage, host, mimic_cert }
    │
    ├─[2] EffectiveCacheHandle.fetch() → 先查缓存
    │     ├─ 命中 → 直接返回 FakeCertPair
    │     └─ 未命中 ↓
    │
    ├─[3] CacheQueryKey.encode() → MessagePack 格式
    │     {
    │       host:    "ftp.example.com"
    │       service: 3 (Ftp)
    │       usage:   0 (TlsServer)
    │       cert:    <上游真实证书的 DER 字节>  ← 作为 mimic 模板
    │     }
    │
    ├─[4] UDP socket.send() → 127.0.0.1:2999 → g3fcgen 进程
    │
    ├─[5] 等待 g3fcgen 响应（默认 4s 超时）
    │
    └─[6] Response::parse() → FakeCertPair { pem_cert, der_private_key }
           └─ 缓存（protective_ttl=10s, maximum_ttl=300s）
```

**通信方式**：本地 UDP socket，MessagePack 序列化，默认目标地址 `127.0.0.1:2999`。

**g3fcgen** 独立进程收到请求后：
- 使用 CA 根证书签发伪造的服务器证书
- 伪造证书的 Subject/SAN 复制自上游真实证书（`mimic_cert`）
- 返回 PEM 格式证书链 + DER 格式私钥
- 支持缓存命中复用（避免每次 TLS 握手都生成新证书）

#### 步骤 5：将伪造证书安装到客户端 SSL 上下文

```rust
// start_tls/tls.rs:116-118
cert_pair.add_to_ssl(&mut clt_ssl)  // 设置伪造证书 + 私钥
    .map_err(TlsInterceptionError::InternalOpensslServerError)?;
```

将 g3fcgen 返回的伪造证书和私钥设置到面向客户端的 SSL 上下文中。

#### 步骤 6：设置 ALPN（协议协商）

```rust
// start_tls/tls.rs:120-124
if let Some(alpn_protocol) = ups_tls_stream.ssl().selected_alpn_protocol() {
    self.tls_interception.server_config
        .set_selected_alpn(&mut clt_ssl, alpn_protocol.to_vec());
}
```

将上游协商好的 ALPN 协议设置到客户端 SSL，确保客户端看到的协议与上游一致。

#### 步骤 7：与客户端完成 TLS 握手

```rust
// start_tls/tls.rs:126-138
let clt_acceptor = SslAcceptor::new(
    clt_ssl,
    tokio::io::join(OnceBufReader::new(clt_r, clt_r_buf), clt_w), // 拼接已读的 ClientHello 缓冲
    self.tls_interception.server_config.accept_timeout,
)?;
let clt_tls_stream = clt_acceptor.accept().await?;  // 代理作为 TLS 服务端接受客户端连接
```

注意：代理携带**伪造证书**（由 g3fcgen 签发）接受客户端 TLS 握手。客户端需要信任 g3fcgen 的 CA 根证书，否则会显示证书警告。

#### 步骤 8：将 TLS 流拆分并重新进入 FTP 协议检测

```rust
// start_tls/tls.rs:140
Ok(self.transfer_connected(clt_tls_stream, ups_tls_stream))
```

`transfer_connected()` (`start_tls/mod.rs:190-230`) 将双向 TLS 流拆分，创建新的 `FtpInterceptObject`（标记 `set_from_starttls()`），重新进入 FTP 协议检测循环。此时流是**已解密**的，后续的 USER/PASS/PASV/STOR 命令都以明文通过检测。

### 4.5 FTPS 域名全局存储

TLS 握手完成后，代理将 FTPS 域名保存到全局状态，供数据通道使用：

```rust
// http_proxy/task/connect/task.rs:478-481
if is_ftps_control {
    if let Host::Domain(domain) = self.upstream.host() {
        get_ftp_upload_state().mark_ftps_domain(
            client_ip, server_ip, "ftp.example.com"
        );
    }
}
```

### 4.6 FTPS 数据通道处理

数据通道的 CONNECT 请求到达时，先查 FTPS 域名：

```rust
// connect/task.rs:485
let ftps_domain = get_ftp_upload_state().get_ftps_domain(client_ip, server_ip);
let is_ftps_data_channel = ftps_domain.is_some();

if is_ftps_data_channel {
    // 走 DPI 通道：使用 ftps_domain 生成 TLS 伪造证书（再次调用 g3fcgen）
    // → TLS MITM 解密数据通道
    // → 解密后的上传数据进入 ICAP 审计
}
```

### 4.7 FTPS 完整时序图

```
时间线      FTP 客户端                 g3proxy                    FTP 服务器          g3fcgen
───────    ──────────               ────────                   ──────────          ───────
           CONNECT :21 ────────────►
                                        ├─ TCP → :21 ──────────►
                                        │                       ├─ 220 Welcome ──►
           ◄── 220 Welcome ──────────  │
           USER xxx ────────────────►  │
                                        ├─ USER xxx ───────────►
                                        │◄── 331 Password ──────│
           ◄── 331 Password ─────────  │
           AUTH TLS ────────────────►  │
                                        ├─ AUTH TLS ───────────►
                                        │◄── 234 Ready ─────────│
           ◄── 234 Ready ────────────  │
                                        │
           ClientHello ──────────────► │
                                        ├─ TLS 握手 ───────────►│
                                        │  (OpenSSL keylog callback
                                        │   写入 TlsKeyLogBuffer)  │  ← 🔑 TLS KeyLog 捕获
                                        │◄── 真实证书 ───────────│
                                        │                        │
                                        ├─ UDP req ──────────────────────────────►│
                                        │   { host:"ftp.example.com",              │
                                        │     mimic_cert:<上游DER> }               │
                                        │◄── UDP rsp ──────────────────────────────│
                                        │   { pem_cert, der_key, ttl }             │
                                        │                                           │
           ◄── 伪造证书 ──────────────  │  (g3fcgen CA 签发)
           TLS 握手完成                 │  TLS 握手完成
           │                            │  │
           │  解密后的 FTP 命令流 ──────┤──┤
           │                            │  │
           mark_ftps_domain("ftp.example.com")  ← 保存域名
           USER/PASS                    │
           PASV ◄── 227 (ip,port) ────  │
           STOR /path → mark_upload()   │
           │                            │
           CONNECT :54321 ─────────────►│
                                        ├─ get_ftps_domain() → 命中
                                        ├─ 再次 TLS MITM (g3fcgen)
                                        ├─ consume_upload() → 命中
                                        ├─ ICAP REQMOD 审计
                                        │  (携带五元组 + TLS KeyLog)     ← 5-tuple + SSL keylog
                                        └─ 226 Transfer complete
```

### 4.8 g3fcgen 架构总结

| 组件 | 说明 |
|------|------|
| **g3fcgen** | 独立 Rust 进程，监听 UDP `127.0.0.1:2999`，持有 CA 根证书私钥 |
| **CertAgentHandle** | 代理内证书请求句柄，通过 `EffectiveCacheHandle` 管理缓存 |
| **通信协议** | UDP + MessagePack，请求包含 (domain, service_type, cert_usage, mimic_cert) |
| **缓存策略** | L1 内存缓存：保护 TTL=10s（出错时兜底），最大 TTL=300s |
| **伪造证书** | 复制上游证书的 Subject/SAN，用 g3fcgen CA 私钥重新签名 |
| **运行时** | 独立 Tokio 线程 `cert-generate`，通过 `spawn_cert_generate_runtime()` 启动 |

---

## 5. 核心数据结构

### 5.1 GlobalUploadState（全局上传状态）

**文件**：`g3proxy/src/serve/ftp_proxy/upload_state.rs`

```rust
// 全局单例 — 两条独立 HTTP CONNECT 连接之间的桥梁
GlobalUploadState {
    // 维度一：FTPS 域名映射
    // Key:   (客户端IP, 服务器IP)
    // Value: "ftp.example.com"
    // 生命周期: mark_ftps_domain() → get_ftps_domain()
    // 用途:   控制通道保存 → 数据通道查询（TLS 证书生成）

    // 维度二：上传命令标记
    // Key:   (客户端IP, 服务器IP)
    // Value: PendingUploadInfo { ftp_command, ftp_path, seq }
    // 生命周期: mark_upload() → consume_upload()（取出即销毁）
    // 用途:   控制通道标记 → 数据通道查询 + 消费
}

struct PendingUploadInfo {
    ftp_command: String,    // "STOR" / "APPE" / "STOU"
    ftp_path: String,       // "/path/to/file.dat"
    seq: usize,             // 序号
}
```

### 5.2 FtpUploadAuditContext（上传审计上下文）

**文件**：`g3proxy/src/serve/ftp_proxy/audit_bridge.rs`

```rust
struct FtpUploadAuditContext {
    icap_client: Arc<IcapReqmodClient>,     // ICAP 客户端
    idle_wheel: Arc<IdleWheel>,             // 空闲检测轮
    copy_config: StreamCopyConfig,          // 流拷贝配置（限速/缓冲区）
    client_addr: Option<SocketAddr>,        // 客户端地址
    ftp_command: String,                    // FTP 命令名
    ftp_path: String,                       // 文件路径
    data_channel_tuple: Option<ConnectionTuple>,  // 连接四元组
}

struct ConnectionTuple {
    server_addr: SocketAddr,    // 代理侧地址
    remote_addr: SocketAddr,    // 上游地址
    protocol: ConnectionProtocol, // Tcp / Udp
}
```

### 5.3 关键枚举

```rust
// FTP 命令检测
enum FtpNextAction {
    StartTls { ... },  // AUTH TLS → 触发 TLS 中间人
    Finish,            // 普通连接结束
}

// TLS 上游类型（ftp_proxy 使用）
enum TlsUpstreamType {
    PlainFtp,         // 明文 FTP
    ExplicitFtps,     // AUTH TLS（先 TCP → 发 AUTH TLS → TLS 握手）
    ImplicitFtps,     // 隐式 FTPS（连接后直接 TLS 握手）
}
```

---

## 6. 与 native ftp_proxy 的关键区别

| 维度 | etc/ftp/ (HTTP CONNECT 模式) | serve/ftp_proxy/ (原生 FTP 代理) |
|------|-----------------------------|--------------------------------|
| **入口协议** | HTTP CONNECT（FTP 客户端配 HTTP 代理） | FTP 原生协议（FTP 客户端直连） |
| **服务端类型** | `http_proxy` | `ftp_proxy` |
| **控制通道** | HTTP CONNECT 隧道 | TCP 直连 + FTP 协议解析 |
| **PASV 重写** | **不重写** | **重写**为本地监听地址 |
| **数据通道中转** | 客户端发起第二条 CONNECT | 代理本地监听接受客户端连接 |
| **数据通道拦截** | 全局状态 `consume_upload()` 查询 | 代理直接持有 `PendingDataChannel` |
| **FTP 命令解析** | `inspect/ftp/object.rs` | `serve/ftp_proxy/ctl_common.rs` |
| **上传审计** | `connect/task.rs` → `ftp_proxy/audit_bridge.rs` | `ftp_proxy/task.rs` → `ftp_proxy/audit_bridge.rs` |
| **适用场景** | FTP 客户端（FileZilla/WinSCP）配 HTTP 代理 | FTP 客户端直连 FTP 代理端口 |

### 为什么 etc/ftp/ 不用 ftp_proxy？

`etc/ftp/` 配置使用 `http_proxy` 而非 `ftp_proxy`，原因是：

1. **复用 HTTP CONNECT 基础设施**：http_proxy 已有的 CONNECT 处理、escaper 路由、auditor DPI 全部复用
2. **避免额外的监听端口**：不需要单独开 FTP 代理端口
3. **统一管理面**：所有代理流量走同一个端口（3128），便于防火墙/NAT 配置

---

## 7. 代码路径索引

### 7.1 启动与配置加载

| 阶段 | 文件 | 行号 |
|------|------|:---:|
| 启动入口 | `g3proxy/src/main.rs` | 全部 |
| 配置分发 | `g3proxy/src/config/mod.rs` | — |
| http_proxy 配置解析 | `g3proxy/src/config/server/http_proxy.rs` | — |
| ftp_auditor 配置解析 | `g3proxy/src/config/audit/auditor.rs` | — |
| TLS 拦截配置 | `g3proxy/src/config/audit/auditor.rs` | `tls_interception_client` / `tls_cert_generator` |
| g3fcgen Agent 启动 | `lib/g3-cert-agent/src/runtime.rs` | `spawn_cert_generate_runtime()` |

### 7.2 控制通道（阶段一）

| 步骤 | 文件 | 行号 |
|------|------|:---:|
| HTTP CONNECT 接受 | `serve/http_proxy/task/connect/task.rs` | 开头 |
| DPI 协议识别入口 | `inspect/stream/mod.rs` | `:270` |
| DPI 初始数据收集 | `inspect/stream/object.rs` | `:78-124` |
| FTP 协议检测 | `lib/g3-dpi/src/protocol/ftp.rs` | `:10-103` |
| FtpInterceptObject 创建 | `inspect/stream/object.rs` | `:202-211` |
| 控制通道中继 | `inspect/ftp/object.rs` | `:260-376` |
| 上传命令标记 | `inspect/ftp/object.rs` | `:297-311` |
| AUTH TLS 检测 → StartTls | `inspect/ftp/object.rs` | `:316-332` |
| PASV 透传（不重写） | `inspect/ftp/object.rs` | 注释 `:258` |

### 7.3 TLS MITM（FTPS AUTH TLS）

| 步骤 | 文件 | 行号 |
|------|------|:---:|
| StartTlsInterceptObject 创建 | `inspect/ftp/object.rs` | `:237-249` |
| do_intercept 入口 | `inspect/start_tls/mod.rs` | `:140-159` |
| 读取 ClientHello (SNI/ALPN) | `inspect/tls/mod.rs` | `read_client_hello()` |
| 上游 TLS 握手 | `inspect/start_tls/tls.rs` | `:76-90` |
| 提取上游真实证书 | `inspect/start_tls/tls.rs` | `:92-94` |
| **请求 g3fcgen 伪造证书** | `inspect/start_tls/tls.rs` | `:99-113` |
| CertAgentHandle.fetch() | `lib/g3-cert-agent/src/handle.rs` | `:45-58` |
| CacheQueryKey.encode() (MsgPack) | `lib/g3-cert-agent/src/lib.rs` | `:70-100` |
| UDP 发送/接收 | `lib/g3-cert-agent/src/query.rs` | `:56-69` (发), `:71-93` (收) |
| 伪造证书安装到 client SSL | `inspect/start_tls/tls.rs` | `:116-118` |
| ALPN 设置 | `inspect/start_tls/tls.rs` | `:120-124` |
| 客户端 TLS 握手 | `inspect/start_tls/tls.rs` | `:126-138` |
| transfer_connected → 新 FtpInterceptObject | `inspect/start_tls/mod.rs` | `:190-287` |
| 连接级别 FTPS 域名保存 | `serve/http_proxy/task/connect/task.rs` | `:478-481` |

### 7.4 数据通道（阶段二）

| 步骤 | 文件 | 行号 |
|------|------|:---:|
| 数据通道 CONNECT 入口 | `serve/http_proxy/task/connect/task.rs` | — |
| FTPS 域名查询 | `connect/task.rs` | `:485` |
| 上传状态消费 | `connect/task.rs` | `:507` |
| 创建审计上下文 | `connect/task.rs` | `:520-528` |
| ICAP 审计执行 | `ftp_proxy/audit_bridge.rs` | `run_ftp_upload_audit_or_relay_bidi()` |

### 7.5 共享组件（被两个模式共同使用）

| 组件 | 文件 | 说明 |
|------|------|------|
| 上传状态全局单例 | `serve/ftp_proxy/upload_state.rs` | `mark_upload()` / `consume_upload()` |
| FTPS 域名存储 | `serve/ftp_proxy/upload_state.rs` | `mark_ftps_domain()` / `get_ftps_domain()` |
| 审计桥接 | `serve/ftp_proxy/audit_bridge.rs` | 构造 ICAP 请求 + 双向中继 |
| FTP 命令解析 | `serve/ftp_proxy/ctl_common.rs` | `is_upload_command()` / `is_auth_tls_command()` |
| FTP 响应读取 | `serve/ftp_proxy/ctl_common.rs` | `read_ftp_response()` / `parse_pasv_response()` |

### 7.7 ICAP 审计增强链路（5元组 + TLS KeyLog + FTP 适配器）

| 组件 | 文件 | 说明 |
|------|------|------|
| FtpUploadAuditContext (五元组+keylog) | `g3proxy/src/serve/ftp_proxy/audit_bridge.rs` | `data_channel_tuple` + `keylog_buffer` 字段 |
| ConnectionTuple 数据结构 | `lib/g3-icap-client/src/reqmod/mod.rs` | 五元组：proxy IP:Port + remote IP:Port + protocol |
| add_connection_tuple() 序列化 | `lib/g3-icap-client/src/serialize/header.rs` | → X-Proxy-IP, X-Proxy-PORT, X-Remote-IP, X-Remote-PORT, X-Proto-P |
| TlsKeyLogBuffer | `lib/g3-types/src/net/tls/keylog.rs` | NSS 格式 KeyLog 缓冲，最大 100 条/连接 |
| add_keylog_headers() 序列化 | `lib/g3-icap-client/src/serialize/header.rs` | → X-TLS-VERSION, X-TLS-CIPHER, X-TLS-SERVER_RANDOM, X-TLS-KeyLog-* |
| FtpUploadAdapter (FTP→ICAP 适配器) | `lib/g3-icap-client/src/reqmod/ftp/mod.rs` | chunked 转发 + fail-open 设计 |
| H1/H2 适配器 KeyLog + 五元组注入 | `lib/g3-icap-client/src/reqmod/h1/mod.rs` + `h2/mod.rs` | `set_keylog_buffer()` + `set_connection_tuple()` |
| TLS 握手 KeyLog 捕获 | `lib/g3-types/src/net/openssl/client/intercept.rs` | OpenSSL `set_keylog_callback` → `TlsKeyLogEntry::parse` |
| auditor tls_keylog 配置解析 | `g3proxy/src/config/audit/auditor.rs` | `tls_keylog: { enable, max_entries }` |
| AuditHandle tls_keylog 开关 | `g3proxy/src/audit/handle.rs` | `tls_keylog()` / `tls_keylog_max_entries()` |

### 7.8 g3fcgen 证书生成链路

| 组件 | 文件 | 说明 |
|------|------|------|
| CertAgentConfig (UDP 地址) | `lib/g3-cert-agent/src/config/mod.rs` | 默认 `127.0.0.1:2999` |
| CertAgentHandle | `lib/g3-cert-agent/src/handle.rs` | `fetch()` / `pre_fetch()` |
| 缓存查询 key | `lib/g3-cert-agent/src/lib.rs` | `CacheQueryKey` + `encode()` |
| UDP 查询运行时 | `lib/g3-cert-agent/src/query.rs` | `QueryRuntime` — 收发 UDP + 超时 |
| 请求/响应协议 | `lib/g3-cert-agent/src/request.rs` + `response.rs` | MessagePack 编解码 |
| g3fcgen 独立进程 | `g3fcgen/` (独立 crate) | 监听 UDP + 生成伪造证书 |
| 运行时启动 | `lib/g3-cert-agent/src/runtime.rs` | `spawn_cert_generate_runtime()` |

---

## 8. 运行命令

```bash
# 1. 启动 g3fcgen 证书生成服务（FTPS 场景必需）
./target/debug/g3fcgen -c g3fcgen/examples/simple/g3fcgen.yaml &

# 2. 启动 c-icap 服务器（ICAP 审计服务）
sudo ./bin/c-icap -N -f ./etc/c-icap.conf

# 3. 启动 g3proxy（加载 etc/ftp/ 配置）
./target/debug/g3proxy --conf-dir etc/ftp/

# 4. 配置 FTP 客户端
#    代理类型: HTTP/1.1 CONNECT
#    代理地址: 0.0.0.0:3128
#    目标地址: 按 FTP 服务器实际地址填写
#    注意: FTPS 场景需客户端信任 g3fcgen 的 CA 根证书
```

---

> 文档基于 g3proxy v1.12.3 源码 + etc/ftp/ 自定义配置生成  
> 分析日期：2026-06-26
