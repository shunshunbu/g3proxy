# g3proxy 发布包构建流程分析

> 基于 `doc/build_and_package.md`、CI 配置、打包脚本和上游 v1.13.0 源码分析

---

## 目录

1. [整体构建流水线](#1-整体构建流水线)
2. [阶段一：源码 Tarball 生成](#2-阶段一源码-tarball-生成)
3. [阶段二：DEB 包构建](#3-阶段二deb-包构建)
4. [阶段三：RPM 包构建](#4-阶段三rpm-包构建)
5. [阶段四：Docker 镜像构建](#5-阶段四docker-镜像构建)
6. [CI/CD 自动化发布](#6-cicd-自动化发布)
7. [构建产物清单](#7-构建产物清单)
8. [本地构建 vs 发布构建对比](#8-本地构建-vs-发布构建对比)

---

## 1. 整体构建流水线

```
┌──────────────────────────────────────────────────────────┐
│                    CI Pipeline (CircleCI)                 │
│                                                          │
│  ┌────────────────────┐                                  │
│  │ build-source-tar   │  源码 Tarball 生成               │
│  │ - git archive      │                                  │
│  │ - prune workspace  │                                  │
│  │ - cargo vendor     │                                  │
│  │ - bundle licenses  │                                  │
│  └────────┬───────────┘                                  │
│           │ .tar.xz                                      │
│           ▼                                              │
│  ┌────────────────────┐    ┌────────────────────────┐   │
│  │   build-deb        │    │    build-rpm            │   │
│  │   (Matrix x10)     │    │    (Matrix x10)         │   │
│  │                    │    │                         │   │
│  │ debian:trixie      │    │ rockylinux:10           │   │
│  │ debian:bookworm    │    │ rockylinux:9            │   │
│  │ debian:bullseye    │    │ rockylinux:8            │   │
│  │ ubuntu:24.04       │    │ opensuse/leap:16.0      │   │
│  │ ubuntu:22.04       │    │ opensuse/leap:15.6      │   │
│  │ × large + arm.med  │    │ × large + arm.medium    │   │
│  │ = 10 个变体        │    │ = 10 个变体             │   │
│  └────────────────────┘    └────────────────────────┘   │
│                                                          │
│  产物: 20+ .deb / .rpm 包 → Cloudsmith 分发             │
│  额外: Docker 镜像 → Docker Hub / GHCR                   │
└──────────────────────────────────────────────────────────┘
```

---

## 2. 阶段一：源码 Tarball 生成

**脚本**：`scripts/release/build_tarball.sh`

这是整个流水线的起点，生成一个**自包含、可离线编译**的源码包。

### 2.1 调用方式

```bash
# 方式一：基于 git tag（正式发布）
./scripts/release/build_tarball.sh g3proxy-v1.12.3

# 方式二：基于 git commit（快照版本）
./scripts/release/build_tarball.sh g3proxy HEAD
./scripts/release/build_tarball.sh g3proxy-v1.12.3-20260629 abc1234
```

### 2.2 参数解析

```bash
# 从 tag 提取应用名和版本号
SOURCE_NAME=$(echo "g3proxy-v1.12.3" | sed 's/\(.*\)-v[0-9].*/\1/')  # → "g3proxy"
SOURCE_VERSION="1.12.3"
PKG_VERSION=$(echo "1.12.3" | tr '-' '.')  # → "1.12.3"

# 提取 git commit 时间戳（用于可重现构建）
SOURCE_TIMESTAMP=$(git show -s --pretty="format:%ct" "${GIT_REVISION}")
```

### 2.3 执行步骤

| 步骤 | 操作 | 产物 |
|:---:|------|------|
| ① | `git archive` 导出源码 | `g3proxy-1.12.3/` 目录 |
| ② | `cargo run --bin capnp-generate` | 生成 Cap'n Proto Rust 代码 |
| ③ | `list_local_deps.py` 解析 `Cargo.lock` | 递归找出 g3proxy 依赖的全部本地 crate |
| ④ | `prune_workspace.py` 裁剪 `Cargo.toml` | 从 workspace 中移除不需要的应用（g3bench/g3statsd/g3tiles 等） |
| ⑤ | 清理无用 crate 目录 |   删除已移除应用的源码目录 |
| ⑥ | `prune_patch.py` 清理无用 patch |   移除 `[patch.crates-io]` 中不再需要的条目 |
| ⑦ | `cargo vendor` 下载全部依赖 | `vendor/` 目录 + `.cargo/config.toml` 配置 |
| ⑧ | `bundle_license.py` 聚合许可证 | `LICENSE-BUNDLED` 文件 |
| ⑨ | `sphinx-build` 生成 HTML 文档 | `sphinx/g3proxy/_build/html/` |
| ⑩ | 移动 `debian/` 和 `.spec` 到顶层 | 打包文件就位 |
| ⑪ | `tar -Jcf` 创建 xz 压缩包 | `g3proxy-1.12.3.tar.xz` |

### 2.4 裁剪逻辑（prune_workspace.py）

g3proxy 所在 workspace 包含 **7 个应用**（g3bench、g3fcgen、g3iploc、g3keymess、g3proxy、g3statsd、g3tiles）和 35+ 个库。发布单个应用时不需要携带其他应用的源码。

```python
# prune_workspace.py 核心逻辑
for m in data['workspace']['members']:
    if m.startswith('g3proxy'):        # 保留 g3proxy 本身
        members.add(m)
for lib_dep:
    members.add("lib/" + lib_dep)      # 保留被 g3proxy 依赖的本地库
# 其余全部移除
```

**实际效果**：假定 g3proxy 依赖 lib 中的 20 个 crate，裁剪后 workspace 只保留 `g3proxy/` + `lib/` 中的 20 个 crate，删除 `g3bench/`、`g3statsd/`、`g3tiles/` 等不相关的应用。

### 2.5 可重现构建

```bash
# 固定时间戳、所有权、排序，确保同一源码生成完全相同的 .tar.xz
PERMISSION_OPTS="--mode=u=rwX,g=rwX,o=rX"
REPRODUCIBLE_OPTS="--mtime=@${SOURCE_TIMESTAMP} --owner=g3:1000 --group=g3:1000 --sort=name"
tar -Jcf "g3proxy-1.12.3.tar.xz" ${REPRODUCIBLE_OPTS} -C "${BUILD_DIR}" .
```

---

## 3. 阶段二：DEB 包构建

### 3.1 构建流程

```
g3proxy-1.12.3.tar.xz
        │
        ├─ tar xf → g3proxy-1.12.3/
        │
        ├─ sed s/UNRELEASED/<codename>/ debian/changelog  # 填发布代号
        │
        └─ dpkg-buildpackage -b -uc
             │
             └─ debian/rules (dh sequencer)
                  │
                  ├─ dh_auto_build:
                  │    cargo build --frozen --profile release-lto \
                  │      --no-default-features \
                  │      --features lua54,rustls-ring,quic,vendored-c-ares \
                  │      --package g3proxy \
                  │      --package g3proxy-ctl \
                  │      --package g3proxy-lua
                  │    cargo build ... --package g3proxy-ftp
                  │
                  ├─ dh_auto_install:
                  │    install → debian/tmp/usr/bin/g3proxy
                  │    install → debian/tmp/usr/bin/g3proxy-ctl
                  │    install → debian/tmp/usr/bin/g3proxy-ftp
                  │    install → debian/tmp/usr/bin/g3proxy-lua
                  │
                  └─ dh_builddeb → g3proxy_1.12.3-1_amd64.deb
```

### 3.2 debian/rules 关键配置

```makefile
PACKAGE_NAME := g3proxy
BUILD_PROFILE := release-lto         # ← LTO 优化级别
LUA_FEATURE   := $(shell scripts/package/detect_lua_feature.sh)    # lua54 / lua53
CARES_FEATURE := $(shell scripts/package/detect_c-ares_feature.sh) # vendored-c-ares / c-ares
```

### 3.3 特性自动检测

| 检测脚本 | 逻辑 | 示例输出 |
|----------|------|---------|
| `detect_lua_feature.sh` | `pkg-config --exists lua54` → `lua54`，否则尝试 `lua53` | `lua54` |
| `detect_c-ares_feature.sh` | 如果系统有 `libc-ares` 则用 `vendored-c-ares`，否则 `c-ares` | `vendored-c-ares` |
| `detect_openssl_feature.sh` | 检测系统 OpenSSL 变体 | `vendored-boringssl` / `openssl` |

### 3.4 产物

```
g3proxy_1.12.3-1_amd64.deb      # Debian/Ubuntu amd64
g3proxy_1.12.3-1_arm64.deb      # Debian/Ubuntu arm64
g3proxy_1.12.3-1.dsc            # 源码包描述
g3proxy_1.12.3-1.debian.tar.xz  # Debian 打包补丁
g3proxy_1.12.3.orig.tar.xz     # 原始源码包
```

---

## 4. 阶段三：RPM 包构建

### 4.1 RPM spec 核心内容（g3proxy.spec）

```spec
Name:           g3proxy
Version:        1.12.0
Release:        1%{?dist}
Source0:        %{name}-%{version}.tar.xz

BuildRequires:  gcc, make, pkgconf, cmake
BuildRequires:  lua-devel, openssl-devel
Requires:       ca-certificates

%build
G3_PACKAGE_VERSION="%{version}-%{release}" \
  cargo build --frozen --profile release-lto \
    --no-default-features \
    --features $LUA_FEATURE,rustls-ring,quic,$CARES_FEATURE \
    --package g3proxy --package g3proxy-ctl --package g3proxy-lua
cargo build --frozen --profile release-lto --package g3proxy-ftp
sh g3proxy/service/generate_systemd.sh

%install
install -m 755 -D target/release-lto/g3proxy      %{buildroot}%{_bindir}/g3proxy
install -m 755 -D target/release-lto/g3proxy-ctl  %{buildroot}%{_bindir}/g3proxy-ctl
install -m 755 -D target/release-lto/g3proxy-ftp  %{buildroot}%{_bindir}/g3proxy-ftp
install -m 755 -D target/release-lto/g3proxy-lua  %{buildroot}%{_bindir}/g3proxy-lua
install -m 644 -D g3proxy/service/g3proxy@.service %{buildroot}/lib/systemd/system/

%files
%{_bindir}/g3proxy
%{_bindir}/g3proxy-ctl
%{_bindir}/g3proxy-ftp
%{_bindir}/g3proxy-lua        # ← 注意：本地 v1.12.3 无此文件（上游 v1.13.0 新增）
/lib/systemd/system/g3proxy@.service
%license LICENSE LICENSE-BUNDLED LICENSE-FOREIGN
%doc sphinx/g3proxy/_build/html
```

### 4.2 构建命令

```bash
# 标准方式
rpmbuild -ta ./g3proxy-1.12.3.tar.xz

# 手动方式（调试用）
tar xvf g3proxy-1.12.3.tar.xz ./g3proxy-1.12.3/g3proxy.spec
cp g3proxy-1.12.3.tar.xz ~/rpmbuild/SOURCES/
rpmbuild -ba ./g3proxy-1.12.3/g3proxy.spec
```

### 4.3 产物

```
g3proxy-1.12.3-1.el8.x86_64.rpm     # RockyLinux 8
g3proxy-1.12.3-1.el9.x86_64.rpm     # RockyLinux 9
g3proxy-1.12.3-1.el10.x86_64.rpm    # RockyLinux 10
g3proxy-1.12.3-1.suse.lp156.x86_64.rpm  # OpenSUSE Leap 15.6
g3proxy-1.12.3-1.suse.lp160.x86_64.rpm  # OpenSUSE Leap 16.0
g3proxy-1.12.3-1.src.rpm            # 源码 RPM
```

---

## 5. 阶段四：Docker 镜像构建

### 5.1 多阶段构建（debian.Dockerfile）

```dockerfile
# 阶段 1：编译（使用 Rust 官方镜像）
FROM rust:bookworm AS builder
WORKDIR /usr/src/g3
COPY . .
RUN apt-get update && apt-get install -y libclang-dev cmake capnproto
RUN cargo build --profile release-lto \
    --no-default-features \
    --features vendored-boringssl,rustls-ring,quic,vendored-c-ares \
    -p g3proxy -p g3proxy-ctl

# 阶段 2：运行（最小化镜像）
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/src/g3/target/release-lto/g3proxy /usr/bin/
COPY --from=builder /usr/src/g3/target/release-lto/g3proxy-ctl /usr/bin/
ENTRYPOINT ["/usr/bin/g3proxy"]
CMD ["-Vvv"]
```

### 5.2 Docker 构建命令

```bash
# 从本地源码构建
docker build -f g3proxy/docker/debian.Dockerfile . -t g3proxy:latest

# 直接从 GitHub 构建
docker build -f g3proxy/docker/debian.Dockerfile github.com/bytedance/g3 -t g3proxy:latest

# 使用预生成的源码 tarball
docker build -f g3proxy/docker/debian.Dockerfile https://example.com/g3proxy-1.12.3.tar.xz -t g3proxy:1.12.3
```

### 5.3 Docker vs DEB/RPM 差异

| 维度 | DEB/RPM 包 | Docker 镜像 |
|------|-----------|------------|
| OpenSSL | 系统库（`libssl-dev`） | `vendored-boringssl`（静态链接） |
| c-ares | `vendored-c-ares`（静态链接） | `vendored-c-ares` |
| Lua | 系统库（`lua54`） | 不启用 Lua |
| Rustls | `rustls-ring` | `rustls-ring` |
| QUIC | ✓ | ✓ |
| 产出二进制 | 4 个（proxy/ctl/ftp/lua） | 2 个（proxy/ctl） |

---

## 6. CI/CD 自动化发布

### 6.1 CircleCI 流水线

```yaml
# .circleci/config.yml
parameters:
  package:
    type: string
    default: g3mkcert    # 默认构建，流水线触发时覆盖
  version:
    type: string
    default: 0.0.1

workflows:
  build-package:
    jobs:
      - build-source-tar    # ← 第一步：生成源码包
      - build-deb:          # ← 第二步：并行构建 DEB
          requires: [build-source-tar]
          matrix:
            image: [debian:trixie, bookworm, bullseye, ubuntu:24.04, 22.04]
            class: [large, arm.medium]
      - build-rpm:          # ← 第二步：并行构建 RPM
          requires: [build-source-tar]
          matrix:
            image: [rockylinux:10, 9, 8, opensuse/leap:16.0, 15.6]
            class: [large, arm.medium]
```

### 6.2 构建矩阵覆盖

| OS | 版本 | x86_64 | ARM64 |
|----|------|:---:|:---:|
| Debian | trixie (13) | ✓ | ✓ |
| Debian | bookworm (12) | ✓ | ✓ |
| Debian | bullseye (11) | ✓ | ✓ |
| Ubuntu | 24.04 | ✓ | ✓ |
| Ubuntu | 22.04 | ✓ | ✓ |
| RockyLinux | 10 | ✓ | ✓ |
| RockyLinux | 9 | ✓ | ✓ |
| RockyLinux | 8 | ✓ | ✓ |
| OpenSUSE | Leap 16.0 | ✓ | ✓ |
| OpenSUSE | Leap 15.6 | ✓ | ✓ |

**总计**：20 个 .deb + 20 个 .rpm = **40 个二进制包**（每个 release）。

### 6.3 发布流程

```
Tag 推送 g3proxy-v1.12.3
        │
        ├─ 手动触发 CircleCI pipeline
        │  parameters: { package: "g3proxy", version: "1.12.3" }
        │
        ├─ build-source-tar → g3proxy-1.12.3.tar.xz
        │
        ├─ build-deb (×10) → 10 个 .deb → store_artifacts
        ├─ build-rpm (×10) → 10 个 .rpm → store_artifacts
        │
        └─ 手动上传到 Cloudsmith (cloudsmith.io/~g3-oqh/)
```

**注意**：CI 只构建和存储产物，上传到 Cloudsmith 是手动步骤。README 推荐生产环境**自行构建**包而非使用预编译版本。

---

## 7. 构建产物清单

### 7.1 每个 release 的完整产物

| 产物类型 | 文件名示例 | 数量 |
|----------|-----------|:---:|
| 源码包 | `g3proxy-1.12.3.tar.xz` | 1 |
| DEB (amd64) | `g3proxy_1.12.3-1_amd64.deb` | 5 |
| DEB (arm64) | `g3proxy_1.12.3-1_arm64.deb` | 5 |
| RPM (x86_64) | `g3proxy-1.12.3-1.el9.x86_64.rpm` | 5 |
| RPM (aarch64) | `g3proxy-1.12.3-1.el9.aarch64.rpm` | 5 |
| 源码 RPM | `g3proxy-1.12.3-1.src.rpm` | 1 |
| Docker 镜像 | `g3proxy:1.12.3` | 1+ |

### 7.2 安装的二进制文件

| 二进制 | 用途 | 构建方式 |
|--------|------|---------|
| `g3proxy` | 主代理进程 | `--package g3proxy` |
| `g3proxy-ctl` | Cap'n Proto RPC 控制工具 | `--package g3proxy-ctl` |
| `g3proxy-ftp` | FTP 代理客户端（辅助工具） | `--package g3proxy-ftp` |
| `g3proxy-lua` | Lua 用户源脚本执行器 | `--package g3proxy-lua` |

### 7.3 安装的配置文件

| 文件 | 来源 |
|------|------|
| `/lib/systemd/system/g3proxy@.service` | `g3proxy/service/generate_systemd.sh` 生成 |

---

## 8. 本地构建 vs 发布构建对比

| 维度 | 本地开发（`cargo build`） | 发布包（DEB/RPM/Docker） |
|------|------------------------|-------------------------|
| 编译 profile | `dev`（快速、无优化） | `release-lto`（LTO + 最高优化） |
| OpenSSL 来源 | 系统库或 vendored | 系统库（DEB/RPM）或 vendored-boringssl（Docker） |
| Rustls 后端 | `rustls-ring`（默认） | `rustls-ring` |
| Lua 特性 | 编译时选择 | 自动检测系统版本 |
| QUIC 特性 | 编译时选择 | ✓ 启用 |
| c-ares | 编译时选择 | `vendored-c-ares` |
| 依赖来源 | crates.io 在线下载 | `cargo vendor` 离线 bundle |
| CPU 优化 | 无特殊目标 | x86_64: `-C target-cpu=x86-64-v2`，aarch64: `+neon,+aes` |
| 可重现性 | 本地环境相关 | 固定时间戳/所有权/路径映射 |
| 裁剪无关应用 | ✗ 全量 workspace | ✓ 只保留 g3proxy + 所需 lib |

### 8.1 本地快速验证命令

```bash
# 完整编译（dev profile）
cargo build

# Release 编译（无 LTO，接近发布性能）
cargo build --release

# LTO Release 编译（最接近发布包）
cargo build --profile release-lto \
  --no-default-features \
  --features lua54,rustls-ring,quic,vendored-c-ares \
  -p g3proxy -p g3proxy-ctl -p g3proxy-ftp -p g3proxy-lua
```

### 8.2 `Cargo.toml` profile 定义

发布包使用的 `release-lto` profile 在 workspace 级 `Cargo.toml` 中定义：

```toml
[profile.release-lto]
inherits = "release"
lto = true           # 启用链接时优化
codegen-units = 1    # 单代码生成单元（更好的优化，更慢的编译）
```

---

## 总结

整个构建体系设计精巧，核心思路是：

1. **一份源码包，多目标构建** — 一个 `g3proxy-1.12.3.tar.xz` 可通过 DEB/RPM/Docker 三种方式构建
2. **完全离线** — `cargo vendor` 将所有依赖打包，目标机器只需 Rust 编译器 + 系统库
3. **自动化矩阵** — CircleCI 一次构建覆盖 10 个 OS 版本 × 2 个 CPU 架构
4. **可重现构建** — 固定时间戳、排序、路径映射，确保同源码同二进制
5. **特性自动适配** — Lua/c-ares/OpenSSL 版本在构建时自动探测，无需手动指定

> 文档基于 g3proxy v1.12.3 + 上游 v1.13.0 打包文件分析  
> 分析日期：2026-06-29
