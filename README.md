# warp-sub

自动优选 Cloudflare WARP 与 VLESS 接入地址，生成 **Clash / v2rayA** 双格式订阅。
单容器部署，一天一更，适合放在家里的 NAS 上。

```
                 ┌──────────────────────────────────────────┐
  cron (每日) ──▶ │  ① 候选生成   ② 并发探测   ③ 真隧道测速  │
                 │     ④ 门槛过滤   ⑤ 综合评分   ⑥ 取 TopN │
                 └──────────────────┬───────────────────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              ▼                     ▼                     ▼
        /sub?target=clash     /sub?target=v2ray        /  面板
        (mihomo: WG/MQ/VL)   (v2rayA: WG/VL)
```

## 它解决什么问题

WARP 的"最优节点"其实是三个变量叠加的结果，任何单一维度都不够：

| 变量 | 影响 | 本项目的处理 |
|---|---|---|
| **IP** | 不同入口 IP 落到不同边缘节点 | 8 个 WARP 入口网段抽样扫描 |
| **端口** | 同一 IP 换端口延迟能差 1.8 倍 | 内置 20 个常用端口一起测 |
| **域名** | 域名走 DNS 调度，可能解析到更优 IP | 支持域名候选，测完标注解析结果 |

并且 WARP 实际上有**两种传输方式**，行为完全不同：

| | WireGuard | MASQUE (HTTP/3) |
|---|---|---|
| 入口 | `162.159.192/193/195/204`、`188.114.96-99` | `162.159.197/198/199` |
| 可用端口 | 2408 / 500 / 1701 / 4500 等 20+ | 443 |
| v2rayA | ✅ 支持 | ❌ 不支持 |
| mihomo | ✅ | ✅ |

所以订阅会按类型分开：`v2ray` 自动排除 MASQUE 节点，`clash` 全量。

## 四类节点

| 类型 | 前缀 | 来源 | 测量方式 |
|---|---|---|---|
| WireGuard | `WG` | 入口网段 IP × 端口 | 真实 WireGuard 握手（Noise IK） |
| WireGuard 域名 | `WGD` | `engage.cloudflareclient.com` + 自建 CNAME | 同上，节点名带解析 IP |
| MASQUE | `MQ` | 162.159.197-199 段 | **完整 CONNECT-IP 握手 + 隧道内 ICMP 回环** |
| VLESS | `VL` | 你的 edgetunnel Worker + 优选域名/IP | WS 升级验证 + TCP RTT |

节点名直接把测量结果写进去，客户端里一眼能看出谁快：

```
WG 162.159.195.186:1018 · 262ms · 抖14ms · 8.4Mbps
VL cf.1o.ee:443 · 110ms · 抖8ms
```

## 筛选流程

```
① 并发探测     每个候选握手 N 次 → 延迟均值 / 抖动(标准差) / 丢包率
               VLESS 与 MASQUE 用 TLS/QUIC 专用超时
② 硬门槛       延迟 / 抖动 / 丢包 任一超标 → 淘汰（原因写进报表）
③ 真隧道测速   对评分最高的若干个 WireGuard 节点起 gVisor 用户态隧道
               真实下载测速，取 throughput
④ 二次门槛     速率不达标的淘汰（可关闭）
⑤ 综合评分     延迟 40% + 抖动 30% + 丢包 20% + 速率 10%
⑥ 取 TopN      每类各取前 N 个进订阅
```

## 部署（镜像方式，推荐）

CI 会把镜像构建并推到 GHCR（多架构：amd64 + arm64，群晖/威联通 ARM 机型可用）。

```bash
# 1. 填环境变量
cp .env.example .env
vi .env        # 改 WARPSUB_IMAGE、WARPSUB_TOKEN、VLESS_HOST、VLESS_UUID

# 2. 起
docker compose up -d

# 3. 打开面板
#    http://<nas-ip>:<WARPSUB_PORT>
```

`.env` 里的 `WARPSUB_IMAGE` 要是你自己的镜像地址：

```
WARPSUB_IMAGE=ghcr.io/<你的GitHub用户名>/warp-sub:latest
```

> 镜像默认是 **private**。第一次拉取前先登录：
> `echo <你的PAT> | docker login ghcr.io -u <用户名> --password-stdin`
> 或者在 GitHub 的 Packages 页面把包设为 public。

### 手动构建（不想用 CI 时）

```bash
docker compose -f docker-compose.build.yml up -d --build
```

## 环境变量

`config.yaml` 不是必须的——下面这些环境变量可以完全替代它。
优先级：环境变量 > config.yaml > 内置默认值。

| 变量 | 说明 |
|---|---|
| `WARPSUB_TOKEN` | 面板/订阅令牌 |
| `WARPSUB_PORT` | 宿主机端口（容器内固定 8080） |
| `WARPSUB_SCHEDULE` | 定时扫描，如 `0 4 * * *` |
| `WARPSUB_DATA_DIR` | 数据目录，容器内为 `/data` |
| `WARPSUB_VLESS_ENABLED` | `true` 开启 VLESS 节点 |
| `WARPSUB_VLESS_HOST` | edgetunnel 的 Worker 域名 |
| `WARPSUB_VLESS_UUID` | edgetunnel 的 UUID |
| `WARPSUB_VLESS_PATH` | 节点路径，默认 `/` |
| `WARPSUB_VLESS_SOURCES` | 公开优选列表，逗号分隔 |
| `WARPSUB_VLESS_VERIFY_DOMAINS` | 逐节点验证的站点，逗号分隔 |
| `WARPSUB_ALLOWED_COUNTRIES` | 只保留这些出口国家的节点 |
| `WARPSUB_EGRESS_PROBE` | 出口探测地址 |
| `WARPSUB_SPEED_URL` | 测速目标（必须非 Cloudflare） |
| `WARPSUB_SHORTLIST` | 进入真测速的节点数 |
| `WARPSUB_SCAN_CONCURRENCY` | 探测并发 |

## CI

`.github/workflows/release.yml`：

```
push 到 main / 打 v* tag / 手动触发
  ↓
go vet + 编译  （PR 也跑，只构建不推送）
  ↓
buildx 多架构构建 linux/amd64 + linux/arm64
  ↓
推送 ghcr.io/<owner>/warp-sub
   latest        ← 默认分支
   1.2.3 / 1.2    ← v1.2.3 tag
   sha-xxxxxxx   ← 每次提交
```

不需要额外配置 secret，用内置的 `GITHUB_TOKEN` 即可（workflow 里已声明 `packages: write`）。

首次启动会自动注册一个 WARP 设备，密钥落在 `data/account.json`（权限 600）。
不需要 root，也不需要 `/dev/net/tun`——隧道测速走 gVisor 用户态网络栈。

### 面板能做什么

- 填 **WARP+ License**，一键绑定到当前账号
- 看到每个候选的**延迟/抖动/丢包/速率**，以及被淘汰的具体原因
- 「立即扫描」手动触发，或等每天定时任务
- 复制双格式订阅链接

## 订阅端点（固定链接）

浏览器打开 `http://<nas-ip>:8080`，面板顶部就是两个**固定不变**的订阅地址：

```
http://<nas-ip>:8080/sub?target=clash&token=<token>    # Clash / mihomo
http://<nas-ip>:8080/sub?target=v2ray&token=<token>    # v2rayA
```

链接只在换 `token` 时变；节点内容每天自动更新，客户端按 `Profile-Update-Interval`
（默认 24h）重新拉取即可，不需要改地址。

参数：

```
?target=clash|v2ray    格式
?only=wg|masque|vless  只取某一类
?token=xxx             鉴权（config 里 token 为空则不需要）
```

- **v2rayA**：直接粘贴 `target=v2ray`。内容为 base64 包裹的 `wireguard://` / `vless://`
  分享链接，v2rayA ≥ 2.5.0 原生识别。
- **Clash Verge / mihomo**：粘贴 `target=clash`，自动附带 `WARP-自动`（url-test）
  和 `WARP-手动`（select）两个策略组。

- v2rayA：直接导入 `target=v2ray` 的链接（base64 + `wireguard://` 分享链接，v2rayA ≥ 2.5.0）
- Clash Verge / mihomo：导入 `target=clash`，附带 `url-test` 自动组和 `select` 手动组

## 测量模型：吞吐 + 稳定性为主，延迟只作存活判断

延迟只能证明节点还活着。真正决定体验的是**速率**和**线路能不能撑住**。

### 下载测试不是取平均，而是取时间序列

```
持续下载 duration_s 秒（或到 max_bytes_mb 封顶），按秒采样：
  峰值 peak       第一段跑多快（你看到的 10MB/s）
  尾部 tail       最后 1/3 的中位数（你后来看到的 10KB/s）
  衰减 decay      tail / peak
  抖动 CV         每秒速率的变异系数
  卡顿 stall      0 字节秒数占比
  最长断流       连续几个 0 字节窗口
```

稳定性评分（0–100）：

```
decay 45%  +  (1-CV) 35%  +  (1-卡顿) 20%，最长断流 ≥5 秒再乘 0.5
```

这样"一开始 10M、几分钟后掉到 10K"的节点会拿到很低的稳定性分，
即使它的平均速率看起来还行。

### 评分权重

| 阶段 | 权重 |
|---|---|
| 粗排（还没测速） | 延迟 55% + 抖动 25% + 丢包 20% |
| 终评（测过速） | **速率 45% + 稳定性 45% + 延迟 10%** |

延迟在终评里只占 10%，并且同时充当**存活门槛**（超过 `max_latency_ms` 直接淘汰）。

### 测速目标不能用 Cloudflare 自己的地址

Worker 直连 Cloudflare 的 IP 有环路限制，`speed.cloudflare.com` 会 TLS 超时——这不是节点坏了。
默认换成非 CF 源：

```yaml
speed_test:
  url: "https://proof.ovh.net/files/100Mb.dat"     # OVH，100MB，支持 range
  # 备选: https://ash-speed.hetzner.com/100MB.bin
```

### 测速失败会被归因，而不是只说"失败"

| 诊断码 | 含义 | 你该做什么 |
|---|---|---|
| `ok` | 正常 | — |
| `tls_blocked` | TLS 握手失败 | 换测速目标；若明文能通但 TLS 不通，说明出口只放行明文 |
| `connect_failed` | WS 握手/建连失败 | 检查 worker 域名、UUID、路径 |
| `no_data` | 隧道通了但取不到数据 | 检查反代/出站 |

判定 `tls_blocked` 时会额外跑一次明文 HTTP 探测，
如果能通就明确提示「出口只放行明文：HTTPS 站点不可用」。

面板「测速诊断」一行会给出本次各类结果的数量。

### 空闲存活测试

建一条真实数据流 → **空闲 idle_seconds 秒** → 再发一个小请求。
直接对应"AI 对话中途断开"：连接长时间不动之后还能不能用。

### 三段漏斗（控制成本）

```
① 快筛   所有候选            → 延迟/抖动/丢包
② 粗排   按粗排分取 Top N
③ 深测   shortlist 个节点     → 吞吐 + 稳定性 + 空闲存活
```

真测速的节点数由 `speed_test.shortlist` 控制（默认 15），
每个节点 `duration_s`（默认 15 秒）/ `max_bytes_mb`（默认 20MB）封顶。
8 个节点一轮大约 5 分钟、200MB。

## 候选池：自动采集 + 实测过滤

只看你手填的十来个域名是不够的。`vless.sources` 可以挂任意公开优选列表，
程序会：

```
拉取列表 → 逐行解析 host[:port][#remark] → 去重
        → 解析 DNS，只保留落在 Cloudflare 网段的
        → 进入真实 WS 握手验证（101 才算活）
        → 通过四道门槛后评分
```

实测（两个公开源）：

```
source: .../domain/mini.txt -> 16 entries, 14 kept
source: .../domain/all.txt  -> hit max 40
scan: source pool added 40 candidates
scan: 41 candidates, 8 passed, 21s
```

CF 网段默认内置一份静态表，启动成功时会用 `cloudflare.com/ips-v4` 覆盖更新。

## 稳定性：不要相信单次测量

```yaml
stability:
  min_hits: 2      # 最近几次扫描中至少上榜 2 次
  bootstrap: true  # 历史不足时先用当前结果
```

用**滑动窗口**而不是严格连续计数——一次限速或网络抖动不该把订阅清空。
面板节点表里会显示「连续 N 次」，右边是它上榜的次数。

## 手动全量扫描

面板上「立即扫描」旁边有个「全量扫描」按钮（会二次确认），
或命令行 `warp-sub -scan -full`，或 `POST /api/scan?full=1`。

区别：抽样扫描每个 /24 取 `sample_per_subnet` 个地址，
全量扫描取全部 256 个。实测同一配置下：

```
抽样: 2 candidates    (1s)
全量: 257 candidates  (3s)   ← 1 个网段 × 1 个端口
```

8 个网段 × 20 端口全量约 4 万个组合，建议睡前跑。

## 代理（proxyip）和 ECH 到底缺不缺

这两件事经常被混在一起，实际上是两回事：

| | 归谁管 | 我们的节点缺吗 |
|---|---|---|
| **proxyip / 反代** | **服务端**。edgetunnel 的 `PROXYIP` 环境变量 | ❌ **不缺**。节点 URI 里不需要任何东西，所有节点共用同一个出口 |
| **ECH** | **客户端**。节点 URI 里的 `ech=` 参数 | ✅ 默认缺，可通过 `vless.ech` 打开 |

也就是说：

- 想走代理出口 → 不用换订阅，我们的节点和你 edg 的节点**走同一个反代**
- 想要 ECH → 在配置里打开就能补上，**不需要依赖 edg 的订阅**

```yaml
vless:
  ech:
    enabled: true
    public_name: "cloudflare-ech.com"
    doh: "https://dns.alidns.com/dns-query"
```

v2ray 订阅输出（和 edg 生成的完全一致）：

```
vless://<uuid>@cf.1o.ee:443?ech=cloudflare-ech.com%2Bhttps%3A%2F%2Fdns.alidns.com%2Fdns-query&...
```

Clash 侧的 ECH 需要具体的 **ECHConfigList**（不是名字）。启动时会自动通过 DoH
抓一次并填入：

```
vless.ech: 已获取 ECHConfigList（96 字节），clash 侧将启用 ECH
```

抓取顺序：配置里的 `doh`（自动识别 alidns 的 `/resolve`）→ Cloudflare DoH → doh.pub。
抓不到就只在 v2ray 格式里带 ECH，不影响 Clash 节点可用。

## 出口国家：为什么同一个 worker 的节点表现差别巨大

实测同一个 edgetunnel、同一套配置，只换接入地址：

| 节点 | 出口 IP | 国家 | 城市 |
|---|---|---|---|
| www.sofi.com | 104.28.163.45 | **SG** | Singapore |
| saas.sin.fan | 104.28.157.20 | **JP** | Narita |
| cf.1o.ee | 104.28.155.185 | **DE** | Dreieich |

**Cloudflare 按接入地址把请求路由到不同机房，出口国家随之改变。**
而 Google Antigravity、ChatGPT 这类服务是**按出口地区判断可用性**的，
所以「某些节点用不了」不是连通性问题，是**地区不对**。

本项目给每个节点测一次出口：

```yaml
vless:
  egress_probe: "https://ipinfo.io/json"
  allowed_countries: [JP, SG]     # 留空 = 不过滤
```

- 面板「出口」列显示国家 + IP
- 节点名带上国家：`VL www.sofi.com:443 · 73ms · 25.1Mbps · SG`
- 自动生成 Clash 策略组 **`出口合格`**，只放允许国家的节点

实测输出（5 个节点，4 个合格，DE 那个被排除）：

```
出口合格: www.sofi.com·SG / store.ubi.com·SG / saas.sin.fan·JP / academy.7shifts.com·SG
```

## 逐站点验证：解决「某些节点打不开某个服务」

有些节点能跑通用流量，但某个具体服务用不了——出口 IP 被封、地区限制、
反代轮换导致会话断裂。只看延迟和速率完全看不出来。

```yaml
vless:
  verify_domains:
    - chatgpt.com
    - agy.example.com     # 换成你实际用的服务域名
```

对每个进入深测的节点，逐一建立 TLS 连接并发出真实 HTTP 请求，记录结果：

- Clash 订阅会多出一个策略组 **`可用 <域名>`**，只放能用的节点
- 节点名里标注：`VL www.sofi.com:443 · 73.8ms · 1.7Mbps · chatgpt✓`
- 面板节点表新增「站点」列，绿=可用、红=不可用

实测（Antigravity 相关四个域名，同一节点）：

```
✅ antigravity.google                    HTTP/1.1 200 OK
✅ antigravity-pa.googleapis.com         HTTP/1.1 404（API 根路径正常返回 404）
✅ cloudcode-pa.googleapis.com           HTTP/1.1 404
✅ generativelanguage.googleapis.com     HTTP/1.1 404
```

说明**网络层是通的**；能不能真正用起来取决于出口地区和长连接稳定性，
所以「出口国家」才是 Antigravity 这类服务的关键判据。

## 两个前端页面

| 页面 | 用途 |
|---|---|
| `/` | 完整面板：节点表、淘汰原因、测速诊断、历史趋势、License、回写、v2rayA 联动 |
| `/simple` | 极简页：只放两个订阅链接 + 立即扫描 + 前 10 个节点，手机上打开用 |

两个页面共用同一个 `token`，互不干扰。

## 和 edgetunnel 怎么协同

本项目**不部署、不修改** edgetunnel，它是我们的一个"节点源"。协同只有三个接触点：

```
                     ┌──────────────────────┐
  你的 edgetunnel ───▶│ 1. Worker 域名 (SNI) │
  (CF Workers/Pages)  │ 2. UUID              │
                      │ 3. WS 路径            │
                     └──────────┬───────────┘
                                │
  公开优选域名列表 ──▶ 候选池 ────┼──▶ 逐个发真实 WS 升级请求
  (你 ADD.txt 里那些)            │      ├─ 101 → 收进订阅
                                │      └─ 403/超时 → 淘汰并记录原因
                                ▼
                        /sub?target=v2ray  ──▶ v2rayA
                        /sub?target=clash  ──▶ mihomo
```

**1. 我只读它的三个参数**，不碰它的配置：

```yaml
vless:
  worker_host: "vpn.suenqi.cloudns.be"     # 既是 SNI 也是 Host
  uuid: "559d0d11-..."
  path: "/"
```

**2. 我做的事是它自己做不了的那件：验证。**

edgetunnel 的 `ADD.txt` 机制是"你给什么它就用什么"，它不做连通性检查。
所以你那份列表里 `fn.130519.xyz`（CF error 1034）一直躺在第 1 位，
客户端按延迟排序时正好选中这个死链。

本项目对每个候选发真实的 WebSocket 升级请求：

| 响应 | 处理 |
|---|---|
| `101 Switching Protocols` | 收进订阅 |
| `403` / `超时` / `200`(落到伪装页) | 淘汰，原因写进面板 |

**3. 两边订阅可以并存，互不干扰。**

- edgetunnel 自己的订阅：`https://vpn.suenqi.cloudns.be/sub?token=<它的token>`
- 本项目的订阅：`http://<nas>:8080/sub?target=v2ray&token=<我的token>`

客户端可以同时导入两个，或者只导入我的（因为我的节点质量更高）。
我的扫描结果不会写回 edgetunnel——你说过 `edg 留着不改`，所以是纯旁路。

**4. 可选的反哺（已实现，默认关闭）**

把实测最优的 VLESS 接入地址 POST 到 edgetunnel 的 `admin/ADD.txt`。
它的定位是**远端同步 / 高可用副本**，不是节点优化：

| | 有回写 | 没有回写 |
|---|---|---|
| 节点本身 | 完全一样（同地址、同 UUID、同 SNI） | 一样 |
| NAS 关机后 | edg 订阅仍能用最近一次的好地址 | edg 订阅还是它原来那份（可能含死链） |
| 别人已订的链接 | 自动变好 | 不变 |

开启方式（面板「远端同步」卡片，或 `config.yaml`）：

```yaml
writeback:
  enabled: true
  base_url: "https://vpn.example.com"
  password: "你的后台密码"
  auto: false        # true 则每次扫描后自动写
```

安全设计：

- 默认关闭，需显式填写地址和密码才生效
- 每次写入前先把原 `ADD.txt` 存到 `data/add-backup-<时间>.txt`（600 权限）
- 只写 VLESS 类节点，备注带实测数据，例如
  `saas.sin.fan:443#VL 107ms 抖4ms`
- 面板里可随时关掉；关掉后不再触碰 edg

## 关于 VLESS（edgetunnel）

本项目**不部署** edgetunnel，只消费它：你已经有 Worker 域名和 UUID，填进配置，
本项目负责挑选最佳的接入地址（优选域名或 IP）并做**真实 WS 握手验证**。

验证很关键：优选域名列表里经常混着无效项。实测数据（84 条公开"优选域名"里）：

- 79 条解析到 CDN 网段（`104.x` / `172.64.x`），对 WARP 完全无效
- 仅 1 条域名解析到 WARP 入口网段
- 而作为 VLESS 接入地址时有 7/8 可用，剩下 1 条返回 `CF error 1034`

所以本项目对每个候选都做实测，返回非 101 的直接淘汰，不会把死链塞进订阅。

## v2rayA 联动

局域网里有 v2rayA 的话，可以让它自动用上本服务生成的节点。

```yaml
v2raya:
  enabled: true
  base_url: "http://192.168.1.2:2017"
  username: "你的用户名"
  password: "你的密码"
  auto: true                                  # 每次扫描后自动同步
  subscription_url: "http://192.168.1.10:8080/sub?target=v2ray&token=xxx"
```

行为：

| 情况 | 动作 |
|---|---|
| v2rayA 里没有这条订阅 | `POST /api/import` 导入 |
| 已经有了（同 host+path+query） | `PUT /api/subscription` 只刷新，**不会重复添加** |

注意两点：

1. `subscription_url` 必须是 **v2rayA 那台机器能访问到的地址**，
   写 `127.0.0.1` 会让 v2rayA 去拉它自己。
2. 面板里可以「测试连接」先验证用户名密码，会列出 v2rayA 现有的订阅和节点数。

实现走的是 v2rayA 的 HTTP API：`/api/login` 拿 JWT，
`/api/touch` 读现有订阅，`/api/import` 导入，`/api/subscription` 刷新。

## 日常运维

### 开机自启

Docker 部署：`docker-compose.yml` 里已经是 `restart: unless-stopped`，
NAS 重启后容器自动拉起。群晖/威联通在「容器管理器」里把项目设为开机启动即可。

不用 Docker 的话，附带了 systemd 单元：

```bash
sudo cp scripts/warp-sub.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now warp-sub
```

### 备份

`data/` 里有账号私钥，丢了要重新注册（订阅里的节点会全部失效）。建议每天备一次：

```bash
./scripts/backup.sh ./data ./backups 14      # 保留 14 份
```

加进 crontab：

```
0 3 * * *  cd /path/to/warp-sub && ./scripts/backup.sh ./data ./backups 14
```

### 升级

```bash
git pull && docker compose up -d --build
```

`data/` 是挂载卷，升级不会丢账号和扫描结果。

### 面板上的历史趋势

每次扫描结束后会记一条摘要到 `data/history.json`（最多 90 条），
面板底部用折线画出「最优延迟」和「入选节点数」的变化，
可以据此判断某个优选域名是不是开始劣化了。

## 配置要点

```yaml
scan:
  concurrency: 128        # NAS 上 64~200，越高越快也越容易被 CF 限速
  rounds: 5               # 抖动/丢包靠多次探测，别低于 3
  sample_per_subnet: 16   # 每个 /24 抽 16 个；0 = 全量 256 个（很慢）

thresholds:               # 四道硬门槛
  max_latency_ms: 400
  max_jitter_ms: 80
  max_loss_pct: 20
  min_speed_mbps: 2

speed_test:
  required: true          # 测不出速率的节点是否淘汰
  cooldown_ms: 30000      # 海量握手后冷却，避免被 CF 限速
```

## 已知限制

1. **MASQUE 已做完整 CONNECT-IP 验证**：用一个独立的 secp256r1 设备注册，
   带自签客户端证书做 HTTP/3 扩展 CONNECT，只有拿到 2xx 才算通过。
   因此 `MQ` 节点是"真的能建隧道"，不是"能 ping 通"。
2. **WireGuard 类可能长期为 0**：见上节，新账号默认 `tunnel_protocol: masque`，
   边缘不接受 WireGuard 握手。所以实际可用的是 `MQ`（Clash）+ `VL`（两端都能用）。
3. **域名类节点的测速不等于客户端体验**。扫描时解析到 A 地址，客户端连接时可能解析到 B。
   节点名里标注了扫描时的解析 IP，方便判断。
4. **mass probe 会触发 Cloudflare 限速**。所以测速阶段前有冷却期；
   如果 NAS 出口带宽小，建议把 `sample_per_subnet` 降到 8。
5. **测速依赖出口网络**。若你的 NAS 本身要走代理才能连外网，务必给容器设 `HTTPS_PROXY`。

## 目录结构

```
internal/
├── config/      YAML 配置
├── account/     WARP 注册、密钥、License
├── wgn/         WireGuard Noise 握手探测器（核心）
├── probe/       VLESS（TLS+WS）与 MASQUE（QUIC）探测
├── tunnel/      gVisor netstack 真隧道测速
├── scoring/     四道门槛 + 加权评分
├── render/      Clash YAML / v2ray base64
├── scan/        流程编排
├── store/       结果持久化
└── httpapi/     API + 订阅端点 + 面板
```

## 免责

仅供学习与个人网络调试使用。WARP 是 Cloudflare 的服务，请遵守其服务条款。

## 实测记录：WARP 正在向 MASQUE 迁移

2026-11 实测发现，新注册的 WARP 设备在注册响应里已经带上：

```json
"policy": {
  "tunnel_protocol": "masque",
  "post_quantum": "enabled_with_downgrades",
  "always_include": [{"ip": "162.159.197.4"}],
  "always_exclude": [{"ip": "162.159.197.3"}]
}
```

即 Cloudflare 把新设备默认成 **MASQUE 隧道**，而不是 WireGuard。表现是：

- `warp_enabled=true`、`peer_public_key=bmXOC+...`（和文档一致）
- 但发 WireGuard 握手过去**收不到任何响应**（多个新账号、多个入口 IP 全部如此）
- 同一时刻，`162.159.197/198/199.x:443` 的 QUIC 握手**正常**

结论：新账号的 WireGuard 握手不被边缘接受，MASQUE 才是当前可用的路径。
代码里两类都实现了，WireGuard 类会在环境支持时自动恢复入选；
如果你的订阅里 `WG` 一直是 0 个，把 `top.wg` 调小、把 `top.masque` 调大即可，
扫描日志会打出明确告警。
