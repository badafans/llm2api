# LLM Gateway

一个支持多上游、多协议转换的 LLM 代理网关。客户端只用配置的"别名"发请求，网关按别名路由到对应上游，在 OpenAI Chat、Anthropic Messages、OpenAI Responses 三种协议之间双向转换，转发并记录 Token 用量。

## 核心特性

- **三协议入口**：同时暴露 OpenAI Chat Completions (`/v1/chat/completions`)、Anthropic Messages (`/v1/messages`)、OpenAI Responses (`/v1/responses`)，另有图片生成 / 编辑 (`/v1/images/generations`、`/v1/images/edits`)
- **三种上游类型**：`openai`（Chat）、`anthropic`（Messages）、`openai-responses`（Responses）。入口与上游同协议时直通，不同时自动转换消息、工具调用、thinking / reasoning、SSE 流式事件
- **Codex 兼容**：支持 Codex 的 Responses Lite 请求（工具目录放在 `input` 的 `additional_tools` 里、`exec` 等 `custom` 工具），即使上游只是 Chat 协议（如 DeepSeek）也能用，见下文
- **Anthropic 自动 Prompt Caching**：上游是 Anthropic 时，网关自动补全块级缓存断点，OpenAI / Responses 客户端也能命中缓存
- **多上游管理**：按名称区分，每个上游支持多 API Key 轮询
- **模型别名（严格）**：客户端只能使用 `model_alias` 里配置的别名，裸上游模型名一律返回 400。别名把请求模型名映射到上游实际模型，支持跨上游路由和独立代理出口
- **模型唯一来源 = custom_models**：每个上游的 `custom_models` 由用户手工填写或点"获取模型列表"拉取，启动 / 重载不再自动联网拉取
- **按模型代理出口**：保存 SOCKS5 代理，每个别名可独立选择出口，默认直连
- **智能重试**：429 / 502 / 503 / 504 自动重试。多 Key 立即切下一把不等待；单 Key 走指数退避（1→2→4…→30s 封顶）。不解析 `Retry-After`
- **流式透传**：SSE 逐事件转发，不缓冲整条响应
- **Token 统计**：记录请求数与输入 / 输出 token，按模型分类；保留今日明细和最近 29 天历史，持久化到 `stats.json`
- **管理面板**：内嵌 Web UI，无外部资源依赖；支持热加载配置、统计、上游 / 别名 / 代理管理、模型与出口连通性测试；可选密码认证

## 快速开始

```bash
# 直接运行（默认免登录，监听 :8000）
go run main.go

# 指定端口并启用管理面板密码
go run main.go -port 8080 -password mypass
```

浏览器打开 `http://localhost:8000/` 进入管理面板。`-password` 为空时无需登录；指定后需先登录。

新上游配置流程：

1. 管理面板 → "上游配置" → 添加上游；填名称、Base URL、API Key
2. "自定义模型"字段：手工填写，或点"获取模型列表"由后端实时调用上游 `/models` 并填入
3. 保存上游配置
4. "模型映射" → 添加别名（请求名）→ 选上游 → 选实际模型（该上游的 `custom_models`）→ 可选代理出口
5. 保存后，客户端用这个别名请求 `/v1/*` 即可

## 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-port` | `8000` | 监听端口 |
| `-config` | `config.json` | 配置文件路径 |
| `-password` | `""` | 管理面板密码；留空则不启用认证 |
| `-debug` | `false` | 打印详细请求 / 响应日志（含完整提示词，注意保密） |

## API 端点

公开接口（**网关不校验客户端 API Key**，对外暴露时请自行在前面加鉴权）：

| 路径 | 方法 | 说明 |
|------|------|------|
| `/v1/chat/completions` | POST | OpenAI Chat 接口 |
| `/v1/messages` | POST | Anthropic Messages 接口 |
| `/v1/responses` | POST | OpenAI Responses 接口 |
| `/v1/images/generations` | POST | 图片生成，转发到 OpenAI 兼容上游的 `/images/generations` |
| `/v1/images/edits` | POST | 图片编辑（multipart），转发到上游 `/images/edits` |
| `/v1/models` | GET | 列出可用模型（只列别名，不暴露上游 `custom_models`） |
| `/health` | GET | 健康检查，返回 `OK` |
| `/login`、`/logout` | GET/POST、POST | 管理面板登录 / 退出 |

图片接口只支持 `api_type` 为 `openai` 的上游；Anthropic / Responses 型上游没有标准图片端点。图片请求按次数统计，不计 token。

管理接口（需认证）：

| 路径 | 方法 | 说明 |
|------|------|------|
| `/api/config` | GET/POST | 读取 / 更新配置 |
| `/api/stats` | GET/DELETE | 查看 / 清空统计 |
| `/api/reload` | POST | 热重载配置（从 config.json 重新读取并应用） |
| `/api/upstream/models` | POST | 用临时配置或已保存配置实时拉取上游模型列表 |
| `/api/upstream/test` | POST | 用草稿配置探测一次模型调用，返回 Key 状态、延迟、首字时间；不保存配置、不计入统计 |

## 配置文件

`config.json` 结构：

```json
{
  "model_alias": {
    "claude-sonnet": {
      "target_model": "z-ai/glm-5.2",
      "upstream": "nvidia",
      "socks5_proxy": "127.0.0.1:1080"
    }
  },
  "reasoning_effort_map": {
    "low": "high",
    "medium": "high",
    "xhigh": "max"
  },
  "socks5_proxies": [
    {
      "addr": "127.0.0.1:1080",
      "username": "",
      "password": "",
      "name": "proxy-1"
    }
  ],
  "upstreams": {
    "nvidia": {
      "base_url": "https://integrate.api.nvidia.com/v1",
      "api_key": "nvapi-xxx",
      "api_type": "openai",
      "custom_models": ["z-ai/glm-5.2"]
    },
    "claude": {
      "base_url": "https://api.anthropic.com/v1",
      "api_key": "sk-ant-xxx",
      "api_type": "anthropic",
      "custom_models": ["claude-sonnet-4-5"],
      "disable_anthropic_auto_cache": false
    },
    "responses-main": {
      "base_url": "https://example.com/v1",
      "api_key": "sk-xxx",
      "api_type": "openai-responses",
      "responses_reasoning_format": ""
    }
  }
}
```

### 字段说明

- **`model_alias`**：`key` 是客户端请求的模型名；`target_model` 是上游实际模型名；`upstream` 指定路由到哪个上游（没有"默认上游"，必须显式指定）；`socks5_proxy` 引用 `socks5_proxies` 中的代理，留空直连
- **`reasoning_effort_map`**：把上游不支持的 effort 级别映射到可用级别，未配置的值保持原样
- **`socks5_proxies`**：SOCKS5 代理列表。同一地址可配多条，用用户名区分（引用写成 `用户名@地址:端口`）
- **`upstreams`**：每个键是上游名称
  - `base_url`：上游 API 根地址
  - `api_key`：每行一个，可配多个，轮询分发
  - `api_type`：`openai`、`anthropic` 或 `openai-responses`，默认 `openai`
  - `custom_models`：该上游的模型列表，是模型唯一来源
  - `responses_reasoning_format`：仅 Responses 上游。空值用标准 `reasoning.effort`，`legacy_reasoning_effort` 用兼容字段 `reasoning_effort`
  - `disable_anthropic_auto_cache`：仅 Anthropic 上游。默认 `false`，即启用自动缓存；设为 `true` 关闭，见下文

保存时后端会校验别名引用的上游 / 代理是否存在，孤儿引用返回 400。

### API Key 多 Key 轮询

`api_key` 支持多行写入多个 Key。某个 Key 触发 429 / 502 / 503 / 504 时：

- 有多把 Key：立即切下一把，不等待
- 只有一把 Key：指数退避重试（1s → 2s → 4s … 30s 封顶）

### 按模型选择 SOCKS5 出口

- `socks5_proxy` 为空时直连；每个别名可选不同出口
- Chat、Anthropic、Responses 的流式和非流式请求都走对应出口
- 代理删除后引用失效：前端显示"（已失效）"，保存时后端校验并返回 400
- 不提供全局启用、轮询或收到 429 后自动切换出口的功能

### Reasoning 参数

当前请求的 `thinking` 和 `reasoning_effort` 独立转发给上游，只经 `reasoning_effort_map` 做取值映射。历史 assistant 消息里非空的 `reasoning_content` 会原样回传给 Chat 上游；空值不发送。

## 协议转换矩阵

| 下游 \ 上游 | OpenAI Chat | Anthropic Messages | Responses API |
|-------------|:-----------:|:-----------------:|:-------------:|
| **OpenAI Chat** | 直通 | 格式转换 | 格式转换 |
| **Anthropic** | 格式转换 | 直通 | 格式转换 |
| **Responses** | 格式转换 | 格式转换 | 直通 |

直通时请求体只替换 `model` 字段，转换开销最低。

## Anthropic 自动 Prompt Caching

Anthropic 的缓存要求在 `system`、`tools`、`messages` 的 content block 上放块级 `cache_control` 断点（最多 4 个）。顶层的 `cache_control` 不是合法字段，会被静默丢弃。OpenAI 和 Responses 客户端不会打断点，不处理就永远不会命中缓存。

上游是 Anthropic 时，网关在请求里没有任何断点的前提下，自动放 3 个：

1. `tools` 末尾
2. `system` 末尾
3. 最后一条 message 的末尾块

客户端自带断点（如 Claude Code）时原样透传，不再注入。对这个上游设置 `disable_anthropic_auto_cache: true`（管理面板里的"关闭 Anthropic 自动 Prompt Caching"）可整体关闭。

统计口径：Anthropic 的 `input_tokens + cache_creation_input_tokens + cache_read_input_tokens` 合并为 OpenAI 的 `prompt_tokens`；`cache_read_input_tokens` 对应 `prompt_tokens_details.cached_tokens`。

## Codex 兼容（Responses Lite）

Codex 的新模型（如 `gpt-5.6-*`、`gpt-6.2-*`）使用 Responses Lite 形态：请求没有顶层 `tools`，工具目录放在 `input` 的 `additional_tools` 项里，并带 `x-openai-internal-codex-responses-lite: true`。网关对上游是 Chat 协议的情况做了这些处理：

- **恢复工具目录**：按顺序扫描整个 `input`，同名工具以最新定义为准，识别 developer 消息里的"工具不再可用 / 命名空间不再可用"通知。顶层 `tools` 与 `additional_tools` 同时存在时合并
- **`custom` 工具**（如 Codex 的 `exec`）：编码成只有一个必填字符串参数 `input` 的 function，grammar 以文字追加到描述里。模型调用后，网关还原成 `custom_tool_call`，`input` 是裸字符串，并发出 `response.custom_tool_call_input.delta / done` 事件
- **命名空间**：默认命名空间 `functions` 不加前缀（上游看到 `exec`），其它命名空间用 `命名空间__工具名`，响应里还原
- **历史**：`custom_tool_call` 与 `custom_tool_call_output` 转成 Chat 的 `tool_calls` 与 `tool` 消息
- **不可表达的工具**（如 `tool_search`、`web_search`）：Chat 上游无法执行，直接丢弃

目录靠请求里的历史恢复，网关不保存会话状态。如果 Codex 压缩上下文时丢掉了早期的 `additional_tools`，工具会随之丢失。

## 管理面板

- **Token 统计**：显示今日按模型的请求数和输入 / 输出 token，下面是最近 7 天逐日表；历史超过 7 天时再显示"近 N 天模型汇总"（最多 29 天历史）。每 5 秒自动刷新，可清空
- **上游配置**：可折叠卡片增删改上游，折叠摘要显示名称、协议、Base URL、Key 数和模型数
- **模型测试**：单个模型测试；"批量测试模型"勾选多个模型后并发测试，显示可用性和响应速度，并发数等于勾选数量，再次点击按钮收起
- **Key 验证**："验证全部 Key"逐个检查 Key 有效 / 无效 / 受限，并可清理失效 Key
- **模型映射**：配置别名路由、跨上游、代理出口
- **SOCKS5 代理**：增删代理条目；"测试全部出口"并发测试所有出口的连通性，也可单个测试
- **推理力度映射**：位于模型映射底部的折叠高级设置
- **完全自托管**：HTML / CSS / JS 都内嵌在 `main.go` 里，不引用外部 CDN、字体或图标，内网可用

## 目录结构

```
llm2api/
├── main.go      # 业务逻辑和内嵌管理面板
└── README.md
```

## 构建

- 需要 Go 1.21+，支持 Windows / Linux / macOS
- 项目是单文件，没有 `go.mod`，用 `go build main.go` 构建，或 `go run main.go` 直接运行
- 管理面板的 JS 内嵌在 `main.go` 里，修改后建议用 `node --check` 校验语法

## 注意事项

- 默认 `api_type` 为 `openai`，上游是 Anthropic 或 Responses 时请对应填写
- 网关不校验客户端 API Key，对外暴露请在前面加反向代理鉴权
- 管理面板 `-password` 默认为空（不启用认证），请仅在可信网络使用
- `-debug` 日志含完整提示词和对话内容，用完请清理
- Anthropic 直通模式下，系统消息中的 `x-anthropic-billing-header` 会被自动清洗
- 流式请求会自动注入 `stream_options.include_usage: true`，保证 token 统计准确
- 网关不会把客户端的 `Accept-Encoding` 转给上游，由 Go 自行协商并自动解压。否则 Codex 带的 `zstd,gzip` 会让会压缩流的上游（如 DeepSeek 官方）返回压缩字节，网关读不到任何 SSE 行，Codex 收到空的 `response.incomplete`（`stream_ended_early`）
- 所有别名必须显式指定上游；客户端只能用已配置的别名调 `/v1/*`
