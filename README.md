# LLM Gateway

一个支持多上游、多协议转换的 LLM 代理网关。将上游的 OpenAI / Anthropic / Responses API 统一转换为 OpenAI Chat 格式对外提供，同时支持 Anthropic Messages 和 OpenAI Responses 协议的透传与转换。

## 核心特性

- **多协议兼容**：同时暴露 OpenAI Chat Completions (`/v1/chat/completions`)、Anthropic Messages (`/v1/messages`)、OpenAI Responses (`/v1/responses`) 三个接口
- **上游格式转换**：自动在上游协议与 OpenAI 协议之间双向转换，包括消息格式、工具调用 (tool use)、thinking / reasoning 字段、SSE 流式事件等
- **多上游管理**：支持配置多个上游，按名称区分，可设默认上游；支持多 API Key 轮询
- **模型别名**：将请求模型名映射到上游实际模型，支持跨上游路由和思维链注入标记
- **SOCKS5 代理**：内置 SOCKS5 客户端，支持轮询、限流自动切换、用户名/密码认证
- **智能重试**：429 / 502 / 503 / 504 自动重试，指数退避，支持 `Retry-After` 头，SOCKS5 代理轮换
- **流式透传**：SSE 流经过网关时保持实时转发，不缓冲整条响应
- **Token 统计**：自动记录请求数、输入/输出 token，按模型分类，每日自动重置，持久化到 `stats.json`
- **管理面板**：内嵌 Web UI，支持热加载配置、查看统计、管理上游/别名/代理，带密码认证

## 快速开始

```bash
# 直接运行
go run main.go

# 指定端口和密码
go run main.go -port 8080 -password mypass

# 启动即用，默认监听 0.0.0.0:8000
go run main.go -port 8000
```

浏览器打开 `http://localhost:8000/` 进入管理面板（如设置了密码需先登录）。

## 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-port` | `8000` | 监听端口 |
| `-config` | `config.json` | 配置文件路径 |
| `-password` | `123456` | 管理面板密码，留空则不启用认证 |
| `-debug` | `false` | 打印详细请求/响应日志 |

## API 端点

| 路径 | 方法 | 说明 |
|------|------|------|
| `/v1/chat/completions` | POST | OpenAI Chat 接口 |
| `/v1/messages` | POST | Anthropic Messages 接口 |
| `/v1/responses` | POST | OpenAI Responses 接口 |
| `/v1/models` | GET | 列出可用模型（别名 + 上游模型） |
| `/health` | GET | 健康检查，返回 `OK` |
| `/login` | GET/POST | 管理面板登录 |
| `/logout` | POST | 退出登录 |

管理接口（需认证）：

| 路径 | 方法 | 说明 |
|------|------|------|
| `/api/config` | GET/POST | 读取 / 更新配置 |
| `/api/stats` | GET/DELETE | 查看 / 清空统计 |
| `/api/reload` | POST | 手动刷新上游模型列表 |

## 配置文件

`config.json` 结构：

```json
{
  "model_alias": {
    "claude-sonnet": {
      "target_model": "z-ai/glm-5.2",
      "upstream": "nvidia",
      "with_reasoning": false
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
  "active_socks5": "",
  "upstreams": {
    "nvidia": {
      "base_url": "https://integrate.api.nvidia.com/v1",
      "api_key": "nvapi-xxx",
      "api_type": "openai",
      "custom_models": ["z-ai/glm-5.2"],
      "responses_reasoning_format": ""
    }
  },
  "default_upstream": "nvidia"
}
```

### 字段说明

- **`model_alias`** — 模型别名映射。`key` 是客户端请求的模型名；`target_model` 是上游实际模型名；`upstream` 指定路由到哪个上游（留空用默认上游）；`with_reasoning` 标记是否给该模型注入 `reasoning_content` 字段
- **`reasoning_effort_map`** — 推理力度映射，将上游不支持的 effort 级别映射到可用级别
- **`socks5_proxies`** — SOCKS5 代理列表；`active_socks5` 设为代理 `addr` 即使用该代理，设为 `__round_robin__` 则轮询，设为 `__rate_limit_switch__` 则在收到 429 时自动切换
- **`upstreams`** — 上游配置，每个条目包含 `base_url`、`api_key`（每行一个 key 实现多 key 轮询）、`api_type`（`openai` / `anthropic` / `openai-responses`）、`custom_models`（自定义模型列表，不拉取上游 `/models`）
- **`default_upstream`** — 默认上游名称

### API Key 多 key 轮询

`api_key` 字段支持多行写入多个 key，网关会按轮询顺序分发请求。单个 key 触发 429 时自动切换到下一个 key。

## 协议转换矩阵

| 下游 \ 上游 | OpenAI Chat | Anthropic Messages | Responses API |
|-------------|:-----------:|:-----------------:|:-------------:|
| **OpenAI Chat** | 直通 | 格式转换 | 格式转换 |
| **Anthropic** | 格式转换 | 直通 | 格式转换 |
| **Responses** | 格式转换 | 格式转换 | 直通 |

直通（passthrough）模式下，请求体只替换 `model` 字段后原样转发，转换开销最低。

## 请求流程

```
客户端请求
    │
    ▼
模型解析（别名 → 目标模型 → 上游）
    │
    ▼
格式转换（Anthropic / Responses → OpenAI Chat）
    │
    ▼
上游调用（多 key 轮询 + SOCKS5 代理 + 自动重试）
    │
    ▼
响应转换（OpenAI Chat → 下游协议）
    │
    ▼
Token 统计记录 → 返回客户端
```

## 管理面板

- **Token 统计**：按模型显示请求数、输入/输出 token，含今日明细与累计总计，每 5 秒自动刷新
- **上游配置**：增删改上游节点，支持 OpenAI / Anthropic / Responses 三种协议类型
- **模型映射**：可视化配置别名路由、跨上游跳转、思维链注入
- **SOCKS5 代理**：可视化管理代理列表与启用模式
- **推理力度映射**：自定义 effort 级别转换规则

## 目录结构

```
C:\Users\99050\Documents\GitHub\MiMo-Code/
├── main.go          # 项目唯一入口，包含所有业务逻辑
├── config.json      # 运行时配置文件
├── stats.json       # Token 统计数据（自动生成）
└── README.md        # 本文件
```

## 环境要求

- Go 1.21+
- Windows / Linux / macOS

## 注意事项

- 默认 `api_type` 为 `openai`，如上游是 Anthropic 或 Responses API 请对应填写
- `with_reasoning: true` 仅对支持此字段的上游（如 DeepSeek）生效，其他上游会自动跳过
- Anthropic 直通模式下，系统消息中的 `x-anthropic-billing-header` 会被自动清洗
- 流式请求会自动注入 `stream_options.include_usage: true` 以确保 token 统计准确
- 管理面板密码留空（`-password ""`）时不启用认证，请仅在可信网络中使用
