---
name: codeseed-context-index
description: 维护 docs/context 作为简洁的项目上下文索引，让新的模型 thread 能快速发现架构、约束、模块设计、Git 规则、可复用组件等工作背景。
license: MIT
compatibility: 适用于 Codeseed 管理的项目 skills 以及兼容 Agent Skills 的客户端。
metadata:
  codeseed.version: "0.1.0"
---

# Codeseed Context Index

当需要为 AI 协作开发创建或维护项目上下文时，使用这个 skill。

目标是让新开启的 thread 不需要用户重复输入背景信息，也能快速进入工作状态。`docs/context/` 目录应该作为简洁索引，指向真正需要阅读的详细文档。

## 职责

1. 项目初始化时创建 `docs/context/`。
2. 将 `docs/context/README.md` 作为主要上下文索引。
3. 保持索引简洁：它应该告诉模型读什么，而不是复制所有细节。
4. 链接到架构、模块设计、代码约束、Git 要求、可复用组件和运行说明等详细文档。
5. 当项目结构、约定或重要决策变化时，更新上下文索引。
6. 如果已有文档是权威来源，优先更新已有文档，再让上下文索引指向它。

## 全局规则

任何安装了这个 skill 的项目都采用以下约定：

1. 开启新的模型 thread 时，在对项目做假设前先阅读 `docs/context/README.md`。
2. 如果 `docs/context/README.md` 链接了与当前任务相关的上下文，只继续阅读任务需要的那些文件。
3. 如果 `docs/context/` 缺失或过期，在依赖项目记忆前先创建或修复它。
4. 将这条规则视为项目级通用指引，而不是只适用于 Codeseed 仓库的约定。

## 建议文件

只创建对项目真正有用的文件：

1. `docs/context/README.md`：简洁索引和阅读顺序。
2. `docs/context/architecture.md`：系统设计和框架设计入口。
3. `docs/context/modules.md`：模块边界和职责。
4. `docs/context/constraints.md`：代码规则、设计约束和测试期望。
5. `docs/context/git.md`：分支、remote、commit 和发布要求。
6. `docs/context/components.md`：可复用组件、helpers 或内部 API。

## 维护规则

1. 保持 `docs/context/README.md` 足够短，适合每个 thread 开始时阅读。
2. 将稳定细节放进专门文件，并从索引链接过去。
3. 避免把大段源码复制进上下文文档。
4. 指向重要文件时，优先使用清晰的相对路径。
5. 当某个文档过期时，更新或移除索引条目。
6. 面向用户的 Markdown 上下文文档应尽量提供中文版本。

## 新 Thread 协议

在使用这个 skill 的项目中开始工作时：

1. 先阅读 `docs/context/README.md`。
2. 只根据当前任务继续阅读索引中相关的链接。
3. 如果存在 `AGENTS.md`，也要检查它。
4. 当任务改变了项目中的长期知识时，更新上下文文档。
