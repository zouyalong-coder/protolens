---
name: codeseed-skill-author
description: 创建、审查和改进 Codeseed 管理的 agent skills。适用于 skill.toml、SKILL.md、preset skills 或项目 skill 元数据相关工作。
license: MIT
compatibility: 适用于 Codeseed 管理的项目 skills 以及兼容 Agent Skills 的客户端。
triggers:
  - skill.toml
  - SKILL.md
  - preset skill
  - project skill metadata
  - skill authoring
default_behavior:
  - 将特定 skill 的触发规则和默认行为写在该 skill 自己的 SKILL.md front matter 中。
  - 不要求 AGENTS.md 枚举单个 skill。
metadata:
  codeseed.version: "0.1.0"
---

# Codeseed Skill Author

当需要为 Codeseed 管理的项目创建、审查或改进 agent skills 时，使用这个 skill。

## 工作流程

1. 识别 skill 面向的目标 agent。
2. 让 skill 聚焦于一个可重复使用的能力。
3. 定义预期文件、入口文档和放置目标。
4. 在 `SKILL.md` front matter 中放置激活线索，尤其是 `description`、`triggers` 和 `default_behavior`。
5. 让 `AGENTS.md` 保持为通用 skill 发现入口，不要在那里硬编码单个 skill 名称。
6. Skill 文档只保留一种语言；当前 Codeseed preset skills 使用中文 `SKILL.md`。
7. 优先提供可以被 `codeseed doctor` 验证的小例子。
8. 除非 skill 明确记录远程依赖，否则避免隐藏依赖外部 SkillHub。

## 输出预期

产出 skill 时，应包含：

1. `skill.toml`
2. `SKILL.md`
3. 所有被引用的 assets 或 scripts

这个 skill 应该可以先从本地目录安装，然后再考虑发布到其它地方。
