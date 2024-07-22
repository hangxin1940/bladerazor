# Blade Razor 刃影

由人工智能驱动的渗透测试解决方案

An AI-Driven Pentesting Solution.

资产侦察工具借鉴了 [OneForAll](https://github.com/shmilylty/OneForAll)


## 使用

    # 创建一个 python 3.12 虚拟环境, 你也可以用 virtualenv
    conda create -n bladerazor python=3.12.3
    conda activate bladerazor
    
    # 更新
    conda update --all
    pip install pip-review
    pip-review --local --auto

    # 安装依赖
    pip install -r requirements.txt

## 数据库

    docker run --name bladerazor-pg \
        -e POSTGRES_USER=bladerazor \
        -e POSTGRES_PASSWORD=123456 \
        -e POSTGRES_DB=bladerazor \
        -p 15432:5432 \
        -d postgres:16

## LLM

| LLM           | 效果 | 推荐  |
|---------------|----|-----|
| gpt-3.5-turbo | 可用 | ⭐⭐⭐ | 

## 工作机制

```mermaid
---
title: 智能代理工作流程
---
stateDiagram-v2
    state "资产侦察" as Recon
    state "资产测绘" as AssetMapping
    state "漏扫" as VulScan
    state "漏洞分析与利用" as Exploit
    state new_recon_assets_state <<choice>>
    state new_mapping_assets_state <<choice>>
    [*] --> Recon
    Recon --> new_recon_assets_state
    new_recon_assets_state --> Recon: 有新资产
    new_recon_assets_state --> AssetMapping: 无新资产
    AssetMapping --> new_mapping_assets_state
    new_mapping_assets_state --> Recon: 有新资产
    new_mapping_assets_state --> VulScan: 无新资产
    VulScan --> Exploit
```