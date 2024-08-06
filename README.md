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
        -d pgvector/pgvector:pg16

## LLM

| LLM           | 效果 | 推荐  |
|---------------|----|-----|
| gpt-3.5-turbo | 可用 | ⭐⭐⭐ | 

## 工作机制

```mermaid
---
title: 预攻击阶段
---
stateDiagram-v2
    state "资产侦察" as Recon
    state "资产测绘" as AssetMapping
    state "端口扫描" as PortScan
    state "漏扫" as VulScan
    state "目录枚举" as DirectoryBruteforcing
    state new_recon_assets_state <<choice>>
    state new_mapping_assets_state <<choice>>
    [*] --> Recon
    Recon --> new_recon_assets_state
    new_recon_assets_state --> Recon: 有新资产
    new_recon_assets_state --> AssetMapping: 无新资产
    AssetMapping --> new_mapping_assets_state
    new_mapping_assets_state --> Recon: 有新资产
    new_mapping_assets_state --> PortScan: 无新资产
    PortScan --> VulScan
    VulScan --> DirectoryBruteforcing
    DirectoryBruteforcing --> [*]
```


```mermaid
---
title: 攻击阶段
---
stateDiagram-v2
    state "攻击面分析" as AttackSurfaceResearch
    state "打点研究" as EstablishingFootholdResearch
    state "审核攻击计划" as AttackPlanReview
    state "部署并实施攻击" as DeployAndExecuteTheAttack
    state attack_plan_review_state <<choice>>
    [*] --> AttackSurfaceResearch
    AttackSurfaceResearch --> EstablishingFootholdResearch
    EstablishingFootholdResearch --> AttackPlanReview
    AttackPlanReview --> attack_plan_review_state
    attack_plan_review_state --> EstablishingFootholdResearch: 重做
    attack_plan_review_state --> [*]: 否决
    attack_plan_review_state --> DeployAndExecuteTheAttack: 通过
    DeployAndExecuteTheAttack --> [*]
```
