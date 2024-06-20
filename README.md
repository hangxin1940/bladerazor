# Blade Razor 刃影

由人工智能驱动的渗透测试解决方案

An AI-Driven Pentesting Solution.

## 使用

    # 创建一个 python 3.12 虚拟环境, 你也可以用 virtualenv
    conda create -n bladerazor python=3.12.3
    conda activate bladerazor
    
    # 更新
    conda update --all
    pip install pip-review
    pip-review --local --auto

    # 安装依赖
    conda env update --file environment.yml
    pip install -r requirements.txt
    

## 数据库

    docker run --name bladerazor-pg -e POSTGRES_USER=bladerazor -e POSTGRES_PASSWORD=123456 -e POSTGRES_DB=bladerazor -p 15432:5432 -d postgres:16
    