#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""常用开源依赖 Top 清单生成（Maven / NPM / PyPI / Go，默认每生态 1000 条）。

产出两份同源数据：

  1. ``scabase-fetcher/data/popular-packages.json``
     站点「常用依赖 Top 清单」面板数据，每生态 N 条
     ``{rank, name, version, desc, line, meta}``。
  2. ``scabase-fetcher/data/pkg_list_popular.txt``
     ``ecosystem|package|version`` 文本，供 community-health 工作流采集健康度信号
     （默认每生态只取前 ``--txt-top`` 条，避免 CI 采集量过大）。

各生态数据源与排序依据：

  npm    npm registry 搜索接口（392 个生态关键词采样，每关键词取 popularity
         权重最高的 250 条），以搜索响应自带的「近一周下载量」排序；
         版本号取 registry 最新发布版；人工整理的高频包作为保底种子。
  pypi   top-pypi-packages（基于 PyPI 官方下载量统计的近 30 天榜单）取前 N 条，
         版本号经 deps.dev 校准为最新稳定版。
  maven  人工整理的高频构件作为种子，经 deps.dev 依赖图展开一层得到候选池
         （即「高频构件本身的依赖」），再以 deps.dev「公开依赖项目数」排序；
         Maven Central 不公开构件级下载量，这是目前最接近热度的公开信号。
  go     人工整理的生态核心模块（golang.org/x、k8s.io、云 SDK 等）+ GitHub
         Star 排序的热门 Go 仓库（经 deps.dev 项目映射得到模块路径与版本）。

用法：
    # 联网全量刷新（四生态各 1000 条，耗时约 10~25 分钟）
    python scabase-fetcher/scripts/gen_popular_packages.py --refresh

    # 只取前 100 条 / 调整并发
    python scabase-fetcher/scripts/gen_popular_packages.py --refresh --top 100 --workers 12

    # 离线：把仓库内已校准的 JSON 转成 pkg_list（无网络）
    python scabase-fetcher/scripts/gen_popular_packages.py
"""
import argparse
import json
import os
import re
import sys
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except ImportError:  # pragma: no cover - 离线环境没有 requests
    requests = None

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.normpath(os.path.join(HERE, "..", "data"))
JSON_OUT = os.path.join(DATA_DIR, "popular-packages.json")
TXT_OUT = os.path.join(DATA_DIR, "pkg_list_popular.txt")

DEPS_API = "https://api.deps.dev/v3alpha"
NPM_SEARCH = "https://registry.npmjs.org/-/v1/search"
NPM_REGISTRY = "https://registry.npmjs.org"
PYPI_TOP_URL = ("https://hugovk.github.io/top-pypi-packages/"
                "top-pypi-packages-30-days.min.json")
GITHUB_SEARCH = "https://api.github.com/search/repositories"

TOP_DEFAULT = 1000
TXT_TOP_DEFAULT = 100
WORKERS_DEFAULT = 8

# 生态展示顺序与标签
ECOSYSTEMS = [
    ("maven", "Maven 常用 Top"),
    ("npm", "NPM 常用 Top"),
    ("pypi", "PyPI 常用 Top"),
    ("go", "Go 常用 Top"),
]

# ---------------------------------------------------------------------------
# 人工整理的高频依赖种子（保底：联网失败或排序信号缺失时仍保证清单可用）
# ---------------------------------------------------------------------------

# (groupId:artifactId, 说明)
MAVEN_SEEDS = [
    # ---- Spring 全家桶 ----
    ("org.springframework.boot:spring-boot-starter-web", "Spring Boot Web 启动器"),
    ("org.springframework.boot:spring-boot-starter", "Spring Boot 核心启动器"),
    ("org.springframework.boot:spring-boot-starter-data-jpa", "JPA 数据访问"),
    ("org.springframework.boot:spring-boot-starter-jdbc", "JDBC 数据访问"),
    ("org.springframework.boot:spring-boot-starter-test", "测试套件"),
    ("org.springframework.boot:spring-boot-starter-security", "安全框架"),
    ("org.springframework.boot:spring-boot-starter-data-redis", "Redis 数据访问"),
    ("org.springframework.boot:spring-boot-starter-validation", "参数校验"),
    ("org.springframework.boot:spring-boot-starter-actuator", "运维监控端点"),
    ("org.springframework.boot:spring-boot-starter-thymeleaf", "服务端模板引擎"),
    ("org.springframework.boot:spring-boot-starter-webflux", "响应式 Web"),
    ("org.springframework.boot:spring-boot-starter-aop", "切面编程"),
    ("org.springframework.boot:spring-boot-starter-cache", "缓存抽象"),
    ("org.springframework.boot:spring-boot-starter-quartz", "定时任务"),
    ("org.springframework.boot:spring-boot-starter-mail", "邮件发送"),
    ("org.springframework.boot:spring-boot-starter-websocket", "WebSocket"),
    ("org.springframework.boot:spring-boot-starter-oauth2-resource-server", "OAuth2 资源服务"),
    ("org.springframework.boot:spring-boot-configuration-processor", "配置元数据生成"),
    ("org.springframework.boot:spring-boot-devtools", "开发期热重载"),
    ("org.springframework.boot:spring-boot-maven-plugin", "Maven 打包插件"),
    ("org.springframework:spring-core", "Spring 核心"),
    ("org.springframework:spring-context", "Spring 上下文"),
    ("org.springframework:spring-beans", "Spring Bean 容器"),
    ("org.springframework:spring-web", "Spring Web 基础"),
    ("org.springframework:spring-webmvc", "Spring MVC"),
    ("org.springframework:spring-tx", "事务管理"),
    ("org.springframework:spring-jdbc", "JDBC 封装"),
    ("org.springframework:spring-test", "Spring 测试"),
    ("org.springframework:spring-aop", "面向切面"),
    ("org.springframework:spring-expression", "表达式语言"),
    ("org.springframework:spring-orm", "ORM 集成"),
    ("org.springframework:spring-oxm", "对象 XML 映射"),
    ("org.springframework:spring-context-support", "上下文扩展支持"),
    ("org.springframework.security:spring-security-core", "Security 核心"),
    ("org.springframework.security:spring-security-web", "Security Web"),
    ("org.springframework.security:spring-security-config", "Security 配置"),
    ("org.springframework.security:spring-security-oauth2-authorization-server", "OAuth2 授权服务器"),
    ("org.springframework.data:spring-data-jpa", "Spring Data JPA"),
    ("org.springframework.data:spring-data-redis", "Spring Data Redis"),
    ("org.springframework.data:spring-data-mongodb", "Spring Data MongoDB"),
    ("org.springframework.data:spring-data-elasticsearch", "Spring Data Elasticsearch"),
    ("org.springframework.cloud:spring-cloud-starter-openfeign", "声明式服务调用"),
    ("org.springframework.cloud:spring-cloud-starter-gateway", "API 网关"),
    ("org.springframework.cloud:spring-cloud-starter-config", "配置中心客户端"),
    ("org.springframework.cloud:spring-cloud-starter-loadbalancer", "客户端负载均衡"),
    ("org.springframework.cloud:spring-cloud-starter-bootstrap", "引导配置支持"),
    ("org.springframework.kafka:spring-kafka", "Kafka 集成"),
    ("org.springframework.amqp:spring-rabbit", "RabbitMQ 集成"),
    ("org.springframework.retry:spring-retry", "重试框架"),
    ("org.springframework.batch:spring-batch-core", "批处理框架"),
    ("org.springframework.session:spring-session-data-redis", "会话共享"),
    # ---- Jakarta / Javax API ----
    ("jakarta.servlet:jakarta.servlet-api", "Servlet API"),
    ("jakarta.validation:jakarta.validation-api", "校验 API"),
    ("jakarta.annotation:jakarta.annotation-api", "注解 API"),
    ("jakarta.persistence:jakarta.persistence-api", "JPA API"),
    ("jakarta.transaction:jakarta.transaction-api", "事务 API"),
    ("jakarta.xml.bind:jakarta.xml.bind-api", "XML 绑定 API"),
    ("jakarta.activation:jakarta.activation-api", "激活框架 API"),
    ("jakarta.mail:jakarta.mail-api", "邮件 API"),
    ("javax.servlet:javax.servlet-api", "Servlet API（旧版）"),
    ("javax.validation:validation-api", "校验 API（旧版）"),
    ("javax.annotation:javax.annotation-api", "注解 API（旧版）"),
    ("javax.xml.bind:jaxb-api", "XML 绑定 API（旧版）"),
    ("org.eclipse.persistence:javax.persistence", "JPA API（旧版）"),
    ("com.sun.mail:javax.mail", "邮件实现"),
    # ---- ORM / 数据访问 ----
    ("org.mybatis:mybatis", "ORM 框架"),
    ("org.mybatis:mybatis-spring", "MyBatis Spring 集成"),
    ("org.mybatis.spring.boot:mybatis-spring-boot-starter", "MyBatis Boot 集成"),
    ("com.baomidou:mybatis-plus-boot-starter", "MyBatis-Plus 启动器"),
    ("com.baomidou:mybatis-plus-core", "MyBatis-Plus 增强"),
    ("com.baomidou:mybatis-plus-annotation", "MyBatis-Plus 注解"),
    ("com.baomidou:mybatis-plus-extension", "MyBatis-Plus 扩展"),
    ("com.baomidou:mybatis-plus-generator", "代码生成器"),
    ("com.baomidou:dynamic-datasource-spring-boot-starter", "动态数据源"),
    ("tk.mybatis:mapper-spring-boot-starter", "通用 Mapper"),
    ("com.github.pagehelper:pagehelper-spring-boot-starter", "分页插件"),
    ("org.hibernate:hibernate-core", "Hibernate ORM"),
    ("org.hibernate.validator:hibernate-validator", "Bean Validation 实现"),
    ("com.github.jsqlparser:jsqlparser", "SQL 解析器"),
    ("p6spy:p6spy", "SQL 监控"),
    ("com.github.gavlyukovskiy:p6spy-spring-boot-starter", "SQL 监控 Boot 集成"),
    # ---- JSON ----
    ("com.fasterxml.jackson.core:jackson-databind", "JSON 对象绑定"),
    ("com.fasterxml.jackson.core:jackson-core", "JSON 流式处理"),
    ("com.fasterxml.jackson.core:jackson-annotations", "JSON 注解"),
    ("com.fasterxml.jackson.dataformat:jackson-dataformat-yaml", "YAML 解析"),
    ("com.fasterxml.jackson.dataformat:jackson-dataformat-xml", "XML 解析"),
    ("com.fasterxml.jackson.datatype:jackson-datatype-jsr310", "Java 8 时间类型"),
    ("com.fasterxml.jackson.module:jackson-module-parameter-names", "构造参数名支持"),
    ("com.google.code.gson:gson", "JSON 解析"),
    ("com.alibaba:fastjson", "JSON 解析（已归档，典型风险组件）"),
    ("com.alibaba:fastjson2", "JSON 解析 2.x"),
    ("com.jayway.jsonpath:json-path", "JSONPath 查询"),
    ("com.googlecode.json-simple:json-simple", "轻量 JSON"),
    ("org.json:json", "JSON 参考实现"),
    ("com.squareup.moshi:moshi", "现代 JSON 库"),
    # ---- 日志 ----
    ("org.slf4j:slf4j-api", "日志门面"),
    ("ch.qos.logback:logback-classic", "日志实现"),
    ("ch.qos.logback:logback-core", "日志核心"),
    ("org.apache.logging.log4j:log4j-core", "Log4j2 实现"),
    ("org.apache.logging.log4j:log4j-api", "Log4j2 API"),
    ("org.apache.logging.log4j:log4j-slf4j2-impl", "Log4j2 桥接 SLF4J"),
    ("org.apache.logging.log4j:log4j-to-slf4j", "Log4j2 转 SLF4J"),
    ("log4j:log4j", "Log4j 1.x（已停止维护，典型风险组件）"),
    ("org.slf4j:jul-to-slf4j", "JUL 桥接"),
    ("org.slf4j:log4j-over-slf4j", "Log4j1 桥接"),
    ("org.slf4j:jcl-over-slf4j", "JCL 桥接"),
    ("net.logstash.logback:logstash-logback-encoder", "Logstash 编码器"),
    # ---- 工具库 ----
    ("com.google.guava:guava", "Java 通用工具库"),
    ("org.apache.commons:commons-lang3", "基础工具类"),
    ("org.apache.commons:commons-text", "文本处理"),
    ("org.apache.commons:commons-collections4", "集合工具"),
    ("org.apache.commons:commons-compress", "压缩解压"),
    ("org.apache.commons:commons-csv", "CSV 处理"),
    ("org.apache.commons:commons-math3", "数学计算"),
    ("org.apache.commons:commons-pool2", "对象池"),
    ("org.apache.commons:commons-exec", "外部进程执行"),
    ("org.apache.commons:commons-email", "邮件发送"),
    ("commons-io:commons-io", "IO 工具"),
    ("commons-codec:commons-codec", "编解码工具"),
    ("commons-beanutils:commons-beanutils", "Bean 反射工具"),
    ("commons-fileupload:commons-fileupload", "文件上传"),
    ("commons-logging:commons-logging", "日志门面（旧）"),
    ("commons-collections:commons-collections", "集合工具（旧）"),
    ("commons-validator:commons-validator", "参数校验"),
    ("cn.hutool:hutool-core", "Hutool 核心"),
    ("cn.hutool:hutool-all", "Hutool 全家桶"),
    ("cn.hutool:hutool-crypto", "Hutool 加密"),
    ("cn.hutool:hutool-http", "Hutool HTTP"),
    ("org.projectlombok:lombok", "编译期代码生成"),
    ("org.mapstruct:mapstruct", "对象映射"),
    ("org.mapstruct:mapstruct-processor", "对象映射处理器"),
    ("ma.glasnost.orika:orika-core", "Bean 拷贝"),
    ("org.modelmapper:modelmapper", "对象映射"),
    ("org.aspectj:aspectjweaver", "切面织入"),
    ("org.aspectj:aspectjrt", "切面运行时"),
    ("cglib:cglib", "动态代理（旧）"),
    ("org.javassist:javassist", "字节码编辑"),
    ("net.bytebuddy:byte-buddy", "字节码增强"),
    ("org.objenesis:objenesis", "无构造实例化"),
    ("org.reflections:reflections", "类路径扫描"),
    ("com.alibaba:transmittable-thread-local", "线程池上下文传递"),
    ("com.lmax:disruptor", "高性能队列"),
    ("it.unimi.dsi:fastutil", "高性能集合"),
    ("io.github.classgraph:classgraph", "类路径扫描"),
    ("org.openjdk.jol:jol-core", "对象布局分析"),
    ("com.alibaba:QLExpress", "表达式引擎"),
    ("org.mvel:mvel2", "表达式语言"),
    ("org.codehaus.groovy:groovy", "Groovy 脚本引擎"),
    # ---- HTTP / 网络 ----
    ("org.apache.httpcomponents:httpclient", "HTTP 客户端 4.x"),
    ("org.apache.httpcomponents.client5:httpclient5", "HTTP 客户端 5.x"),
    ("org.apache.httpcomponents:httpcore", "HTTP 核心"),
    ("org.apache.httpcomponents.core5:httpcore5", "HTTP 核心 5.x"),
    ("org.apache.httpcomponents:httpmime", "MIME 支持"),
    ("org.apache.httpcomponents:httpasyncclient", "异步 HTTP 客户端"),
    ("com.squareup.okhttp3:okhttp", "HTTP 客户端"),
    ("com.squareup.okhttp3:logging-interceptor", "HTTP 日志拦截器"),
    ("com.squareup.okhttp3:mockwebserver", "HTTP Mock 服务"),
    ("com.squareup.retrofit2:retrofit", "类型安全 HTTP 客户端"),
    ("com.squareup.retrofit2:converter-jackson", "Retrofit Jackson 转换"),
    ("io.github.openfeign:feign-core", "声明式 HTTP 客户端"),
    ("io.github.openfeign:feign-okhttp", "Feign OkHttp"),
    ("io.rest-assured:rest-assured", "REST API 测试"),
    ("io.rest-assured:json-schema-validator", "JSON Schema 校验"),
    ("org.asynchttpclient:async-http-client", "异步 HTTP 客户端"),
    # ---- 限流 / 熔断 / 弹性 ----
    ("io.github.resilience4j:resilience4j-spring-boot2", "弹性容错"),
    ("io.github.resilience4j:resilience4j-circuitbreaker", "熔断器"),
    ("com.netflix.hystrix:hystrix-core", "熔断（旧）"),
    ("com.alibaba.csp:sentinel-core", "流量防卫兵"),
    # ---- Netty / RPC ----
    ("io.netty:netty-all", "网络应用框架"),
    ("io.netty:netty-codec-http", "HTTP 编解码"),
    ("io.netty:netty-handler", "网络处理器"),
    ("io.netty:netty-transport", "传输层"),
    ("io.netty:netty-codec-http2", "HTTP/2 编解码"),
    ("io.grpc:grpc-netty-shaded", "gRPC 传输"),
    ("io.grpc:grpc-protobuf", "gRPC Protobuf"),
    ("io.grpc:grpc-stub", "gRPC Stub"),
    ("io.grpc:grpc-core", "gRPC 核心"),
    ("com.google.protobuf:protobuf-java", "Protobuf 运行时"),
    ("com.google.protobuf:protobuf-java-util", "Protobuf 工具"),
    ("org.apache.thrift:libthrift", "Thrift RPC"),
    ("org.apache.avro:avro", "Avro 序列化"),
    ("com.alibaba:dubbo", "Dubbo 2.x"),
    ("org.apache.dubbo:dubbo", "Dubbo 3.x"),
    ("org.apache.dubbo:dubbo-spring-boot-starter", "Dubbo Boot 集成"),
    ("org.apache.curator:curator-recipes", "ZooKeeper  recipes"),
    ("org.apache.curator:curator-framework", "ZooKeeper 客户端"),
    ("org.apache.curator:curator-client", "ZooKeeper 底层客户端"),
    ("org.apache.zookeeper:zookeeper", "ZooKeeper 服务端"),
    ("com.101tec:zkclient", "ZooKeeper 客户端（旧）"),
    ("io.etcd:jetcd-core", "etcd 客户端"),
    # ---- 消息队列 ----
    ("org.apache.kafka:kafka-clients", "Kafka 客户端"),
    ("org.apache.rocketmq:rocketmq-client", "RocketMQ 客户端"),
    ("org.apache.rocketmq:rocketmq-spring-boot-starter", "RocketMQ Boot 集成"),
    ("com.rabbitmq:amqp-client", "RabbitMQ 客户端"),
    ("org.apache.pulsar:pulsar-client", "Pulsar 客户端"),
    ("com.aliyun.openservices:ons-client", "阿里云消息服务"),
    # ---- Redis ----
    ("redis.clients:jedis", "Redis 客户端"),
    ("io.lettuce:lettuce-core", "Redis 客户端（响应式）"),
    ("org.redisson:redisson-spring-boot-starter", "Redis 分布式对象"),
    ("org.redisson:redisson", "Redisson 核心"),
    # ---- 数据库驱动 / 连接池 ----
    ("com.mysql:mysql-connector-j", "MySQL 驱动"),
    ("mysql:mysql-connector-java", "MySQL 驱动（旧）"),
    ("org.postgresql:postgresql", "PostgreSQL 驱动"),
    ("com.oracle.database.jdbc:ojdbc8", "Oracle 驱动"),
    ("com.microsoft.sqlserver:mssql-jdbc", "SQL Server 驱动"),
    ("com.h2database:h2", "内存数据库"),
    ("org.hsqldb:hsqldb", "内存数据库"),
    ("org.xerial:sqlite-jdbc", "SQLite 驱动"),
    ("org.mariadb.jdbc:mariadb-java-client", "MariaDB 驱动"),
    ("ru.yandex.clickhouse:clickhouse-jdbc", "ClickHouse 驱动"),
    ("com.clickhouse:clickhouse-jdbc", "ClickHouse 驱动（新版）"),
    ("com.kingbase8:kingbase8", "人大金仓驱动"),
    ("org.mongodb:mongodb-driver-sync", "MongoDB 同步驱动"),
    ("com.alibaba:druid", "数据库连接池"),
    ("com.alibaba:druid-spring-boot-starter", "连接池 Boot 集成"),
    ("com.zaxxer:HikariCP", "高性能连接池"),
    ("org.apache.commons:commons-dbcp2", "连接池"),
    ("com.mchange:c3p0", "连接池（旧）"),
    ("org.apache.tomcat:tomcat-jdbc", "Tomcat 连接池"),
    # ---- Web 容器 ----
    ("org.apache.tomcat.embed:tomcat-embed-core", "内嵌 Tomcat"),
    ("org.eclipse.jetty:jetty-server", "Jetty 服务端"),
    ("io.undertow:undertow-core", "Undertow 容器"),
    # ---- API 文档 ----
    ("io.swagger.core.v3:swagger-annotations", "API 文档注解"),
    ("org.springdoc:springdoc-openapi-starter-webmvc-ui", "OpenAPI 文档界面"),
    ("com.github.xiaoymin:knife4j-openapi3-spring-boot-starter", "Knife4j 接口文档"),
    ("com.github.xiaoymin:knife4j-spring-boot-starter", "Knife4j 接口文档（旧）"),
    # ---- 安全 ----
    ("org.apache.shiro:shiro-spring", "Shiro 安全框架"),
    ("org.apache.shiro:shiro-core", "Shiro 核心"),
    ("io.jsonwebtoken:jjwt-api", "JWT API"),
    ("io.jsonwebtoken:jjwt-impl", "JWT 实现"),
    ("io.jsonwebtoken:jjwt-jackson", "JWT JSON 处理"),
    ("com.auth0:java-jwt", "JWT 签发与校验"),
    ("com.nimbusds:nimbus-jose-jwt", "JOSE/JWT 实现"),
    ("me.zhyd.oauth:JustAuth", "第三方登录"),
    ("cn.dev33:sa-token-spring-boot-starter", "Sa-Token 认证授权"),
    ("org.bouncycastle:bcprov-jdk18on", "加密算法库"),
    ("com.github.ulisesbocchio:jasypt-spring-boot-starter", "配置加密"),
    ("com.google.crypto.tink:tink", "加密工具库"),
    # ---- 测试 ----
    ("junit:junit", "JUnit 4 单元测试"),
    ("org.junit.jupiter:junit-jupiter", "JUnit 5 单元测试"),
    ("org.junit.jupiter:junit-jupiter-api", "JUnit 5 API"),
    ("org.junit.jupiter:junit-jupiter-engine", "JUnit 5 引擎"),
    ("org.junit.vintage:junit-vintage-engine", "JUnit 4 兼容引擎"),
    ("org.junit.platform:junit-platform-launcher", "JUnit 平台启动器"),
    ("org.mockito:mockito-core", "Mock 测试框架"),
    ("org.mockito:mockito-junit-jupiter", "Mockito JUnit 5 集成"),
    ("org.assertj:assertj-core", "流式断言"),
    ("org.testng:testng", "TestNG 测试框架"),
    ("org.powermock:powermock-module-junit4", "静态 Mock"),
    ("com.github.tomakehurst:wiremock-jre8", "HTTP Mock"),
    ("org.testcontainers:testcontainers", "集成测试容器"),
    ("org.testcontainers:junit-jupiter", "容器测试 JUnit 5 集成"),
    ("org.awaitility:awaitility", "异步断言"),
    ("org.hamcrest:hamcrest", "匹配器"),
    ("com.tngtech.archunit:archunit", "架构规则测试"),
    ("org.openjdk.jmh:jmh-core", "基准测试"),
    ("org.seleniumhq.selenium:selenium-java", "浏览器自动化"),
    ("com.google.jimfs:jimfs", "内存文件系统"),
    ("nl.jqno.equalsverifier:equalsverifier", "equals 契约测试"),
    ("org.opentest4j:opentest4j", "测试断言异常"),
    ("org.apiguardian:apiguardian-api", "API 注解"),
    # ---- 缓存 ----
    ("com.github.ben-manes.caffeine:caffeine", "本地缓存"),
    ("com.github.ben-manes.caffeine:jcache", "JCache 适配"),
    ("org.ehcache:ehcache", "Ehcache 缓存"),
    ("org.cache2k:cache2k-core", "Cache2k"),
    # ---- 可观测性 ----
    ("io.micrometer:micrometer-core", "可观测性埋点"),
    ("io.micrometer:micrometer-registry-prometheus", "Prometheus 指标"),
    ("io.prometheus:simpleclient", "Prometheus 客户端"),
    ("io.prometheus:simpleclient_common", "Prometheus 公共模型"),
    ("io.opentelemetry:opentelemetry-api", "OpenTelemetry API"),
    # ---- Office / 文件 ----
    ("org.apache.poi:poi", "Office 文档处理"),
    ("org.apache.poi:poi-ooxml", "Office OOXML 处理"),
    ("com.alibaba:easyexcel", "Excel 处理"),
    ("org.apache.pdfbox:pdfbox", "PDF 处理"),
    ("com.itextpdf:itextpdf", "PDF 生成"),
    ("com.itextpdf:itext-asian", "PDF 中文支持"),
    ("com.google.zxing:core", "二维码生成"),
    ("com.google.zxing:javase", "二维码 JavaSE 支持"),
    ("net.coobird:thumbnailator", "图片缩略图"),
    # ---- 解析 ----
    ("org.yaml:snakeyaml", "YAML 解析"),
    ("org.dom4j:dom4j", "XML 解析"),
    ("org.jsoup:jsoup", "HTML 解析"),
    ("com.thoughtworks.xstream:xstream", "对象序列化（历史漏洞较多）"),
    ("jdom:jdom", "XML 解析（旧）"),
    ("org.jdom:jdom2", "XML 解析"),
    ("org.glassfish.jaxb:jaxb-runtime", "JAXB 运行时"),
    # ---- 压缩 / IO ----
    ("org.xerial.snappy:snappy-java", "Snappy 压缩"),
    ("org.lz4:lz4-java", "LZ4 压缩"),
    ("com.github.luben:zstd-jni", "Zstandard 压缩"),
    ("org.tukaani:xz", "XZ 压缩"),
    ("net.lingala.zip4j:zip4j", "ZIP 处理"),
    # ---- 时间 / 中文 ----
    ("joda-time:joda-time", "日期时间库"),
    ("com.belerweb:pinyin4j", "中文拼音"),
    # ---- 模板引擎 ----
    ("org.freemarker:freemarker", "模板引擎"),
    ("org.apache.velocity:velocity-engine-core", "模板引擎"),
    ("org.thymeleaf:thymeleaf", "服务端模板"),
    ("org.thymeleaf:thymeleaf-spring5", "Thymeleaf Spring 5"),
    ("com.ibeetl:beetl", "模板引擎"),
    # ---- 响应式 ----
    ("io.projectreactor:reactor-core", "响应式编程"),
    ("io.projectreactor.netty:reactor-netty", "响应式网络"),
    ("io.reactivex.rxjava2:rxjava", "RxJava 2"),
    ("io.reactivex.rxjava3:rxjava", "RxJava 3"),
    ("io.vertx:vertx-core", "Vert.x 核心"),
    ("io.vertx:vertx-web", "Vert.x Web"),
    # ---- 阿里云 / 云 SDK ----
    ("com.aliyun:aliyun-java-sdk-core", "阿里云 SDK 核心"),
    ("com.aliyun:dysmsapi20170525", "阿里云短信"),
    ("com.aliyun:alipay-sdk-java", "支付宝 SDK"),
    ("com.aliyun.oss:aliyun-sdk-oss", "阿里云 OSS"),
    ("com.aliyun:tea-openapi", "阿里云 OpenAPI 客户端"),
    ("com.tencentcloudapi:tencentcloud-sdk-java", "腾讯云 SDK"),
    ("com.qiniu:qiniu-java-sdk", "七牛云 SDK"),
    ("com.amazonaws:aws-java-sdk-s3", "AWS SDK v1"),
    ("software.amazon.awssdk:s3", "AWS SDK v2"),
    ("io.minio:minio", "MinIO 对象存储"),
    # ---- 微服务 / 云原生 ----
    ("com.alibaba.cloud:spring-cloud-starter-alibaba-nacos-discovery", "Nacos 服务发现"),
    ("com.alibaba.cloud:spring-cloud-starter-alibaba-nacos-config", "Nacos 配置中心"),
    ("com.alibaba.nacos:nacos-client", "Nacos 客户端"),
    ("com.alibaba.csp:sentinel-spring-cloud-gateway", "网关限流"),
    ("org.apache.shardingsphere:shardingsphere-jdbc-core", "分库分表"),
    ("io.seata:seata-spring-boot-starter", "分布式事务"),
    ("io.seata:seata-all", "Seata 全量"),
    ("com.xuxueli:xxl-job-core", "分布式任务调度"),
    ("com.dangdang:elastic-job-lite-core", "分布式任务调度（旧）"),
    ("com.alibaba.otter:canal.client", "MySQL Binlog 订阅"),
    ("com.github.docker-java:docker-java", "Docker 客户端"),
    ("io.fabric8:kubernetes-client", "Kubernetes 客户端"),
    ("io.kubernetes:client-java", "Kubernetes 官方客户端"),
    # ---- 大数据 ----
    ("org.apache.hadoop:hadoop-common", "Hadoop 基础"),
    ("org.apache.hadoop:hadoop-client", "Hadoop 客户端"),
    ("org.apache.hbase:hbase-client", "HBase 客户端"),
    ("org.apache.spark:spark-core_2.12", "Spark 核心"),
    ("org.apache.flink:flink-streaming-java", "Flink 流处理"),
    ("org.apache.lucene:lucene-core", "全文检索"),
    ("org.elasticsearch:elasticsearch", "Elasticsearch 服务端"),
    ("org.elasticsearch.client:elasticsearch-rest-high-level-client", "ES 高级客户端"),
    ("co.elastic.clients:elasticsearch-java", "ES 新版客户端"),
    # ---- 微信生态 ----
    ("com.github.binarywang:weixin-java-mp", "微信公众号 SDK"),
    ("com.github.binarywang:weixin-java-pay", "微信支付 SDK"),
    ("com.github.binarywang:weixin-java-miniapp", "微信小程序 SDK"),
    # ---- 其他常用 ----
    ("com.typesafe:config", "HOCON 配置"),
    ("org.scala-lang:scala-library", "Scala 标准库"),
    ("org.jetbrains.kotlin:kotlin-stdlib", "Kotlin 标准库"),
    ("org.jetbrains.kotlin:kotlin-reflect", "Kotlin 反射"),
    ("com.google.code.findbugs:jsr305", "注解"),
    ("org.checkerframework:checker-qual", "类型注解"),
    ("com.google.errorprone:error_prone_annotations", "错误排查注解"),
    ("org.reactivestreams:reactive-streams", "响应式流 API"),
    ("io.perfmark:perfmark-api", "性能标记 API"),
    # ---- 典型风险组件（用于演示） ----
    ("org.apache.struts:struts2-core", "Struts 2（历史漏洞较多）"),
    ("org.apache.logging.log4j:log4j-web", "Log4j2 Web 支持"),
    ("net.sf.ehcache:ehcache-core", "Ehcache（旧版）"),
]

# (包名, 说明)
NPM_SEEDS = [
    # ---- 运行时 / 工具 ----
    ("lodash", "通用工具函数库"),
    ("tslib", "TypeScript 运行时辅助"),
    ("core-js", "标准库 Polyfill"),
    ("regenerator-runtime", "async/await 运行时"),
    ("semver", "语义化版本解析"),
    ("ms", "时间单位换算"),
    ("uuid", "UUID 生成"),
    ("nanoid", "短 ID 生成"),
    ("debug", "调试日志"),
    ("chalk", "终端着色"),
    ("ansi-styles", "终端样式"),
    ("supports-color", "颜色支持检测"),
    ("commander", "CLI 参数解析"),
    ("yargs", "CLI 参数解析"),
    ("minimist", "参数解析"),
    ("inquirer", "交互式命令行"),
    ("ora", "终端加载动画"),
    ("boxen", "终端文本框"),
    ("figures", "终端符号"),
    ("is-unicode-supported", "Unicode 检测"),
    ("fs-extra", "文件系统增强"),
    ("glob", "文件匹配"),
    ("globby", "文件匹配（Promise）"),
    ("minimatch", "glob 匹配"),
    ("micromatch", "glob 匹配"),
    ("chokidar", "文件监听"),
    ("rimraf", "递归删除"),
    ("del", "删除文件"),
    ("mkdirp", "递归创建目录"),
    ("tempy", "临时文件"),
    ("graceful-fs", "文件系统增强"),
    ("proper-lockfile", "文件锁"),
    ("write-file-atomic", "原子写文件"),
    ("find-up", "向上查找文件"),
    ("locate-path", "路径查找"),
    ("p-limit", "并发限制"),
    ("p-map", "并发映射"),
    ("p-retry", "重试"),
    ("delay", "延时"),
    ("cross-env", "跨平台环境变量"),
    ("dotenv", "环境变量加载"),
    ("dotenv-expand", "环境变量展开"),
    ("os-homedir", "用户目录"),
    ("username", "用户名"),
    ("arch", "CPU 架构"),
    ("os-name", "系统名称"),
    ("execa", "进程执行"),
    ("cross-spawn", "跨平台 spawn"),
    ("shell-quote", "Shell 引用"),
    ("which", "查找可执行文件"),
    ("isexe", "可执行判断"),
    ("node-fetch", "HTTP 客户端"),
    ("got", "HTTP 客户端"),
    ("superagent", "HTTP 客户端"),
    ("axios", "HTTP 客户端"),
    ("ky", "HTTP 客户端"),
    ("undici", "HTTP 客户端"),
    ("follow-redirects", "重定向处理"),
    ("agent-base", "代理基础"),
    ("https-proxy-agent", "HTTPS 代理"),
    ("socks-proxy-agent", "SOCKS 代理"),
    ("proxy-from-env", "代理环境变量"),
    # ---- Web 框架 / 服务端 ----
    ("express", "Web 服务框架"),
    ("koa", "Web 框架"),
    ("fastify", "高性能 Web 框架"),
    ("hapi", "Web 框架"),
    ("restify", "REST 框架"),
    ("nest-common", "Nest 公共库"),
    ("@nestjs/core", "Nest 核心"),
    ("@nestjs/common", "Nest 公共"),
    ("@nestjs/platform-express", "Nest Express 适配"),
    ("body-parser", "请求体解析"),
    ("cors", "跨域中间件"),
    ("helmet", "安全响应头"),
    ("compression", "响应压缩"),
    ("cookie-parser", "Cookie 解析"),
    ("cookie", "Cookie 处理"),
    ("cookie-signature", "Cookie 签名"),
    ("morgan", "HTTP 访问日志"),
    ("pino", "高性能日志库"),
    ("pino-http", "HTTP 日志"),
    ("winston", "日志库"),
    ("bunyan", "日志库"),
    ("loglevel", "日志级别"),
    ("signale", "日志输出"),
    ("multer", "文件上传中间件"),
    ("formidable", "表单解析"),
    ("busboy", "流式表单解析"),
    ("qs", "查询字符串解析"),
    ("querystring", "查询字符串"),
    ("path-to-regexp", "路径转正则"),
    ("router", "简单路由"),
    ("route-parser", "路由解析"),
    ("methods", "HTTP 方法"),
    ("parseurl", "URL 解析"),
    ("url-parse", "URL 解析"),
    ("query-string", "查询字符串"),
    ("strict-uri-encode", "URI 编码"),
    ("encodeurl", "URL 编码"),
    ("decode-uri-component", "URI 解码"),
    ("raw-body", "请求体读取"),
    ("bytes", "字节处理"),
    ("content-type", "内容类型"),
    ("content-disposition", "内容处置"),
    ("type-is", "类型判断"),
    ("accepts", "内容协商"),
    ("negotiator", "内容协商"),
    ("fresh", "缓存新鲜度"),
    ("etag", "ETag 生成"),
    ("vary", "Vary 头"),
    ("on-finished", "响应结束回调"),
    ("on-headers", "响应头回调"),
    ("depd", "依赖弃用提示"),
    ("destroy", "流销毁"),
    ("encodeurl ", "URL 编码"),
    ("send", "静态文件发送"),
    ("serve-static", "静态文件服务"),
    ("serve-favicon", "Favicon"),
    ("finalhandler", "最终处理器"),
    ("merge-descriptors", "描述符合并"),
    ("utils-merge", "对象合并"),
    ("escape-html", "HTML 转义"),
    # ---- 前端框架 / 生态 ----
    ("react", "UI 框架"),
    ("react-dom", "React DOM 渲染器"),
    ("react-is", "React 元素判断"),
    ("react-transition-group", "过渡动画"),
    ("react-error-boundary", "错误边界"),
    ("prop-types", "React props 校验"),
    ("classnames", "className 拼接"),
    ("clsx", "className 拼接"),
    ("react-redux", "Redux React 绑定"),
    ("redux", "状态管理"),
    ("@reduxjs/toolkit", "Redux 官方工具集"),
    ("redux-thunk", "Redux 中间件"),
    ("reselect", "状态选择器"),
    ("react-router-dom", "前端路由"),
    ("react-router", "前端路由核心"),
    ("history", "会话历史"),
    ("react-hook-form", "表单状态管理"),
    ("formik", "表单管理"),
    ("yup", "对象 schema 校验"),
    ("zod", "运行时 schema 校验"),
    ("@tanstack/react-query", "服务端数据同步"),
    ("swr", "数据请求"),
    ("use-sync-external-store", "外部存储订阅"),
    ("immer", "不可变数据"),
    ("immutable", "不可变数据结构"),
    ("react-fast-compare", "深比较"),
    ("shallowequal", "浅比较"),
    ("hoist-non-react-statics", "静态属性提升"),
    ("react-helmet", "文档头管理"),
    ("react-intersection-observer", "交叉观察"),
    ("react-use", "React Hooks 集"),
    ("ahooks", "React Hooks 集"),
    ("vue", "渐进式前端框架"),
    ("@vue/runtime-core", "Vue 运行时"),
    ("@vue/runtime-dom", "Vue DOM 运行时"),
    ("@vue/reactivity", "Vue 响应式"),
    ("@vue/shared", "Vue 共享工具"),
    ("vue-router", "Vue 路由"),
    ("pinia", "Vue 状态管理"),
    ("vuex", "Vue 状态管理（旧）"),
    ("@vueuse/core", "Vue 组合式工具"),
    ("element-plus", "Vue 3 组件库"),
    ("antd", "React 中后台组件库"),
    ("@ant-design/icons", "Ant Design 图标"),
    ("@ant-design/cssinjs", "Ant Design 样式注入"),
    ("svelte", "Svelte 框架"),
    ("preact", "轻量 React 替代"),
    ("solid-js", "Solid 框架"),
    ("jquery", "DOM 操作库"),
    ("zepto", "轻量 jQuery"),
    # ---- 构建工具 ----
    ("typescript", "TypeScript 编译器"),
    ("esbuild", "高速打包器"),
    ("vite", "前端构建工具"),
    ("@vitejs/plugin-react", "Vite React 插件"),
    ("@vitejs/plugin-vue", "Vite Vue 插件"),
    ("rollup", "模块打包器"),
    ("webpack", "打包器"),
    ("webpack-cli", "Webpack 命令行"),
    ("webpack-dev-server", "开发服务器"),
    ("webpack-merge", "配置合并"),
    ("babel-loader", "Babel Webpack Loader"),
    ("css-loader", "CSS Webpack Loader"),
    ("style-loader", "样式注入 Loader"),
    ("less-loader", "Less Loader"),
    ("sass-loader", "Sass Loader"),
    ("postcss-loader", "PostCSS Loader"),
    ("file-loader", "文件 Loader"),
    ("url-loader", "URL Loader"),
    ("html-webpack-plugin", "HTML 插件"),
    ("mini-css-extract-plugin", "CSS 提取"),
    ("copy-webpack-plugin", "文件拷贝"),
    ("terser-webpack-plugin", "JS 压缩"),
    ("clean-webpack-plugin", "目录清理"),
    ("@babel/core", "Babel 编译器核心"),
    ("@babel/preset-env", "Babel 环境预设"),
    ("@babel/preset-react", "Babel React 预设"),
    ("@babel/preset-typescript", "Babel TS 预设"),
    ("@babel/plugin-transform-runtime", "Babel 运行时转换"),
    ("@babel/runtime", "Babel 运行时 helper"),
    ("@babel/parser", "Babel 解析器"),
    ("@babel/traverse", "Babel 遍历"),
    ("@babel/generator", "Babel 代码生成"),
    ("@babel/types", "Babel 类型"),
    ("@babel/template", "Babel 模板"),
    ("@babel/code-frame", "错误代码帧"),
    ("@babel/helper-module-imports", "模块导入助手"),
    ("babel-plugin-macros", "宏插件"),
    ("postcss", "CSS 后处理器"),
    ("autoprefixer", "CSS 前缀补全"),
    ("tailwindcss", "原子化 CSS 框架"),
    ("sass", "Sass 编译器"),
    ("less", "Less 编译器"),
    ("stylus", "Stylus 编译器"),
    ("csso", "CSS 压缩"),
    ("cssnano", "CSS 优化"),
    ("lightningcss", "CSS 处理"),
    ("acorn", "JS 解析器"),
    ("espree", "ESLint 解析器"),
    ("escodegen", "代码生成"),
    ("esrecurse", "AST 遍历"),
    ("estraverse", "AST 遍历"),
    ("source-map", "Source Map"),
    ("magic-string", "字符串操作"),
    ("@jridgewell/sourcemap-codec", "Source Map 编解码"),
    ("@jridgewell/trace-mapping", "Source Map 映射"),
    # ---- Lint / 测试 ----
    ("eslint", "静态代码检查"),
    ("prettier", "代码格式化"),
    ("@typescript-eslint/parser", "TypeScript AST 解析"),
    ("@typescript-eslint/eslint-plugin", "TS 规则插件"),
    ("eslint-plugin-react", "React 规则"),
    ("eslint-plugin-vue", "Vue 规则"),
    ("eslint-plugin-import", "import 规则"),
    ("eslint-config-prettier", "Prettier 兼容配置"),
    ("stylelint", "样式检查"),
    ("jest", "测试框架"),
    ("ts-jest", "Jest TS 支持"),
    ("babel-jest", "Jest Babel 支持"),
    ("jest-environment-jsdom", "Jest jsdom 环境"),
    ("mocha", "测试框架"),
    ("chai", "断言库"),
    ("sinon", "Mock / Stub 工具"),
    ("@testing-library/react", "React 组件测试"),
    ("@testing-library/jest-dom", "DOM 断言"),
    ("@testing-library/user-event", "用户事件模拟"),
    ("cypress", "端到端测试"),
    ("playwright", "浏览器自动化"),
    ("puppeteer", "无头浏览器"),
    ("vitest", "Vite 测试框架"),
    ("jsdom", "DOM 实现"),
    ("happy-dom", "DOM 实现"),
    ("istanbul-lib-coverage", "覆盖率"),
    ("nyc", "覆盖率"),
    # ---- 类型定义 ----
    ("@types/node", "Node.js 类型定义"),
    ("@types/react", "React 类型定义"),
    ("@types/react-dom", "React DOM 类型定义"),
    ("@types/express", "Express 类型定义"),
    ("@types/lodash", "Lodash 类型定义"),
    ("@types/jest", "Jest 类型定义"),
    ("@types/mocha", "Mocha 类型定义"),
    ("@types/chai", "Chai 类型定义"),
    ("@types/semver", "semver 类型定义"),
    ("@types/qs", "qs 类型定义"),
    ("@types/cookie", "cookie 类型定义"),
    ("@types/cors", "cors 类型定义"),
    ("@types/uuid", "uuid 类型定义"),
    ("@types/debug", "debug 类型定义"),
    ("@types/ms", "ms 类型定义"),
    # ---- 数据 / 客户端 ----
    ("pg", "PostgreSQL 驱动"),
    ("pg-promise", "PostgreSQL 客户端"),
    ("mysql2", "MySQL 驱动"),
    ("sqlite3", "SQLite 驱动"),
    ("better-sqlite3", "SQLite（同步）"),
    ("mongoose", "MongoDB ODM"),
    ("mongodb", "MongoDB 驱动"),
    ("redis", "Redis 官方客户端"),
    ("ioredis", "Redis 客户端"),
    ("sequelize", "关系型 ORM"),
    ("knex", "SQL 查询构建器"),
    ("typeorm", "TypeScript ORM"),
    ("prisma", "Prisma CLI"),
    ("@prisma/client", "Prisma 客户端"),
    ("dataloader", "批量加载"),
    ("graphql", "GraphQL 实现"),
    ("@graphql-tools/schema", "GraphQL 工具"),
    ("apollo-server-express", "Apollo 服务端"),
    ("graphql-yoga", "GraphQL 服务端"),
    ("socket.io", "实时通信服务端"),
    ("socket.io-client", "实时通信客户端"),
    ("ws", "WebSocket 实现"),
    ("engine.io", "实时通信引擎"),
    ("mqtt", "MQTT 客户端"),
    ("amqplib", "RabbitMQ 客户端"),
    ("kafkajs", "Kafka 客户端"),
    ("nodemailer", "邮件发送"),
    ("@aws-sdk/client-s3", "AWS S3 客户端"),
    ("@aws-sdk/client-dynamodb", "AWS DynamoDB 客户端"),
    ("firebase", "Firebase SDK"),
    ("@supabase/supabase-js", "Supabase 客户端"),
    ("openai", "OpenAI SDK"),
    ("@anthropic-ai/sdk", "Anthropic SDK"),
    # ---- 日期 / 可视化 / 其他 ----
    ("moment", "日期处理（旧版、已停止新特性）"),
    ("dayjs", "轻量日期库"),
    ("date-fns", "日期工具集"),
    ("luxon", "日期时间库"),
    ("echarts", "可视化图表库"),
    ("chart.js", "轻量图表库"),
    ("d3", "数据可视化"),
    ("three", "3D 引擎"),
    ("pixi.js", "2D 渲染引擎"),
    ("gsap", "动画库"),
    ("animejs", "动画库"),
    ("highlight.js", "代码语法高亮"),
    ("marked", "Markdown 解析"),
    ("markdown-it", "Markdown 解析"),
    ("dompurify", "XSS 防护"),
    ("xss", "XSS 过滤"),
    ("jsonschema", "JSON Schema 校验"),
    ("ajv", "JSON Schema 校验"),
    ("fast-json-patch", "JSON Patch"),
    ("json5", "JSON5 解析"),
    ("js-yaml", "YAML 解析"),
    ("toml", "TOML 解析"),
    ("@iarna/toml", "TOML 解析"),
    ("csv-parse", "CSV 解析"),
    ("papaparse", "CSV 解析"),
    ("xlsx", "Excel 处理"),
    ("exceljs", "Excel 处理"),
    ("pdfkit", "PDF 生成"),
    ("jspdf", "PDF 生成"),
    ("file-saver", "文件保存"),
    ("jszip", "ZIP 处理"),
    ("pako", "zlib 压缩"),
    ("lz-string", "LZ 压缩"),
    ("crypto-js", "前端加密库"),
    ("jsonwebtoken", "JWT 签发校验"),
    ("bcryptjs", "密码哈希"),
    ("bcrypt", "密码哈希"),
    ("argon2", "密码哈希"),
    ("passport", "认证中间件"),
    ("passport-local", "本地认证策略"),
    ("express-session", "会话管理"),
    ("connect-redis", "Redis 会话存储"),
    ("json-server", "Mock 服务"),
    ("nodemon", "开发热重载"),
    ("concurrently", "并发执行脚本"),
    ("npm-run-all", "脚本编排"),
]

# (项目名, 说明) —— top-pypi-packages 不可用时的保底清单
PYPI_SEEDS = [
    ("requests", "HTTP 客户端"),
    ("urllib3", "HTTP 底层库"),
    ("certifi", "CA 根证书"),
    ("charset-normalizer", "字符编码检测"),
    ("idna", "域名编码"),
    ("boto3", "AWS SDK"),
    ("botocore", "AWS 底层库"),
    ("s3transfer", "S3 传输"),
    ("jmespath", "JMESPath 查询"),
    ("python-dateutil", "日期解析"),
    ("pytz", "时区数据库"),
    ("tzdata", "时区数据"),
    ("six", "Python 2/3 兼容"),
    ("setuptools", "打包工具"),
    ("wheel", "打包格式"),
    ("pip", "包管理器"),
    ("packaging", "版本与标记解析"),
    ("importlib-metadata", "元数据访问"),
    ("zipp", "ZIP 路径"),
    ("typing-extensions", "类型扩展"),
    ("numpy", "科学计算"),
    ("scipy", "科学计算"),
    ("pandas", "数据分析"),
    ("matplotlib", "绘图"),
    ("seaborn", "统计绘图"),
    ("scikit-learn", "机器学习"),
    ("joblib", "并行计算"),
    ("threadpoolctl", "线程池控制"),
    ("tqdm", "进度条"),
    ("torch", "深度学习"),
    ("tensorflow", "深度学习"),
    ("keras", "深度学习"),
    ("jax", "自动微分"),
    ("transformers", "预训练模型"),
    ("tokenizers", "分词器"),
    ("huggingface-hub", "模型仓库"),
    ("datasets", "数据集"),
    ("accelerate", "分布式训练"),
    ("safetensors", "安全张量格式"),
    ("sentence-transformers", "句向量"),
    ("faiss-cpu", "向量检索"),
    ("chromadb", "向量数据库"),
    ("openai", "OpenAI SDK"),
    ("anthropic", "Anthropic SDK"),
    ("tiktoken", "BPE 分词"),
    ("langchain", "LLM 应用框架"),
    ("langchain-core", "LLM 核心"),
    ("llama-index", "RAG 框架"),
    ("protobuf", "Protobuf 运行时"),
    ("grpcio", "gRPC 运行时"),
    ("grpcio-tools", "gRPC 代码生成"),
    ("pydantic", "数据校验"),
    ("pydantic-core", "Pydantic 核心"),
    ("fastapi", "Web 框架"),
    ("starlette", "ASGI 框架"),
    ("uvicorn", "ASGI 服务器"),
    ("gunicorn", "WSGI 服务器"),
    ("django", "全栈 Web 框架"),
    ("djangorestframework", "DRF"),
    ("sqlparse", "SQL 解析"),
    ("asgiref", "ASGI 参考"),
    ("flask", "轻量 Web 框架"),
    ("werkzeug", "WSGI 工具库"),
    ("jinja2", "模板引擎"),
    ("itsdangerous", "签名工具"),
    ("markupsafe", "安全字符串"),
    ("click", "CLI 框架"),
    ("blinker", "信号"),
    ("sqlalchemy", "ORM"),
    ("alembic", "数据库迁移"),
    ("greenlet", "协程"),
    ("psycopg2-binary", "PostgreSQL 驱动"),
    ("psycopg", "PostgreSQL 驱动（新版）"),
    ("pymysql", "MySQL 驱动"),
    ("mysqlclient", "MySQL 驱动"),
    ("redis", "Redis 客户端"),
    ("celery", "分布式任务队列"),
    ("kombu", "消息库"),
    ("amqp", "RabbitMQ 客户端"),
    ("billiard", "多进程池"),
    ("vine", "Promise 实现"),
    ("pymongo", "MongoDB 驱动"),
    ("motor", "MongoDB 异步驱动"),
    ("elasticsearch", "ES 客户端"),
    ("clickhouse-driver", "ClickHouse 驱动"),
    ("pyodbc", "ODBC 驱动"),
    ("orjson", "快速 JSON"),
    ("ujson", "快速 JSON"),
    ("msgpack", "MessagePack"),
    ("pyyaml", "YAML 解析"),
    ("toml", "TOML 解析"),
    ("tomli", "TOML 解析"),
    ("python-dotenv", "环境变量"),
    ("dynaconf", "配置管理"),
    ("omegaconf", "配置管理"),
    ("hydra-core", "配置框架"),
    ("virtualenv", "虚拟环境"),
    ("build", "构建前端"),
    ("twine", "发布工具"),
    ("poetry-core", "Poetry 核心"),
    ("attrs", "属性类"),
    ("cattrs", "结构化转换"),
    ("marshmallow", "序列化校验"),
    ("jsonschema", "JSON Schema 校验"),
    ("pyjwt", "JWT 实现"),
    ("passlib", "密码哈希框架"),
    ("bcrypt", "密码哈希"),
    ("cryptography", "加密库"),
    ("pyopenssl", "OpenSSL 封装"),
    ("arrow", "日期时间"),
    ("pendulum", "日期时间"),
    ("humanize", "人性化格式"),
    ("rich", "富文本输出"),
    ("colorama", "终端颜色"),
    ("loguru", "日志库"),
    ("structlog", "结构化日志"),
    ("python-json-logger", "JSON 日志"),
    ("sentry-sdk", "错误监控"),
    ("prometheus-client", "Prometheus 客户端"),
    ("opentelemetry-api", "OpenTelemetry API"),
    ("opentelemetry-sdk", "OpenTelemetry SDK"),
    ("newrelic", "APM 监控"),
    ("datadog", "监控 Agent"),
    ("tenacity", "重试库"),
    ("backoff", "退避重试"),
    ("cachetools", "缓存工具"),
    ("diskcache", "磁盘缓存"),
    ("cloudpickle", "云序列化"),
    ("dill", "扩展序列化"),
    ("lxml", "XML/HTML 解析"),
    ("beautifulsoup4", "HTML 解析"),
    ("soupsieve", "CSS 选择器"),
    ("html5lib", "HTML 解析"),
    ("bleach", "HTML 清洗"),
    ("markdown", "Markdown 渲染"),
    ("markdown-it-py", "Markdown 解析"),
    ("docutils", "文档工具"),
    ("pygments", "语法高亮"),
    ("sphinx", "文档生成"),
    ("nbformat", "Notebook 格式"),
    ("jupyter-core", "Jupyter 核心"),
    ("ipython", "交互式 Shell"),
    ("ipykernel", "Jupyter 内核"),
    ("notebook", "Jupyter Notebook"),
    ("jupyterlab", "JupyterLab"),
    ("traitlets", "配置系统"),
    ("prompt-toolkit", "交互式终端"),
    ("wcwidth", "宽字符宽度"),
    ("parso", "解析器"),
    ("pexpect", "进程控制"),
    ("pyzmq", "ZeroMQ"),
    ("tornado", "异步网络"),
    ("websockets", "WebSocket"),
    ("websocket-client", "WebSocket 客户端"),
    ("aiohttp", "异步 HTTP"),
    ("httpx", "现代 HTTP 客户端"),
    ("httpcore", "HTTP 核心"),
    ("h11", "HTTP/1.1 实现"),
    ("anyio", "异步兼容层"),
    ("sniffio", "异步库检测"),
    ("aiofiles", "异步文件"),
    ("watchfiles", "文件监听"),
    ("uvloop", "高性能事件循环"),
    ("httptools", "HTTP 解析"),
    ("uv", "快速工具链"),
    ("ruff", "Lint 与格式化"),
    ("black", "代码格式化"),
    ("isort", "import 排序"),
    ("flake8", "代码检查"),
    ("pylint", "代码检查"),
    ("mypy", "类型检查"),
    ("pytest", "测试框架"),
    ("pytest-cov", "覆盖率插件"),
    ("coverage", "覆盖率"),
    ("tox", "测试环境管理"),
    ("hypothesis", "属性测试"),
    ("faker", "假数据生成"),
    ("factory-boy", "测试夹具"),
    ("responses", "请求 Mock"),
    ("requests-mock", "请求 Mock"),
    ("vcrpy", "录制回放"),
    ("locust", "压测"),
    ("selenium", "浏览器自动化"),
    ("playwright", "浏览器自动化"),
    ("paramiko", "SSH 客户端"),
    ("fabric", "远程执行"),
    ("ansible", "自动化运维"),
    ("docker", "Docker 客户端"),
    ("kubernetes", "K8s 客户端"),
    ("pyinstaller", "打包可执行"),
    ("google-cloud-storage", "GCS 客户端"),
    ("google-api-python-client", "Google API 客户端"),
    ("google-auth", "Google 认证"),
    ("google-auth-oauthlib", "OAuth 流程"),
    ("oauthlib", "OAuth 实现"),
    ("requests-oauthlib", "OAuth 集成"),
    ("pygithub", "GitHub API"),
    ("gitpython", "Git 操作"),
    ("watchdog", "文件监控"),
    ("psutil", "进程与系统"),
    ("ray", "分布式计算"),
    ("dask", "并行计算"),
    ("polars", "DataFrame"),
    ("pyarrow", "Arrow 格式"),
    ("duckdb", "分析数据库"),
    ("tabulate", "表格输出"),
    ("texttable", "表格输出"),
    ("pathspec", "路径匹配"),
    ("platformdirs", "平台目录"),
    ("appdirs", "应用目录"),
    ("fsspec", "文件系统抽象"),
    ("smart-open", "流式打开"),
    ("chardet", "编码检测"),
    ("filetype", "文件类型"),
    ("python-magic", "文件类型"),
    ("rapidfuzz", "模糊匹配"),
    ("fuzzywuzzy", "模糊匹配"),
    ("unidecode", "Unicode 转写"),
    ("python-slugify", "Slug 生成"),
    ("phonenumbers", "电话号码解析"),
    ("email-validator", "邮箱校验"),
    ("dnspython", "DNS 工具"),
    ("tldextract", "域名解析"),
    ("geoip2", "IP 地理"),
    ("maxminddb", "IP 数据库"),
    ("shapely", "几何计算"),
    ("pyproj", "地图投影"),
    ("folium", "地图可视化"),
    ("plotly", "交互图表"),
    ("bokeh", "交互图表"),
    ("altair", "声明式图表"),
    ("great-expectations", "数据质量"),
    ("mlflow", "实验管理"),
    ("wandb", "实验管理"),
    ("tensorboard", "可视化"),
    ("xgboost", "梯度提升"),
    ("lightgbm", "梯度提升"),
    ("catboost", "梯度提升"),
    ("statsmodels", "统计模型"),
    ("sympy", "符号计算"),
    ("networkx", "图算法"),
    ("numba", "JIT 编译"),
    ("llvmlite", "LLVM 绑定"),
    ("cython", "C 扩展"),
    ("cffi", "C 外部函数"),
    ("pycparser", "C 解析器"),
]

# (模块路径, 说明) —— Go 生态核心模块（排在 Star 榜单之前）
GO_SEEDS = [
    # ---- golang.org/x ----
    ("golang.org/x/net", "网络库"),
    ("golang.org/x/sync", "并发原语"),
    ("golang.org/x/sys", "系统调用"),
    ("golang.org/x/text", "文本处理"),
    ("golang.org/x/crypto", "加密扩展"),
    ("golang.org/x/time", "时间与限流"),
    ("golang.org/x/oauth2", "OAuth2"),
    ("golang.org/x/image", "图像处理"),
    ("golang.org/x/mod", "模块工具"),
    ("golang.org/x/tools", "工具链"),
    ("golang.org/x/term", "终端"),
    ("golang.org/x/exp", "实验特性"),
    ("golang.org/x/mobile", "移动端"),
    ("golang.org/x/blog", "官方博客代码"),
    ("golang.org/x/review", "代码评审工具"),
    ("golang.org/x/vuln", "漏洞数据库"),
    ("golang.org/x/pkgsite", "包文档站"),
    ("golang.org/x/website", "官网代码"),
    # ---- google.golang.org ----
    ("google.golang.org/grpc", "gRPC 框架"),
    ("google.golang.org/protobuf", "Protobuf 新版 API"),
    ("google.golang.org/genproto", "生成代码"),
    ("google.golang.org/api", "Google API 客户端"),
    ("google.golang.org/appengine", "App Engine API"),
    ("google.golang.org/cloud", "云客户端（旧）"),
    ("google.golang.org/grpc/cmd/protoc-gen-go-grpc", "gRPC 代码生成插件"),
    # ---- k8s.io ----
    ("k8s.io/api", "K8s API 类型"),
    ("k8s.io/apimachinery", "K8s 基础类型"),
    ("k8s.io/client-go", "K8s 客户端"),
    ("k8s.io/klog/v2", "K8s 日志"),
    ("k8s.io/kube-openapi", "OpenAPI 工具"),
    ("k8s.io/utils", "K8s 工具"),
    ("k8s.io/metrics", "指标 API"),
    ("k8s.io/cli-runtime", "CLI 运行时"),
    ("k8s.io/kubectl", "kubectl 包"),
    ("k8s.io/kubernetes", "K8s 源码模块"),
    ("k8s.io/component-base", "组件基础"),
    ("k8s.io/apiextensions-apiserver", "CRD 服务"),
    ("k8s.io/controller-runtime", "控制器框架"),
    ("k8s.io/code-generator", "代码生成器"),
    ("k8s.io/system-validators", "系统校验"),
    # ---- gopkg.in ----
    ("gopkg.in/yaml.v2", "YAML 解析"),
    ("gopkg.in/yaml.v3", "YAML 解析"),
    ("gopkg.in/ini.v1", "INI 解析"),
    ("gopkg.in/natefinch/lumberjack.v2", "日志切割"),
    ("gopkg.in/go-playground/validator.v9", "参数校验"),
    # ---- Web 框架 ----
    ("github.com/gin-gonic/gin", "Web 框架"),
    ("github.com/labstack/echo", "Web 框架"),
    ("github.com/gofiber/fiber", "高性能 Web 框架"),
    ("github.com/beego/beego", "Web 框架"),
    ("github.com/gorilla/mux", "路由器"),
    ("github.com/go-chi/chi", "轻量路由"),
    ("github.com/julienschmidt/httprouter", "高性能路由"),
    ("github.com/valyala/fasthttp", "高性能 HTTP"),
    ("github.com/urfave/negroni", "中间件"),
    ("github.com/justinas/alice", "中间件链"),
    ("github.com/rs/cors", "CORS 中间件"),
    ("github.com/unrolled/secure", "安全中间件"),
    ("github.com/gorilla/handlers", "中间件集"),
    # ---- 日志 ----
    ("github.com/sirupsen/logrus", "结构化日志"),
    ("go.uber.org/zap", "高性能日志"),
    ("github.com/rs/zerolog", "零分配日志"),
    ("github.com/k0kubun/pp", "美化打印"),
    ("github.com/davecgh/go-spew", "深度打印"),
    ("github.com/fatih/color", "终端颜色"),
    # ---- CLI / 配置 ----
    ("github.com/spf13/cobra", "CLI 框架"),
    ("github.com/spf13/pflag", "POSIX 参数"),
    ("github.com/urfave/cli", "CLI 框架"),
    ("github.com/jessevdk/go-flags", "CLI 框架"),
    ("github.com/spf13/viper", "配置管理"),
    ("github.com/knadh/koanf", "配置管理"),
    ("github.com/caarlos0/env", "环境变量配置"),
    ("github.com/joho/godotenv", "环境变量文件"),
    ("github.com/srikrsna/envconfig", "环境变量结构体"),
    ("github.com/mitchellh/go-homedir", "用户目录"),
    ("github.com/mitchellh/mapstructure", "结构体映射"),
    ("github.com/mitchellh/hashstructure", "结构体哈希"),
    ("github.com/fatih/structs", "结构体工具"),
    ("github.com/jinzhu/copier", "结构体拷贝"),
    ("github.com/magiconair/properties", "Properties 解析"),
    # ---- 测试 ----
    ("github.com/stretchr/testify", "断言与 Mock"),
    ("github.com/smartystreets/goconvey", "BDD 测试"),
    ("github.com/onsi/ginkgo", "BDD 测试"),
    ("github.com/onsi/gomega", "断言库"),
    ("github.com/gavv/httpexpect", "HTTP 测试"),
    ("github.com/jarcoal/httpmock", "HTTP Mock"),
    ("github.com/h2non/gock", "HTTP Mock"),
    ("github.com/dnaeon/go-vcr", "录制回放"),
    ("github.com/stretchr/objx", "测试辅助"),
    ("go.uber.org/mock", "Mock 生成"),
    ("github.com/golang/mock", "Mock 生成（旧）"),
    ("github.com/matryer/moq", "Mock 生成"),
    # ---- 数据库 ----
    ("github.com/go-gorm/gorm", "ORM"),
    ("github.com/go-xorm/xorm", "ORM"),
    ("entgo.io/ent", "实体框架"),
    ("github.com/jmoiron/sqlx", "SQL 扩展"),
    ("github.com/lib/pq", "PostgreSQL 驱动"),
    ("github.com/jackc/pgx", "PostgreSQL 驱动"),
    ("github.com/go-sql-driver/mysql", "MySQL 驱动"),
    ("github.com/mattn/go-sqlite3", "SQLite 驱动"),
    ("github.com/redis/go-redis/v9", "Redis 客户端"),
    ("github.com/gomodule/redigo", "Redis 客户端"),
    ("github.com/alicebob/miniredis", "Redis 测试"),
    ("github.com/go-redis/redismock", "Redis Mock"),
    ("github.com/go-redsync/redsync/v4", "分布式锁"),
    ("github.com/bsm/redislock", "Redis 分布式锁"),
    ("go.mongodb.org/mongo-driver", "MongoDB 驱动"),
    ("github.com/elastic/go-elasticsearch", "ES 客户端"),
    ("github.com/olivere/elastic", "ES 客户端（旧）"),
    ("github.com/ClickHouse/clickhouse-go", "ClickHouse 驱动"),
    ("github.com/prestodb/presto-go-client", "Presto 客户端"),
    ("github.com/aws/aws-sdk-go", "AWS SDK v1"),
    ("github.com/aws/aws-sdk-go-v2", "AWS SDK v2"),
    ("github.com/aws/aws-sdk-go-v2/service/s3", "AWS S3 v2"),
    ("github.com/Azure/azure-sdk-for-go", "Azure SDK"),
    ("github.com/aliyun/aliyun-oss-go-sdk", "阿里云 OSS"),
    ("github.com/tencentyun/cos-go-sdk-v5", "腾讯云 COS"),
    ("github.com/qiniu/go-sdk", "七牛云 SDK"),
    ("github.com/minio/minio-go/v7", "MinIO 客户端"),
    # ---- 消息队列 ----
    ("github.com/IBM/sarama", "Kafka 客户端"),
    ("github.com/segmentio/kafka-go", "Kafka 客户端"),
    ("github.com/Shopify/sarama", "Kafka 客户端（旧）"),
    ("github.com/nats-io/nats.go", "NATS 客户端"),
    ("github.com/nats-io/stan.go", "NATS Streaming"),
    ("github.com/rabbitmq/amqp091-go", "RabbitMQ 客户端"),
    ("github.com/apache/pulsar-client-go", "Pulsar 客户端"),
    ("github.com/nsqio/go-nsq", "NSQ 客户端"),
    ("github.com/streadway/amqp", "RabbitMQ 客户端（旧）"),
    # ---- 序列化 / 编解码 ----
    ("github.com/gogo/protobuf", "Protobuf 分支"),
    ("github.com/golang/protobuf", "Protobuf（旧 API）"),
    ("github.com/json-iterator/go", "高性能 JSON"),
    ("github.com/mailru/easyjson", "JSON 代码生成"),
    ("github.com/tidwall/gjson", "JSON 查询"),
    ("github.com/tidwall/sjson", "JSON 修改"),
    ("github.com/tidwall/pretty", "JSON 美化"),
    ("github.com/buger/jsonparser", "JSON 解析"),
    ("github.com/bytedance/sonic", "高性能 JSON"),
    ("github.com/valyala/fastjson", "快速 JSON"),
    ("github.com/vmihailenco/msgpack", "MessagePack"),
    ("github.com/ugorji/go", "codec"),
    ("github.com/pquerna/ffjson", "JSON 生成（旧）"),
    ("github.com/frankban/quicktest", "测试辅助"),
    ("github.com/google/go-cmp", "深度比较"),
    # ---- 校验 / 工具 ----
    ("github.com/go-playground/validator", "参数校验"),
    ("github.com/asaskevich/govalidator", "参数校验"),
    ("github.com/go-ozzo/ozzo-validation", "参数校验"),
    ("github.com/infoblxopen/protoc-gen-gorm", "gRPC ORM 生成"),
    ("github.com/samber/lo", "函数式工具"),
    ("github.com/thoas/go-funk", "函数式工具"),
    ("github.com/jinzhu/inflection", "单复数转换"),
    ("github.com/spf13/cast", "类型转换"),
    ("github.com/paulbellamy/ratecounter", "计数器"),
    ("github.com/panjf2000/ants", "协程池"),
    ("github.com/Jeffail/tunny", "协程池"),
    ("github.com/reactivex/rxgo", "RxGo"),
    ("github.com/robfig/cron", "定时任务"),
    ("github.com/gorhill/cronexpr", "Cron 表达式"),
    ("github.com/go-co-op/gocron", "定时任务"),
    ("github.com/adhocore/gronx", "Cron 工具"),
    ("github.com/gorilla/websocket", "WebSocket"),
    ("github.com/gobwas/ws", "WebSocket"),
    ("github.com/lesismal/arpc", "RPC 框架"),
    ("github.com/google/uuid", "UUID"),
    ("github.com/gofrs/uuid", "UUID"),
    ("github.com/rs/xid", "短 ID"),
    ("github.com/bwmarrin/snowflake", "雪花 ID"),
    ("github.com/sony/sonyflake", "分布式 ID"),
    ("github.com/teris-io/shortid", "短 ID"),
    ("github.com/lithammer/shortuuid", "短 UUID"),
    ("github.com/oklog/ulid", "ULID"),
    # ---- HTTP 客户端 / 服务 ----
    ("github.com/go-resty/resty", "HTTP 客户端"),
    ("github.com/parnurzeal/gorequest", "HTTP 客户端"),
    ("github.com/hashicorp/go-retryablehttp", "重试 HTTP"),
    ("github.com/imroc/req", "HTTP 客户端"),
    ("github.com/gojek/heimdall", "HTTP 客户端"),
    ("github.com/sethgrid/pester", "重试 HTTP"),
    ("github.com/avast/retry-go", "重试"),
    ("github.com/cenkalti/backoff", "退避重试"),
    ("github.com/hashicorp/go-multierror", "错误聚合"),
    ("github.com/pkg/errors", "错误处理"),
    ("github.com/rotisserie/eris", "错误处理"),
    # ---- 鉴权 ----
    ("github.com/golang-jwt/jwt", "JWT 实现"),
    ("github.com/dgrijalva/jwt-go", "JWT 实现（旧）"),
    ("github.com/casbin/casbin", "访问控制"),
    ("github.com/casbin/casbin/v2", "访问控制 v2"),
    ("github.com/coreos/go-oidc", "OIDC 客户端"),
    ("github.com/oauth2-proxy/oauth2-proxy", "OAuth 代理"),
    ("github.com/ory/hydra", "OAuth 服务端"),
    ("github.com/justinas/nosurf", "CSRF 防护"),
    # ---- gRPC / 协议 ----
    ("github.com/grpc-ecosystem/grpc-gateway", "REST 网关"),
    ("github.com/envoyproxy/protoc-gen-validate", "参数校验生成"),
    ("github.com/mwitkow/go-proto-validators", "校验生成"),
    ("github.com/grpc-ecosystem/go-grpc-middleware", "gRPC 中间件"),
    ("github.com/grpc-ecosystem/go-grpc-prometheus", "gRPC 监控"),
    ("buf.build/buf", "Protobuf 工具链"),
    ("github.com/fullstorydev/grpcurl", "gRPC CLI"),
    ("github.com/jhump/protoreflect", "gRPC 反射"),
    # ---- 可观测性 ----
    ("github.com/prometheus/client_golang", "Prometheus 客户端"),
    ("github.com/prometheus/client_model", "Prometheus 数据模型"),
    ("github.com/prometheus/common", "Prometheus 公共库"),
    ("go.opentelemetry.io/otel", "OpenTelemetry"),
    ("go.opentelemetry.io/otel/sdk", "OTel SDK"),
    ("go.opentelemetry.io/otel/trace", "OTel 链路"),
    ("go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp", "HTTP 埋点"),
    ("github.com/DataDog/datadog-go", "Datadog 客户端"),
    ("github.com/newrelic/go-agent", "New Relic Agent"),
    ("github.com/getsentry/sentry-go", "Sentry 客户端"),
    ("github.com/opentracing/opentracing-go", "链路追踪"),
    ("github.com/uber/jaeger-client-go", "Jaeger 客户端"),
    ("github.com/hashicorp/go-metrics", "指标库"),
    # ---- 配置中心 / 注册中心 ----
    ("github.com/hashicorp/consul", "Consul 客户端"),
    ("github.com/hashicorp/consul/api", "Consul API"),
    ("github.com/hashicorp/vault/api", "Vault 客户端"),
    ("github.com/coreos/etcd/client/v3", "etcd 客户端"),
    ("github.com/smallnest/rpcx", "RPC 框架"),
    ("github.com/tal-tech/go-zero", "go-zero 框架"),
    ("github.com/zeromicro/go-zero", "go-zero 框架（新版）"),
    ("github.com/apache/dubbo-go", "Dubbo Go"),
    ("github.com/cloudwego/kitex", "Kitex RPC"),
    ("github.com/cloudwego/hertz", "Hertz HTTP 框架"),
    ("github.com/go-kratos/kratos", "Kratos 微服务"),
    ("github.com/go-kit/kit", "Go kit 微服务"),
    ("github.com/micro/go-micro", "go-micro"),
    ("github.com/go-micro/go-micro", "go-micro v3"),
    # ---- 云原生 / 容器 ----
    ("github.com/docker/docker/client", "Docker 客户端"),
    ("github.com/docker/compose", "Compose"),
    ("github.com/containerd/containerd", "containerd"),
    ("github.com/opencontainers/image-spec", "OCI 镜像规范"),
    ("github.com/helm/helm", "Helm"),
    ("github.com/argoproj/argo-cd", "Argo CD"),
    ("github.com/fluxcd/flux2", "Flux CD"),
    ("github.com/knative/serving", "Knative Serving"),
    ("github.com/istio/istio", "Istio"),
    ("github.com/linkerd/linkerd2", "Linkerd"),
    ("github.com/prometheus/prometheus", "Prometheus"),
    ("github.com/grafana/loki", "Loki 日志"),
    ("github.com/jaegertracing/jaeger", "Jaeger 链路"),
    ("github.com/open-telemetry/opentelemetry-collector-contrib", "OTel Collector"),
    ("github.com/kubernetes-sigs/kind", "Kind 集群"),
    ("github.com/kubernetes-sigs/kustomize", "Kustomize"),
    ("github.com/kubernetes-sigs/yaml", "YAML 工具"),
    ("github.com/kubernetes-sigs/controller-runtime", "控制器运行时"),
    ("github.com/kubernetes-sigs/structured-merge-diff", "结构化合并"),
    ("github.com/kubernetes-sigs/secrets-store-csi-driver", "CSI 驱动"),
    # ---- GraphQL / API ----
    ("github.com/99designs/gqlgen", "GraphQL 服务端"),
    ("github.com/graph-gophers/graphql-go", "GraphQL 服务端"),
    ("github.com/graphql-go/graphql", "GraphQL 实现"),
    ("github.com/swaggo/swag", "API 文档生成"),
    ("github.com/swaggo/gin-swagger", "Gin Swagger"),
    ("github.com/swaggo/http-swagger", "HTTP Swagger"),
    ("github.com/go-swagger/go-swagger", "Swagger 工具"),
    # ---- 定时 / 工作流 ----
    ("github.com/robfig/cron/v3", "Cron 调度"),
    ("github.com/goquartz/quartz", "Quartz 移植"),
    ("github.com/hibiken/asynq", "异步任务队列"),
    ("github.com/looplab/fsm", "状态机"),
    ("github.com/qmuntal/stateless", "状态机"),
    # ---- 其他常用 ----
    ("github.com/fsnotify/fsnotify", "文件监听"),
    ("github.com/schollz/progressbar", "进度条"),
    ("github.com/cheggaaa/pb", "进度条"),
    ("github.com/briandowns/spinner", "加载动画"),
    ("github.com/buger/goterm", "终端控制"),
    ("github.com/gosuri/uilive", "终端刷新"),
    ("github.com/gosuri/uiprogress", "进度条"),
    ("github.com/olekukonko/tablewriter", "表格输出"),
    ("github.com/jedib0t/go-pretty", "美化输出"),
    ("github.com/olekukonko/ts", "时间序列"),
    ("github.com/nyaruka/phonenumbers", "电话号码解析"),
    ("github.com/bojand/ghz", "gRPC 压测"),
    ("github.com/hashicorp/go-version", "版本比较"),
    ("github.com/masterminds/semver", "语义化版本"),
    ("github.com/blang/semver", "语义化版本"),
    ("github.com/Masterminds/semver/v3", "语义化版本 v3"),
    ("github.com/google/go-github", "GitHub API"),
    ("github.com/google/go-querystring", "查询参数"),
    ("github.com/googleapis/gax-go", "Google API 扩展"),
    ("github.com/klauspost/compress", "压缩库"),
    ("github.com/klauspost/cpuid", "CPU 特性"),
    ("github.com/pierrec/lz4", "LZ4 压缩"),
    ("github.com/ulikunitz/xz", "XZ 压缩"),
    ("github.com/DataDog/zstd", "Zstd 压缩"),
    ("github.com/golang/snappy", "Snappy 压缩"),
    ("github.com/xi2/xz", "XZ 压缩（旧）"),
]

# 种子清单去重（同名构件/包只保留第一次出现，附带说明以先到者为准）
def _dedupe_seeds(seeds):
    seen = set()
    unique = []
    for entry in seeds:
        if entry[0] in seen:
            continue
        seen.add(entry[0])
        unique.append(entry)
    return unique


MAVEN_SEEDS = _dedupe_seeds(MAVEN_SEEDS)
NPM_SEEDS = _dedupe_seeds(NPM_SEEDS)
PYPI_SEEDS = _dedupe_seeds(PYPI_SEEDS)
GO_SEEDS = _dedupe_seeds(GO_SEEDS)

# npm 搜索关键词：覆盖名称片段与常见描述词，采样后按周下载量归并
NPM_KEYWORDS = [
    "react", "vue", "angular", "svelte", "solid", "preact", "jquery", "next", "nuxt",
    "webpack", "rollup", "vite", "esbuild", "parcel", "babel", "typescript", "swc",
    "eslint", "prettier", "stylelint", "jest", "mocha", "chai", "sinon", "cypress",
    "playwright", "puppeteer", "vitest", "storybook", "husky", "lint",
    "express", "koa", "fastify", "hapi", "nest", "restify", "socket", "websocket",
    "axios", "fetch", "http", "request", "got", "superagent", "retry", "proxy",
    "lodash", "underscore", "ramda", "immutable", "moment", "dayjs", "date-fns",
    "uuid", "nanoid", "hash", "crypto", "md5", "sha", "jwt", "oauth", "auth",
    "redux", "mobx", "zustand", "recoil", "router", "route", "history", "query",
    "form", "table", "chart", "graph", "echarts", "d3", "three", "canvas", "webgl",
    "icon", "svg", "css", "sass", "less", "stylus", "tailwind", "bootstrap",
    "antd", "element", "material", "chakra", "component", "widget", "layout",
    "color", "theme", "dark", "animation", "transition", "gesture", "scroll",
    "dom", "html", "markdown", "yaml", "toml", "xml", "json", "csv", "excel",
    "sql", "database", "mongo", "mongoose", "mysql", "postgres", "redis", "orm",
    "sequelize", "prisma", "knex", "graphql", "apollo", "relay", "rest", "grpc",
    "kafka", "rabbitmq", "mqtt", "amqp", "queue", "worker", "thread", "cluster",
    "fs", "file", "path", "glob", "watch", "stream", "buffer", "zlib", "gzip",
    "archive", "zip", "compress", "image", "img", "png", "jpg", "pdf", "font",
    "video", "audio", "media", "player", "recorder", "camera",
    "log", "logger", "logging", "debug", "trace", "error", "winston", "pino",
    "config", "env", "dotenv", "settings", "option", "flag", "argv", "yargs",
    "cli", "command", "terminal", "shell", "spawn", "exec", "prompt", "inquirer",
    "spinner", "progress", "chalk", "color", "ora", "boxen", "figures",
    "test", "testing", "mock", "stub", "fake", "fixture", "coverage", "assert",
    "schema", "validate", "validator", "yup", "zod", "ajv", "sanitize", "escape",
    "security", "helmet", "cors", "csrf", "xss", "bcrypt", "password", "encrypt",
    "session", "cookie", "passport", "cache", "memoize", "lru", "store", "state",
    "event", "emitter", "events", "observable", "rxjs", "promise", "async",
    "util", "utils", "helper", "tool", "toolkit", "lib", "library", "core",
    "common", "shared", "base", "mini", "light", "tiny", "simple", "fast",
    "server", "client", "sdk", "api", "restful", "openapi", "swagger",
    "node", "deno", "bun", "npm", "yarn", "pnpm", "package", "module", "plugin",
    "loader", "compiler", "parser", "lexer", "ast", "transform", "generator",
    "codegen", "template", "engine", "render", "view", "template",
    "javascript", "js", "typescript", "ts", "nodejs", "frontend", "backend",
    "fullstack", "dev", "development", "build", "deploy", "ci", "docker",
    "kubernetes", "k8s", "cloud", "aws", "azure", "gcp", "serverless",
    "ai", "ml", "llm", "openai", "gpt", "langchain", "embedding", "vector",
    "bot", "discord", "slack", "telegram", "wechat", "notification", "mail",
    "email", "sms", "push", "payment", "stripe", "paypal", "shop", "ecommerce",
    "cms", "blog", "docs", "documentation", "markdown-it", "highlight",
    "prism", "shiki", "monaco", "editor", "codemirror", "ace", "diff", "patch",
    "tree", "grid", "list", "select", "dropdown", "modal", "dialog", "drawer",
    "tooltip", "popover", "toast", "notification", "alert", "message", "badge",
    "avatar", "card", "tabs", "tab", "menu", "nav", "breadcrumb", "pagination",
    "slider", "carousel", "swiper", "calendar", "datepicker", "timepicker",
    "upload", "download", "progress", "skeleton", "loading", "spin", "empty",
    "drag", "drop", "sortable", "resizable", "virtual", "lazy", "prefetch",
    "polyfill", "shim", "core-js", "regenerator", "babel-polyfill",
    "echarts-for-react", "chart.js", "apexcharts", "highcharts", "recharts",
    "victory", "nivo", "visx", "sigma", "cytoscape", "dagre", "mermaid",
]

# Go 仓库中明显不是依赖库的项目名/描述关键词（按 GitHub Star 采样时过滤）
NON_LIBRARY_PATTERN = re.compile(
    r"(awesome|interview|roadmap|tutorial|course|cheatsheet|handbook|cookbook|"
    r"build your own|build-your-own|system design|leetcode|coding interview|"
    r"collection of|curated|list of|learning|study|education|bootcamp|"
    r"free programming|books?|notes on|summary of|resources|links|"
    r"project based|beginner|practice|exercise|guide to|how to learn)",
    re.IGNORECASE)


# ---------------------------------------------------------------------------
# 版本比较（覆盖 Maven / PyPI / Go 的常见版本形态）
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(r"\d+|[A-Za-z]+")

# 稳定限定词：出现在版本尾部时不视为预发布
STABLE_WORDS = {
    "release", "final", "ga", "r", "stable", "post", "rev", "sp", "fixed",
    "official", "current", "latest", "prod",
}
# 预发布限定词
PRERELEASE_WORDS = {
    "alpha", "beta", "rc", "m", "milestone", "cr", "snapshot", "pre", "preview",
    "dev", "ea", "incubating", "nightly", "canary", "attic", "deprecated",
    "experimental", "unstable", "bridge",
}


def _split_version(version):
    """把版本号拆成 (数字发布段, 限定词段)。"""
    text = str(version or "").strip()
    if text[:1] in ("v", "V"):
        text = text[1:]
    text = text.split("+", 1)[0]          # 去 build 元数据 / +incompatible
    text = text.split(";", 1)[0]          # Maven 版本范围偶见分号
    text = text.split("@", 1)[0]
    tokens = _TOKEN_RE.findall(text)
    release, qualifier = [], []
    in_qualifier = False
    for token in tokens:
        if not in_qualifier and token.isdigit():
            release.append(int(token))
        else:
            in_qualifier = True
            qualifier.append(token)
    return release, qualifier


def version_key(version):
    """可比较的版本键：发布段 > 段数 > 稳定标记 > 限定词。"""
    release, qualifier = _split_version(version)
    words = [word for word in qualifier if not word.isdigit()]
    if not qualifier:
        stable = 2
    elif words and all(word.lower() in STABLE_WORDS for word in words):
        stable = 2
    elif words and all(word.lower() in PRERELEASE_WORDS for word in words):
        stable = 0
    else:
        stable = 1
    qual_key = tuple(
        (0, word.lower()) if not word.isdigit() else (1, int(word))
        for word in qualifier)
    return (tuple(release), len(release), stable, qual_key)


def sort_versions(versions):
    """按版本新旧降序排列（新→旧）。"""
    return sorted({str(v) for v in versions if v}, key=version_key, reverse=True)


def pick_latest_stable(versions):
    """优先取最新稳定版；没有稳定版时退回最新版。"""
    ordered = sort_versions(versions)
    if not ordered:
        return None
    for version in ordered:
        _release, _qualifier = _split_version(version)
        if version_key(version)[2] == 2:
            return version
    return ordered[0]


# ---------------------------------------------------------------------------
# HTTP（线程本地 Session + 重试）
# ---------------------------------------------------------------------------

_TLS = threading.local()


def _session():
    session = getattr(_TLS, "session", None)
    if session is None:
        session = requests.Session()
        session.headers.update({
            "User-Agent": "scabase-popular-packages/1.0 (+https://github.com/scabase)",
            "Accept": "application/json",
        })
        _TLS.session = session
    return session


def http_json(url, attempts=4, timeout=30, backoff=1.2, quiet=True):
    """GET JSON，失败重试；404 返回 None（调用方视为「不存在」）。"""
    if requests is None:
        return None
    last = None
    for attempt in range(attempts):
        try:
            resp = _session().get(url, timeout=timeout)
            if resp.status_code in (404, 410):
                return None
            if resp.status_code >= 400:
                last = "HTTP %s" % resp.status_code
            else:
                return resp.json()
        except Exception as exc:  # pragma: no cover - 网络异常降级
            last = "%s: %s" % (type(exc).__name__, exc)
        time.sleep(backoff * (attempt + 1))
    if not quiet and last:
        print("    请求失败 %s (%s)" % (url, last), file=sys.stderr)
    return None


def run_pool(func, items, workers, label=""):
    """并发执行 func(item) -> 任意值，返回 {item: result}（异常记 None）。"""
    results = {}
    if not items:
        return results
    total = len(items)
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        futures = {pool.submit(func, item): item for item in items}
        done = 0
        for future in as_completed(futures):
            item = futures[future]
            done += 1
            try:
                results[item] = future.result()
            except Exception:  # pragma: no cover
                results[item] = None
            if label and (done % 250 == 0 or done == total):
                print("    %s %d/%d" % (label, done, total), flush=True)
    return results


# ---------------------------------------------------------------------------
# deps.dev 封装
# ---------------------------------------------------------------------------

def deps_quote(name):
    return urllib.parse.quote(str(name), safe="")


def deps_package_versions(system, name):
    url = "%s/systems/%s/packages/%s" % (DEPS_API, system.lower(), deps_quote(name))
    payload = http_json(url, attempts=4)
    versions = []
    for entry in (payload or {}).get("versions") or []:
        key = entry.get("versionKey") or {}
        if key.get("version"):
            versions.append(key["version"])
    return versions


def deps_dependents(system, name, version):
    url = "%s/systems/%s/packages/%s/versions/%s:dependents" % (
        DEPS_API, system.lower(), deps_quote(name), deps_quote(version))
    payload = http_json(url, attempts=3)
    if not payload:
        return None
    count = payload.get("dependentCount")
    return int(count) if isinstance(count, (int, float)) else None


def deps_requirements(system, name, version):
    url = "%s/systems/%s/packages/%s/versions/%s:requirements" % (
        DEPS_API, system.lower(), deps_quote(name), deps_quote(version))
    payload = http_json(url, attempts=3) or {}
    body = payload.get(system.lower()) or {}
    names = []
    for dep in body.get("dependencies") or []:
        resolved = dep.get("resolvedName") or dep.get("name") or ""
        if ":" in resolved:
            names.append(resolved)
    return names


def deps_project_package_versions(project_id, system=None):
    """GitHub 项目 → 包版本映射（用于 Go 仓库 → 模块路径）。

    system 传入时只保留该生态的包（deps.dev 会把仓库同时映射到 npm / Go 等）。
    """
    url = "%s/projects/%s:packageversions" % (DEPS_API, deps_quote(project_id))
    payload = http_json(url, attempts=3) or {}
    grouped = {}
    for entry in payload.get("versions") or []:
        key = entry.get("versionKey") or {}
        name, version = key.get("name"), key.get("version")
        if not name or not version:
            continue
        if system and (key.get("system") or "").upper() != system.upper():
            continue
        grouped.setdefault(name, []).append(version)
    return grouped


# ---------------------------------------------------------------------------
# NPM
# ---------------------------------------------------------------------------

def fetch_npm(top, workers):
    """npm registry 搜索接口多关键词采样，按周下载量排序。"""
    pool = {}

    def collect(keyword):
        params = {
            "text": keyword,
            "size": 250,
            "popularity": 1.0,
            "quality": 0,
            "maintenance": 0,
        }
        url = "%s?%s" % (NPM_SEARCH, urllib.parse.urlencode(params))
        payload = http_json(url, attempts=3, timeout=40)
        found = []
        for obj in (payload or {}).get("objects") or []:
            pkg = obj.get("package") or {}
            name = pkg.get("name")
            if not name:
                continue
            downloads = (obj.get("downloads") or {}).get("weekly") or 0
            dependents = obj.get("dependents")
            try:
                dependents = int(dependents)
            except (TypeError, ValueError):
                dependents = None
            found.append({
                "name": name,
                "version": pkg.get("version"),
                "desc": pkg.get("description") or "",
                "weekly_downloads": int(downloads or 0),
                "dependents": dependents,
            })
        return keyword, found

    results = run_pool(collect, NPM_KEYWORDS, workers, "npm 关键词采样")
    for keyword, found in results.values():
        for record in found or []:
            current = pool.get(record["name"])
            if current is None or record["weekly_downloads"] > current["weekly_downloads"]:
                pool[record["name"]] = record
    print("  npm 采样合并：%d 个候选包" % len(pool))

    # 人工种子保底（补版本与说明）
    missing = [name for name, _desc in NPM_SEEDS if name not in pool]

    def seed_record(name):
        url = "%s/%s/latest" % (NPM_REGISTRY, deps_quote(name))
        payload = http_json(url, attempts=3, timeout=30)
        if not payload:
            return None
        return {
            "name": name,
            "version": payload.get("version"),
            "desc": payload.get("description") or "",
            "weekly_downloads": 0,
            "dependents": None,
        }

    for name, record in run_pool(seed_record, missing, workers, "npm 种子补齐").items():
        if record:
            pool[name] = record
    desc_map = dict(NPM_SEEDS)
    for name, desc in desc_map.items():
        if name in pool and not pool[name].get("desc"):
            pool[name]["desc"] = desc

    ordered = sorted(pool.values(),
                     key=lambda r: (-r["weekly_downloads"], r["name"]))
    items = []
    for record in ordered[:top]:
        meta = {}
        if record.get("weekly_downloads"):
            meta["weekly_downloads"] = record["weekly_downloads"]
        if record.get("dependents"):
            meta["dependents"] = record["dependents"]
        items.append({
            "rank": 0,
            "name": record["name"],
            "version": record.get("version"),
            "desc": record.get("desc") or "",
            "line": "npm|%s|%s" % (record["name"], record.get("version") or ""),
            "meta": meta,
        })
    return items, "近一周 npm 下载量（registry 搜索接口多关键词采样合并）"


# ---------------------------------------------------------------------------
# PyPI
# ---------------------------------------------------------------------------

def fetch_pypi(top, workers):
    """top-pypi-packages 近 30 天下载量榜单 + deps.dev 版本校准。"""
    payload = http_json(PYPI_TOP_URL, attempts=4, timeout=60)
    rows = (payload or {}).get("rows") or []
    picked = rows[:top]
    if not picked:
        picked = [{"project": name, "download_count": 0} for name, _ in PYPI_SEEDS]
    names = [row.get("project") for row in picked if row.get("project")]

    def latest(name):
        versions = deps_package_versions("pypi", name)
        return name, pick_latest_stable(versions)

    versions = {name: version
                for name, version in run_pool(latest, names, workers,
                                              "pypi 版本校准").values()}
    desc_map = dict(PYPI_SEEDS)
    items = []
    for row in picked:
        name = row.get("project")
        if not name:
            continue
        version = versions.get(name)
        items.append({
            "rank": 0,
            "name": name,
            "version": version,
            "desc": desc_map.get(name, ""),
            "line": "pypi|%s|%s" % (name, version or ""),
            "meta": {
                "monthly_downloads": row.get("download_count"),
            },
        })
    basis = "近 30 天 PyPI 下载量（top-pypi-packages 官方统计）"
    if not payload:
        basis = "人工整理（top-pypi-packages 不可用）"
    return items, basis


# ---------------------------------------------------------------------------
# Maven
# ---------------------------------------------------------------------------

def fetch_maven(top, workers, max_candidates=2600):
    """curated 种子 + deps.dev 依赖图展开一层 → 按公开依赖项目数排序。"""
    seeds = [(gav, desc) for gav, desc in MAVEN_SEEDS]
    seed_names = {gav for gav, _ in seeds}

    print("  maven 种子：%d 个，正在获取最新稳定版本…" % len(seeds))

    def seed_version(item):
        gav, _desc = item
        return gav, pick_latest_stable(deps_package_versions("maven", gav))

    seed_versions = {gav: version
                     for gav, version in run_pool(
                         seed_version, seeds, workers, "maven 种子版本").values()
                     if version}
    print("  maven 种子有效版本：%d/%d" % (len(seed_versions), len(seeds)))

    # 依赖图展开一层：种子构件的直接依赖即「常见依赖」候选池
    def seed_deps(gav):
        version = seed_versions.get(gav)
        if not version:
            return gav, []
        return gav, deps_requirements("maven", gav, version)

    print("  maven 正在展开依赖图（一层）…")
    pool = {}          # gav -> {"refs": int, "desc": str}
    for gav, names in run_pool(seed_deps, list(seed_versions), workers,
                               "maven 依赖展开").values():
        for name in names or []:
            entry = pool.setdefault(name, {"refs": 0, "desc": ""})
            entry["refs"] += 1
    for gav, desc in seeds:
        pool.setdefault(gav, {"refs": 0, "desc": desc})
    print("  maven 候选池：%d 个构件（含 %d 个种子）" % (len(pool), len(seed_names)))

    if len(pool) > max_candidates:
        keep = set(seed_names)
        rest = sorted((gav for gav in pool if gav not in keep),
                      key=lambda gav: (-pool[gav]["refs"], gav))
        keep.update(rest[:max_candidates - len(keep)])
        pool = {gav: pool[gav] for gav in keep}
        print("  maven 候选池超限，按被依赖次数截断至 %d" % len(pool))

    # 版本 + 公开依赖数
    def probe(gav):
        versions = deps_package_versions("maven", gav)
        ordered = sort_versions(versions)
        stable = [v for v in ordered if version_key(v)[2] == 2]
        candidates = (stable or ordered)[:3]
        version = candidates[0] if candidates else None
        count = None
        for candidate in candidates:
            count = deps_dependents("maven", gav, candidate)
            if count:
                version = candidate
                break
        return {"version": version, "dependents": count or 0,
                "desc": pool[gav]["desc"]}

    print("  maven 正在统计公开依赖数…")
    probed = run_pool(probe, list(pool), workers, "maven 依赖数统计")

    desc_map = dict(MAVEN_SEEDS)
    items = []
    for gav, info in probed.items():
        if not info or not info.get("version"):
            continue
        items.append({
            "rank": 0,
            "name": gav,
            "version": info["version"],
            "desc": info.get("desc") or desc_map.get(gav, ""),
            "line": "maven|%s|%s" % (gav, info["version"]),
            "meta": {"dependents": info.get("dependents") or 0},
        })
    items.sort(key=lambda item: (-(item["meta"]["dependents"]), item["name"]))
    basis = ("deps.dev 公开依赖项目数（最新稳定版本；候选池 = 人工高频构件 "
             "+ 其直接依赖）")
    return items[:top], basis


# ---------------------------------------------------------------------------
# Go
# ---------------------------------------------------------------------------

def _github_search(query, page, per_page=100):
    params = {"q": query, "sort": "stars", "order": "desc",
              "per_page": per_page, "page": page}
    token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
    headers = {}
    if token:
        headers["Authorization"] = "Bearer %s" % token
    url = "%s?%s" % (GITHUB_SEARCH, urllib.parse.urlencode(params))
    for attempt in range(4):
        try:
            resp = _session().get(url, timeout=40, headers=headers)
        except Exception as exc:  # pragma: no cover
            print("    GitHub 搜索失败: %s" % exc, file=sys.stderr)
            time.sleep(5 * (attempt + 1))
            continue
        if resp.status_code == 403 and "rate limit" in resp.text.lower():
            reset = resp.headers.get("X-RateLimit-Reset")
            wait = 60
            try:
                wait = max(5, int(reset) - int(time.time()) + 2)
            except (TypeError, ValueError):
                pass
            print("    GitHub 搜索限流，等待 %ds" % wait, flush=True)
            time.sleep(min(wait, 300))
            continue
        if resp.status_code >= 400:
            return None
        try:
            return resp.json()
        except ValueError:  # pragma: no cover
            return None
    return None


def github_top_repos(language, target, star_floor=200):
    """按 Star 拉取 language 的热门仓库（含星标下限分档，突破 1000 条上限）。"""
    repos = {}
    bands = [None]
    pages_per_band = 10
    for band in bands + ["stars:1000..%d" % star_floor,
                         "stars:300..999", "stars:100..299"]:
        query = "language:%s" % language + ((" " + band) if band else "")
        for page in range(1, pages_per_band + 1):
            data = _github_search(query, page)
            items = (data or {}).get("items") or []
            if not items:
                break
            for item in items:
                full_name = item.get("full_name")
                if not full_name:
                    continue
                repos[full_name] = {
                    "stars": item.get("stargazers_count") or 0,
                    "desc": item.get("description") or "",
                }
            if len(repos) >= target or len(items) < 100:
                break
        if len(repos) >= target:
            break
    return repos


def fetch_go(top, workers, repo_target=2200):
    """Go：人工核心模块 + GitHub Star 热门仓库（deps.dev 映射模块路径与版本）。"""
    curated = {}
    for name, desc in GO_SEEDS:
        curated[name] = desc

    print("  go 正在拉取 GitHub 热门 Go 仓库…")
    repos = github_top_repos("go", repo_target)
    print("  go 候选仓库：%d 个" % len(repos))

    def probe_repo(full_name):
        project_id = "github.com/%s" % full_name
        grouped = deps_project_package_versions(project_id, system="GO")
        if not grouped:
            return None
        preferred = ("github.com/%s" % full_name).lower()
        # 取版本数最多的模块名：kubernetes/kubernetes → k8s.io/kubernetes、
        # grpc/grpc → google.golang.org/grpc 等规范路径会自然胜出
        best_name = max(grouped,
                        key=lambda name: (len(grouped[name]),
                                          1 if name.lower() == preferred else 0))
        return {
            "module": best_name,
            "version": pick_latest_stable(grouped[best_name]),
        }

    probed = run_pool(probe_repo, list(repos), workers, "go 模块映射")

    star_items = []
    for full_name, info in probed.items():
        if not info or not info.get("version"):
            continue
        meta = repos.get(full_name) or {}
        text = "%s %s" % (full_name, meta.get("desc") or "")
        if NON_LIBRARY_PATTERN.search(text):
            continue
        star_items.append({
            "name": info["module"],
            "version": info["version"],
            "desc": "",
            "stars": meta.get("stars") or 0,
        })
    star_items.sort(key=lambda item: (-item["stars"], item["name"]))

    def curated_version(name):
        return name, pick_latest_stable(deps_package_versions("go", name))

    curated_versions = {name: version
                        for name, version in run_pool(
                            curated_version, list(curated), workers,
                            "go 核心模块版本").values() if version}

    items = []
    seen = set()
    for name, desc in curated.items():
        version = curated_versions.get(name)
        if not version:
            continue
        seen.add(name)
        items.append({
            "rank": 0, "name": name, "version": version, "desc": desc,
            "line": "go|%s|%s" % (name, version),
            "meta": {"source": "生态核心模块（人工整理）"},
        })
    for item in star_items:
        if item["name"] in seen:
            continue
        seen.add(item["name"])
        items.append({
            "rank": 0, "name": item["name"], "version": item["version"],
            "desc": item["desc"],
            "line": "go|%s|%s" % (item["name"], item["version"]),
            "meta": {"stars": item["stars"], "source": "GitHub Star 排序"},
        })
    basis = ("生态核心模块（人工整理）优先，其余按 GitHub Star 排序"
             "（经 deps.dev 映射模块路径与版本）")
    return items[:top], basis


# ---------------------------------------------------------------------------
# 产物组装
# ---------------------------------------------------------------------------

def build_items_offline(ecosystem, top):
    """离线模式：只用人工种子，版本留空（健康度查询允许不带版本）。"""
    seeds = {"maven": MAVEN_SEEDS, "npm": NPM_SEEDS,
             "pypi": PYPI_SEEDS, "go": GO_SEEDS}[ecosystem]
    items = []
    for idx, (name, desc) in enumerate(seeds[:top]):
        items.append({
            "rank": idx + 1,
            "name": name,
            "version": None,
            "desc": desc,
            "line": "%s|%s|" % (ecosystem, name),
            "meta": {},
        })
    return items


OFFLINE_BASIS = {
    "maven": "人工整理：按 Java 生态常见程度排序",
    "npm": "人工整理：按 Node 生态常见程度排序",
    "pypi": "人工整理：按 Python 生态常见程度排序",
    "go": "人工整理：按 Go 生态常见程度排序",
}


def build_document(refresh, top, workers=WORKERS_DEFAULT, verbose=True,
                   only=None, existing=None):
    """组装四生态清单。

    only 非空时只刷新指定生态，其余生态沿用 existing 中已采集的数据
    （便于单生态增量刷新，避免重复请求全部数据源）。
    """
    selected = {name.strip().lower() for name in (only or []) if name.strip()}
    lists = []
    fetchers = {
        "npm": lambda: fetch_npm(top, workers),
        "pypi": lambda: fetch_pypi(top, workers),
        "maven": lambda: fetch_maven(top, workers),
        "go": lambda: fetch_go(top, workers),
    }
    for ecosystem, label in ECOSYSTEMS:
        if selected and ecosystem not in selected and existing:
            reused = None
            for group in existing.get("lists") or []:
                if group.get("ecosystem") == ecosystem:
                    reused = group
                    break
            if reused:
                lists.append(reused)
                if verbose:
                    print("[%s] 沿用已有数据（%d 项）" % (ecosystem, reused.get("count") or 0),
                          flush=True)
                continue
        if refresh:
            if verbose:
                print("[%s] 联网采集…" % ecosystem, flush=True)
            items, basis = fetchers[ecosystem]()
        else:
            items = build_items_offline(ecosystem, top)
            basis = OFFLINE_BASIS[ecosystem]
        for idx, item in enumerate(items):
            item["rank"] = idx + 1
        lists.append({
            "key": ecosystem,
            "label": "%s %d" % (label, top),
            "ecosystem": ecosystem,
            "count": len(items),
            "rank_basis": basis,
            "items": items,
        })
        if verbose:
            print("[%s] %d 项（%s）" % (ecosystem, len(items), basis), flush=True)
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": ("npm registry 搜索 / top-pypi-packages / deps.dev 依赖图与依赖数 / "
                   "GitHub Star + deps.dev 项目映射"),
        "notes": ("示例清单用于快速体验漏洞查询与社区支持力度查询；"
                  "版本号为刷新时刻的最新稳定发布版本。"),
        "lists": lists,
    }


def load_existing(path=None):
    path = path or JSON_OUT
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return None


def write_txt(document, txt_top=TXT_TOP_DEFAULT, path=None):
    lines = ["# 由 scabase-fetcher/scripts/gen_popular_packages.py 生成：" +
             "常用依赖 Top 清单（ecosystem|package|version）",
             "# 生成时间 %s" % document["generated_at"],
             "# 每生态取前 %d 条（完整清单见 popular-packages.json）" % txt_top]
    for group in document["lists"]:
        lines.append("# %s（%s，共 %d 项）" % (group["label"], group["ecosystem"],
                                             group["count"]))
        for item in (group.get("items") or [])[:txt_top]:
            if item.get("version"):
                lines.append(item["line"])
    target = path or TXT_OUT
    os.makedirs(os.path.dirname(os.path.abspath(target)), exist_ok=True)
    with open(target, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def write_json(document, path=None):
    target = path or JSON_OUT
    os.makedirs(os.path.dirname(os.path.abspath(target)), exist_ok=True)
    with open(target, "w", encoding="utf-8") as handle:
        json.dump(document, handle, ensure_ascii=False, separators=(",", ":"))
        handle.write("\n")


def main():
    global JSON_OUT, TXT_OUT
    parser = argparse.ArgumentParser(description="常用依赖 Top 清单生成")
    parser.add_argument("--refresh", action="store_true",
                        help="联网刷新四个生态的 Top 清单（默认每生态 1000 条）")
    parser.add_argument("--top", type=int, default=TOP_DEFAULT,
                        help="每生态取前 N 个（默认 1000）")
    parser.add_argument("--txt-top", type=int, default=TXT_TOP_DEFAULT,
                        help="pkg_list_popular.txt 每生态取前 N 个（默认 100）")
    parser.add_argument("--workers", type=int, default=WORKERS_DEFAULT,
                        help="并发请求数（默认 8）")
    parser.add_argument("--repo-target", type=int, default=2200,
                        help="Go 生态采样的 GitHub 仓库数（默认 2200）")
    parser.add_argument("--only", default="",
                        help="只刷新指定生态（逗号分隔：maven/npm/pypi/go），"
                             "其余生态沿用已有 JSON 数据")
    parser.add_argument("--json", default=JSON_OUT)
    parser.add_argument("--txt", default=TXT_OUT)
    args = parser.parse_args()

    JSON_OUT, TXT_OUT = args.json, args.txt

    if args.refresh and requests is None:
        print("缺少 requests，无法联网刷新；改为读取已有产物", file=sys.stderr)
        args.refresh = False

    if not args.refresh:
        existing = load_existing()
        if existing:
            write_txt(existing, args.txt_top)
            print("离线模式：复用 %s，已生成 %s" % (JSON_OUT, TXT_OUT))
            return 0
        print("离线模式且无已有 %s，将使用内置种子清单" % JSON_OUT)

    only = [name.strip().lower() for name in args.only.split(",") if name.strip()]
    existing = load_existing() if (only and args.refresh) else None
    if only and args.refresh and not existing:
        print("未找到已有 %s，将全量刷新四个生态" % JSON_OUT, file=sys.stderr)
        only = []

    document = build_document(args.refresh, args.top, args.workers,
                              only=only, existing=existing)
    write_json(document)
    write_txt(document, args.txt_top)
    for group in document["lists"]:
        missing = sum(1 for item in group["items"] if not item.get("version"))
        print("%s：%d 项，缺版本 %d 项" % (group["label"], group["count"], missing))
    print("已写入 %s / %s" % (JSON_OUT, TXT_OUT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
