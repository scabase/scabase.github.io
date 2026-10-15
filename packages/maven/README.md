# ScaBase 数据 Maven 包模板

发布后的坐标为 `cn.scabase:scabase-data`，走 GitHub Packages 的
Apache Maven 注册表（`https://maven.pkg.github.com/scabase/scabase.github.io`）。

`packages/maven` 目录**本身不带数据**，数据由流水线构建 staging 内容后
落到 `packages/maven/generated/scabase-data/`（`generated/` 已加入 `.gitignore`），
再在打包时作为资源目录挂进 jar 的 `scabase-data/` 路径下。

## 本地打包

```bash
python -m oss_intake.cli release --out packages/maven/generated/scabase-data \
  --vulns scabase-fetcher/data/vulns.json \
  --health scabase-fetcher/data/health.json \
  --community scabase-fetcher/data/community-support.json \
  --facts scabase-fetcher/data/facts
mvn -f packages/maven/pom.xml -B clean package
# 查看产物内容
unzip -l packages/maven/target/scabase-data-*.jar
```

## 依赖方式

```xml
<dependency>
  <groupId>cn.scabase</groupId>
  <artifactId>scabase-data</artifactId>
  <version>20261015.231400.0</version>
</dependency>
```

```java
import cn.scabase.data.ScaBaseData;

String manifest = ScaBaseData.manifest();
String vulns = ScaBaseData.vulns();
String health = ScaBaseData.health();
```

包名/版本每轮发布重算，消费端建议直接读取 `scabase-data/manifest.json`
里的 `version` 与 `content_digest` 做版本对齐。
