package cn.scabase.data;

import java.io.IOException;
import java.io.InputStream;

/**
 * ScaBase 数据访问入口。
 *
 * <p>jar 内资源路径：
 *
 * <pre>
 * scabase-data/manifest.json
 * scabase-data/data/vulns.json
 * scabase-data/data/health.json
 * scabase-data/data/community-support.json
 * scabase-data/data/facts/&lt;dataset&gt;/&lt;eco&gt;.json
 * </pre>
 *
 * <p>示例：
 *
 * <pre>{@code
 * String manifest = ScaBaseData.manifest();
 * String vulns = ScaBaseData.vulns();
 * String health = ScaBaseData.health();
 * }</pre>
 */
public final class ScaBaseData {

    /** jar 内资源根路径。 */
    public static final String BASE = "scabase-data";

    private ScaBaseData() {
        // 工具类，禁止实例化
    }

    /**
     * 打开包内资源的输入流，调用方负责关闭。
     *
     * @param relativePath 相对 {@link #BASE} 的路径，如 {@code data/vulns.json}
     * @return 非空输入流
     * @throws IOException 资源不存在时抛出
     */
    public static InputStream open(String relativePath) throws IOException {
        String path = BASE + "/" + relativePath;
        InputStream in = ScaBaseData.class.getClassLoader().getResourceAsStream(path);
        if (in == null) {
            throw new IOException("数据资源不存在：" + path);
        }
        return in;
    }

    /**
     * 读取包内资源为 UTF-8 字符串。
     *
     * @param relativePath 相对 {@link #BASE} 的路径
     * @return 文件内容
     * @throws IOException 资源不存在或读取失败
     */
    public static String read(String relativePath) throws IOException {
        try (InputStream in = open(relativePath)) {
            return new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        }
    }

    /** 清单：版本号、content_digest、每个文件的 sha256 与条目数。 */
    public static String manifest() throws IOException {
        return read("manifest.json");
    }

    /** 漏洞结果（OSV + NVD 富化，按组件聚合）。 */
    public static String vulns() throws IOException {
        return read("data/vulns.json");
    }

    /** 组件活跃度原始信号。 */
    public static String health() throws IOException {
        return read("data/health.json");
    }

    /** 社区支持力度汇总（0-100 分与 A/B/C/D 等级）。 */
    public static String community() throws IOException {
        return read("data/community-support.json");
    }
}
