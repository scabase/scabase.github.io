"""GitHub Actions 工作流文件校验。

背景：``pages.yml`` 的 ``on:`` 块曾被误缩进两个空格（写成 ``  on:``），
GitHub 直接判定「Invalid workflow file」，该工作流长期处于 failure：
站点改由分支部署兜底，而 pages.yml 内的资产版本号（``?v=hash``）与
``index.json`` 构建时重建静默失效。本测试把该检查前移到 CI 门禁
（community-health.yml 的测试步骤先于数据提交执行）。
"""
import glob
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOW_DIR = os.path.join(ROOT, ".github", "workflows")


class WorkflowFilesTest(unittest.TestCase):
    """工作流必须是合法 YAML，且 on/jobs 等顶层键位于第 0 列。"""

    def test_workflow_files_exist(self):
        files = glob.glob(os.path.join(WORKFLOW_DIR, "*.yml"))
        self.assertTrue(files, "未找到任何工作流文件：%s" % WORKFLOW_DIR)

    def test_workflows_parse_and_shape(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML 不可用，跳过 YAML 解析校验")
        for path in sorted(glob.glob(os.path.join(WORKFLOW_DIR, "*.yml"))):
            name = os.path.basename(path)
            with open(path, "r", encoding="utf-8") as handle:
                text = handle.read()
            try:
                doc = yaml.safe_load(text)
            except yaml.YAMLError as exc:
                self.fail("%s YAML 解析失败: %s" % (name, exc))
            self.assertIsInstance(doc, dict, name)
            # `on:` 在 YAML 1.1 下被解析为布尔键 True
            self.assertTrue(True in doc or "on" in doc, "%s 缺少 on 触发器" % name)
            self.assertIn("jobs", doc, "%s 缺少 jobs 段" % name)

    def test_top_level_keys_not_indented(self):
        """on:/jobs: 必须在第 0 列——pages.yml 缩进事故的精准回归。"""
        for path in sorted(glob.glob(os.path.join(WORKFLOW_DIR, "*.yml"))):
            name = os.path.basename(path)
            with open(path, "r", encoding="utf-8") as handle:
                lines = handle.read().splitlines()
            for key in ("on:", "jobs:"):
                candidates = [ln for ln in lines if ln.lstrip().startswith(key)]
                self.assertTrue(candidates, "%s 缺少顶层 %s" % (name, key))
                for line in candidates:
                    self.assertTrue(
                        line.startswith(key),
                        "%s 的 %s 被缩进（%r），GitHub 会判 Invalid workflow file"
                        % (name, key, line))


if __name__ == "__main__":
    unittest.main()
