'use strict';

/**
 * ScaBase 数据发布包访问接口。
 *
 * 包内结构（版本号、文件 sha256 与条目数见 manifest.json）：
 *
 *     manifest.json
 *     data/vulns.json                漏洞结果（OSV + NVD 富化，按组件聚合）
 *     data/health.json               组件活跃度原始信号
 *     data/community-support.json    社区支持力度汇总（A/B/C/D 等级）
 *     data/facts/<dataset>/<eco>.json  事实层分片快照（可选）
 */
var fs = require('fs');
var path = require('path');
var crypto = require('crypto');

var ROOT = __dirname;

/** 读取 JSON 文件（UTF-8）。 */
function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

/** 逐文件计算 sha256，与 manifest 中的记录保持一致。 */
function sha256File(file) {
  var digest = crypto.createHash('sha256');
  digest.update(fs.readFileSync(file));
  return digest.digest('hex');
}

function exists(file) {
  try {
    return fs.statSync(file).isFile();
  } catch (err) {
    return false;
  }
}

var cache = {};

/** 发布包根目录，容器/脚本拷贝后仍以该目录为基准定位数据。 */
function root() {
  return ROOT;
}

/** 清单对象（含 version / content_digest / files / datasets / signature）。 */
function manifest() {
  if (!cache.manifest) {
    cache.manifest = readJson(path.join(ROOT, 'manifest.json'));
  }
  return cache.manifest;
}

/** 清单声明的版本号（CalVer，如 20261015.231400.0）。 */
function version() {
  return manifest().version;
}

/** 内容指纹：相同数据必定相同，用于判断是否需要重新拉取。 */
function contentDigest() {
  return manifest().content_digest;
}

/**
 * 数据集文件的绝对路径；不存在返回 null。
 * name 取 vulns / health / community，或直接传清单里的相对路径。
 */
function datasetPath(name) {
  if (!name) {
    return null;
  }
  var dataset = (manifest().datasets || {})[name];
  var rel = dataset ? dataset.path : name;
  var file = path.join(ROOT, rel);
  return exists(file) ? file : null;
}

/** 读取并解析某个数据集（不存在时返回 null）。 */
function read(name) {
  var file = datasetPath(name);
  return file ? readJson(file) : null;
}

/** 包内随附的事实层目录（可选产物，缺失返回 null）。 */
function factsDir() {
  var dir = path.join(ROOT, 'data', 'facts');
  try {
    return fs.statSync(dir).isDirectory() ? dir : null;
  } catch (err) {
    return null;
  }
}

/** 收集单条漏洞记录涉及的所有编号（含 CVE 别名）。 */
function idsOf(record) {
  var out = [];
  if (!record) {
    return out;
  }
  if (record.id) {
    out.push(record.id);
  }
  (record.aliases || []).forEach(function (alias) {
    if (out.indexOf(alias) < 0) {
      out.push(alias);
    }
  });
  return out;
}

/** 提取某条漏洞记录的 CVE 编号列表。 */
function cveIdsOf(record) {
  return idsOf(record).filter(function (id) {
    return /^CVE-/i.test(id);
  });
}

/**
 * 按 CVE 编号反查受影响组件。
 * 返回 [{ component, osvId, aliases, cves, severity, published, modified, source }]。
 */
function findByCve(cveId) {
  var target = String(cveId || '').toUpperCase();
  var vulns = read('vulns') || {};
  var hits = [];
  Object.keys(vulns).forEach(function (component) {
    var payload = vulns[component] || {};
    var records = ((payload.osv_raw || {}).vulns) || [];
    records.forEach(function (record) {
      var aliases = idsOf(record);
      var cves = cveIdsOf(record);
      if (aliases.indexOf(target) < 0 && cves.indexOf(target) < 0) {
        return;
      }
      hits.push({
        component: component,
        osvId: record.id || null,
        aliases: aliases,
        cves: cves,
        severity: ((record.database_specific || {}).severity) || null,
        published: record.published || null,
        modified: record.modified || null,
        source: record.source || 'OSV'
      });
    });
  });
  return hits;
}

/** 社区支持力度结果里某个等级（A/B/C/D）的全部组件。 */
function componentsByGrade(grade) {
  var report = read('community') || {};
  return (report.components || []).filter(function (row) {
    return String(row.grade).toUpperCase() === String(grade || '').toUpperCase();
  });
}

/**
 * 逐文件校验完整性：比对 sha256 与 manifest 记录是否一致。
 * 返回 { ok, checked, failures: [{ path, reason }] }。
 */
function verify() {
  var failures = [];
  var files = manifest().files || [];
  files.forEach(function (entry) {
    var file = path.join(ROOT, entry.path);
    if (!exists(file)) {
      failures.push({ path: entry.path, reason: 'missing' });
      return;
    }
    if (entry.sha256 && sha256File(file) !== entry.sha256) {
      failures.push({ path: entry.path, reason: 'sha256-mismatch' });
    }
  });
  return { ok: failures.length === 0, checked: files.length, failures: failures };
}

module.exports = {
  root: root,
  manifest: manifest,
  version: version,
  contentDigest: contentDigest,
  datasetPath: datasetPath,
  read: read,
  vulns: function () {
    return read('vulns');
  },
  health: function () {
    return read('health');
  },
  community: function () {
    return read('community');
  },
  factsDir: factsDir,
  findByCve: findByCve,
  componentsByGrade: componentsByGrade,
  verify: verify
};
