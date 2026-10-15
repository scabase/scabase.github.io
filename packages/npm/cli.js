#!/usr/bin/env node
'use strict';

/**
 * scabase-data 命令行：查看清单、校验完整性、按 CVE 反查组件。
 *
 *   npx scabase-data version
 *   npx scabase-data manifest
 *   npx scabase-data verify
 *   npx scabase-data cve CVE-2025-70974
 *   npx scabase-data dataset health
 */
var api = require('./index.js');

var USAGE = [
  '用法：scabase-data <command> [args]',
  '',
  '  manifest            输出清单（版本号、文件哈希、条目统计）',
  '  version             输出发布包版本号',
  '  digest              输出内容指纹（判断是否需要重新拉取）',
  '  verify              逐文件校验 sha256（失败退出码 1）',
  '  path                输出发布包根目录',
  '  dataset <name>      输出数据集文件绝对路径（vulns/health/community）',
  '  cve <CVE-x-y>       反查受该 CVE 影响的组件',
  '  grade <A|B|C|D>     输出该社区支持力度等级的组件',
  '  help                显示本帮助'
].join('\n');

function dump(value) {
  process.stdout.write(JSON.stringify(value, null, 2) + '\n');
}

var cmd = (process.argv[2] || 'manifest').toLowerCase();
var arg = process.argv[3];

switch (cmd) {
  case 'manifest':
    dump(api.manifest());
    break;
  case 'version':
    process.stdout.write(api.version() + '\n');
    break;
  case 'digest':
    process.stdout.write(api.contentDigest() + '\n');
    break;
  case 'verify': {
    var result = api.verify();
    dump(result);
    process.exit(result.ok ? 0 : 1);
    break;
  }
  case 'path':
    process.stdout.write(api.root() + '\n');
    break;
  case 'dataset': {
    var file = api.datasetPath(arg);
    if (!file) {
      process.stderr.write('数据集不存在：' + arg + '\n');
      process.exit(1);
    }
    process.stdout.write(file + '\n');
    break;
  }
  case 'cve': {
    var hits = api.findByCve(arg);
    dump(hits);
    process.exit(hits.length ? 0 : 1);
    break;
  }
  case 'grade':
    dump(api.componentsByGrade(arg));
    break;
  case 'help':
  case '-h':
  case '--help':
    process.stdout.write(USAGE + '\n');
    break;
  default:
    process.stderr.write('未知命令：' + cmd + '\n' + USAGE + '\n');
    process.exit(2);
}
