#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""osv_enrich 解析单测:mock 掉网络,离线验证三种 OSV 返回形态的解析。
(真实 api.osv.dev 在部分本地网络不可达,线上由 GitHub Actions 验证)"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
import collect  # noqa: E402

# —— 形态1:SEMVER/ECOSYSTEM ranges(introduced + fixed)——
collect.http_json = lambda url, headers=None, tries=3: {
    'id': 'GHSA-xxxx', 'aliases': ['CVE-2024-2887'],
    'affected': [{'package': {'name': 'ghostscript', 'ecosystem': 'Ubuntu:Pro:20.04:LTS'},
                  'ranges': [{'type': 'SEMVER',
                              'events': [{'introduced': '0'},
                                         {'fixed': '10.04.0'}]}]}],
}
out = collect.osv_enrich([{'id': 'CVE-2024-2887', 'ver': '详见公告', 'tags': ['XSS']}])
ver, eco = out['CVE-2024-2887']
assert ver == 'Ubuntu ghostscript < 10.04.0', f'ranges 解析错误: {ver!r}'
assert eco == 'Ubuntu', f'生态标签错误: {eco!r}'

# —— 形态2:versions 枚举 ——
collect.http_json = lambda url, headers=None, tries=3: {
    'affected': [{'package': {'name': 'requests', 'ecosystem': 'PyPI'},
                  'versions': ['2.0.0', '2.1.0', '2.2.0', '2.3.0']}],
}
out = collect.osv_enrich([{'id': 'CVE-2024-2887', 'ver': '详见公告', 'tags': []}])
ver, eco = out['CVE-2024-2887']
assert ver == 'PyPI requests 2.0.0 / 2.1.0 / 2.2.0', f'versions 解析错误: {ver!r}'
assert eco == 'PyPI'

# —— 形态3:404 / 不可达 → 不产出,不抛错 ——
collect.http_json = lambda url, headers=None, tries=3: None
out = collect.osv_enrich([{'id': 'CVE-2099-0001', 'ver': '详见公告', 'tags': []}])
assert out == {}, '不可达时应返回空字典'

# —— 已有 CPE 版本的条目不查询 ——
calls = []
def spy(url, headers=None, tries=3):
    calls.append(url)
    return None
collect.http_json = spy
collect.osv_enrich([{'id': 'CVE-2024-1', 'ver': 'Linux Kernel ≤ 6.9', 'tags': []},
                    {'id': 'CVE-2024-2', 'ver': None, 'tags': []}])
assert calls == ['https://api.osv.dev/v1/vulns/CVE-2024-2'], \
    f'不应查询已有版本条目: {calls}'

print('OSV-PARSE-TESTS: 4/4 PASS')
