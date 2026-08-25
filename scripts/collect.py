#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
漏讯 VulnWire · 情报采集脚本
抓取 NVD / GitHub POC 仓库 / CISA KEV 三个免费公开源，
生成 data/data.json 供前端动态加载。

仅用 Python 标准库；任一数据源失败自动降级（重试 2 次后跳过）；
items 为空时不写文件（保留旧数据），始终以退出码 0 结束（除非全部失败且无旧数据可保留时仍退出 0）。
用法：python3 scripts/collect.py  （在仓库根目录执行）
"""

import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

# ---------------- 配置 ----------------
NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
GH_SEARCH_URL = 'https://api.github.com/search/repositories'
KEV_URL = ('https://www.cisa.gov/sites/default/files/feeds/'
           'known_exploited_vulnerabilities.json')
OUT_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'data.json')

WINDOW_HOURS = 72          # 情报流窗口：近 72 小时新披露的 CVE
POC_PUSH_WINDOW_H = 24 * 7 # POC 仓库：近 7 天有推送的
MAX_ITEMS = 60
MAX_POCS = 60
HTTP_TIMEOUT = 40
TZ8 = timezone(timedelta(hours=8))

SEV_LABEL = {'crit': '严重', 'high': '高危', 'med': '中危', 'low': '低危'}
SEV_LABEL_EN = {'crit': 'critical', 'high': 'high', 'med': 'medium', 'low': 'low'}

# CWE → 中文类型（POC 表 type 字段用英文 key）
CWE_MAP = {
    'CWE-78': ('命令注入', 'cmd'),   'CWE-79': ('XSS', 'leak'),
    'CWE-89': ('SQL 注入', 'sqli'),  'CWE-22': ('路径遍历', 'leak'),
    'CWE-918': ('SSRF', 'ssrf'),     'CWE-352': ('CSRF', 'priv'),
    'CWE-434': ('文件上传', 'rce'),  'CWE-502': ('反序列化', 'deser'),
    'CWE-287': ('认证缺陷', 'priv'), 'CWE-862': ('权限绕过', 'priv'),
    'CWE-863': ('权限绕过', 'priv'), 'CWE-269': ('提权', 'priv'),
    'CWE-125': ('越界读取', 'mem'),  'CWE-787': ('越界写入', 'mem'),
    'CWE-120': ('缓冲区溢出', 'mem'),'CWE-190': ('整数溢出', 'mem'),
    'CWE-200': ('信息泄露', 'leak'), 'CWE-611': ('XXE', 'leak'),
    'CWE-74': ('注入', 'cmd'),       'CWE-94': ('代码注入', 'rce'),
    'CWE-95': ('代码注入', 'rce'),   'CWE-77': ('命令注入', 'cmd'),
}
# 描述关键词兜底（CWE 缺失时）
KW_MAP = [
    (r'remote code execution|remote command execution|rce\b', ('RCE', 'rce')),
    (r'sql injection', ('SQL 注入', 'sqli')),
    (r'cross-site scripting|\bxss\b', ('XSS', 'leak')),
    (r'server-side request forgery|\bssrf\b', ('SSRF', 'ssrf')),
    (r'path traversal|directory traversal', ('路径遍历', 'leak')),
    (r'deserializ', ('反序列化', 'deser')),
    (r'privilege escalation|elevation of privilege', ('提权', 'priv')),
    (r'authorization bypass|authenticat\w* bypass|access control', ('权限绕过', 'priv')),
    (r'arbitrary file (read|upload)', ('文件操作', 'leak')),
    (r'information (disclosure|leak)', ('信息泄露', 'leak')),
    (r'out[- ]of[- ]bounds|buffer overflow|memory corruption|use.after.free', ('内存破坏', 'mem')),
    (r'command injection', ('命令注入', 'cmd')),
    (r'cross-site request forgery|\bcsrf\b', ('CSRF', 'priv')),
]

# ---------------- 工具 ----------------
def http_json(url, headers=None, tries=3):
    """GET → JSON，指数退避重试"""
    last = None
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers=headers or {
                'User-Agent': 'VulnWire-collector/1.0', 'Accept': 'application/json'})
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
                return json.loads(r.read().decode('utf-8'))
        except Exception as e:  # noqa: BLE001 — 任一源失败都要降级
            last = e
            if i < tries - 1:
                time.sleep(3 * (i + 1))
    print(f'  ! 源失败 {url[:60]}… : {last}', file=sys.stderr)
    return None

def rel_zh(iso):
    """ISO 时间 → 中文相对时间（X 分钟前）"""
    try:
        dt = datetime.fromisoformat(iso.replace('Z', '+00:00'))
    except (ValueError, AttributeError):
        return '近期'
    if dt.tzinfo is None:          # NVD 的时间戳无时区后缀，按 UTC 处理
        dt = dt.replace(tzinfo=timezone.utc)
    mins = int((datetime.now(timezone.utc) - dt).total_seconds() // 60)
    if mins < 1:    return '刚刚'
    if mins < 60:   return f'{mins} 分钟前'
    if mins < 1440: return f'{mins // 60} 小时前'
    if mins < 1440 * 30: return f'{mins // 1440} 天前'
    return f'{mins // (1440 * 30)} 个月前'

def star_fmt(n):
    if n >= 1000:
        s = f'{n / 1000:.1f}'.rstrip('0').rstrip('.')
        return f'{s}k'
    return str(n)

def sev_of(score):
    if score is None: return 'low'
    if score >= 9: return 'crit'
    if score >= 7: return 'high'
    if score >= 4: return 'med'
    return 'low'

def cve_id_of(text):
    m = re.search(r'CVE-\d{4}-\d{4,7}', text or '', re.I)
    return m.group(0).upper() if m else None

# ---------------- 数据源 ----------------
def fetch_nvd():
    """近 WINDOW_HOURS 新披露的 CVE 列表（原始 NVD 结构）"""
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=WINDOW_HOURS)
    q = urllib.parse.urlencode({
        'pubStartDate': start.strftime('%Y-%m-%dT%H:%M:%S.000+00:00'),
        'pubEndDate':   end.strftime('%Y-%m-%dT%H:%M:%S.000+00:00'),
        'resultsPerPage': 2000,
    })
    data = http_json(f'{NVD_URL}?{q}')
    if not data:
        return None
    out, idx = [], data.get('startIndex', 0)
    out += data.get('vulnerabilities', [])
    total = data.get('totalResults', len(out))
    while idx + 2000 < total and len(out) < 2000:  # 兜底翻页（一般到不了）
        idx += 2000
        q2 = q + f'&startIndex={idx}'
        d2 = http_json(f'{NVD_URL}?{q2}')
        if not d2: break
        out += d2.get('vulnerabilities', [])
    print(f'  NVD: {len(out)} 条新披露 CVE（近 {WINDOW_HOURS}h）')
    return out

def fetch_github_repos():
    """近 POC_PUSH_WINDOW_H 有推送、名称含 CVE 的仓库"""
    since = (datetime.now(timezone.utc) - timedelta(hours=POC_PUSH_WINDOW_H)) \
        .strftime('%Y-%m-%d')
    q = urllib.parse.urlencode({'q': f'CVE in:name pushed:>{since}',
                                'sort': 'updated', 'order': 'desc',
                                'per_page': 100})
    headers = {'User-Agent': 'VulnWire-collector/1.0', 'Accept': 'application/json'}
    tok = os.environ.get('GITHUB_TOKEN') or os.environ.get('GH_TOKEN')
    if tok:
        headers['Authorization'] = f'Bearer {tok}'
    data = http_json(f'{GH_SEARCH_URL}?{q}', headers=headers)
    if not data:
        return None
    repos = [it for it in data.get('items', [])
             # 投毒防护：排除归档、零关注可疑仓库、恶意描述
             if not it.get('archived')
             and (it.get('stargazers_count', 0) >= 1 or it.get('forks_count', 0) >= 1)
             and 'malware' not in (it.get('description') or '').lower()
             and 'malicious' not in (it.get('description') or '').lower()]
    print(f'  GitHub: {len(repos)} 个活跃 POC 仓库（近 {POC_PUSH_WINDOW_H//24} 天）')
    return repos

def fetch_kev():
    """CISA KEV → {cveID: entry}"""
    data = http_json(KEV_URL)
    if not data:
        return None
    m = {v['cveID'].upper(): v for v in data.get('vulnerabilities', [])}
    print(f'  KEV: {len(m)} 条在野利用记录')
    return m

# ---------------- 字段提取 ----------------
def nvd_fields(v):
    """NVD vulnerabilities[i].cve → 常用字段"""
    c = v.get('cve', v)
    desc = ''
    for d in c.get('descriptions', []):
        if d.get('lang') == 'en':
            desc = d.get('value', '')
            break
    score = None
    for k in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
        m = c.get('metrics', {}).get(k)
        if m:
            score = m[0].get('cvssData', {}).get('baseScore')
            if score is not None:
                break
    cwes = []
    for w in c.get('weaknesses', []):
        for d in w.get('description', []):
            if d.get('value', '').startswith('CWE-'):
                cwes.append(d['value'])
    refs = [r.get('url') for r in c.get('references', []) if r.get('url')]
    # CPE → 产品名 + 版本范围
    product, ver = None, None
    vers = set()
    for conf in c.get('configurations', []):
        for node in conf.get('nodes', []):
            for m in node.get('cpeMatch', []):
                crit = m.get('criteria', '')
                parts = crit.split(':')
                if len(parts) > 5 and parts[2] == 'a':
                    if not product:
                        product = f'{parts[3].replace("_", " ").title()} {parts[4].replace("_", " ").title()}'.strip()
                    ve = m.get('versionEndExcluding') or m.get('versionEndIncluding')
                    if ve:
                        vers.add(f'≤ {ve}')
                    elif parts[5] not in ('*', '-'):
                        vers.add(f'= {parts[5]}')
    if vers:
        ver = ' / '.join(sorted(vers)[:3])
    return {'id': c.get('id'), 'desc': desc, 'score': score, 'cwes': cwes,
            'refs': refs, 'product': product, 'ver': ver,
            'published': c.get('published', '')}

def vuln_type(cwes, desc):
    """(中文类型标签, POC 表 type key)"""
    for cwe in cwes:
        if cwe in CWE_MAP:
            return CWE_MAP[cwe]
    low = desc.lower()
    for pat, val in KW_MAP:
        if re.search(pat, low):
            return val
    return ('新披露', 'leak')

# ---------------- 组装 ----------------
def build(repos, kev):
    """三个源 → 前端 schema"""
    nvd = fetch_nvd()
    if nvd is None and not repos:
        return None  # 什么都没有 → 不写文件

    # POC 仓库按 CVE 聚合
    poc_by_cve = {}
    for r in (repos or []):
        cid = cve_id_of(r.get('full_name') or '') or cve_id_of(r.get('description') or '')
        if cid:
            poc_by_cve.setdefault(cid, []).append(r)
    kev = kev or {}

    items, seen = [], set()
    nvd_sorted = sorted(nvd or [],
                        key=lambda v: v.get('cve', v).get('published', ''),
                        reverse=True)          # 最新在前，截取才有意义
    for v in nvd_sorted:
        f = nvd_fields(v)
        if not f['id'] or f['id'] in seen:
            continue
        seen.add(f['id'])
        reps = poc_by_cve.get(f['id'], [])
        sev = sev_of(f['score'])
        is_kev = f['id'] in kev
        poc = 'exploited' if is_kev else ('poc' if reps else 'none')
        zh, _ = vuln_type(f['cwes'], f['desc'])
        prod = f['product'] or (kev.get(f['id']) or {}).get('product') or ''
        d = f['desc'].strip().replace('\n', ' ')
        def cut(s, n):
            return s if len(s) <= n else s[:n].rsplit(' ', 1)[0] + '…'
        title = (f'{prod} — {cut(d, 100)}' if prod else cut(d, 130)) or f'{f["id"]} 新披露'
        tag_list = [zh] + ([prod.split()[0]] if prod else []) + \
                   (['在野利用'] if is_kev else (['POC 公开'] if reps else ['新披露']))
        tag_list = list(dict.fromkeys(tag_list))[:3]   # 去重保序
        ai = (f'CVSS {f["score"]:.1f}（{SEV_LABEL[sev]}）。'
              if f['score'] is not None else '暂无 CVSS 评分。')
        if is_kev:
            ai += '已列入 CISA 在野利用清单（KEV），建议立即处置。'
        elif reps:
            ai += 'GitHub 已出现公开 POC 仓库，建议 48 小时内评估。'
        else:
            ai += '暂无公开 POC，按常规补丁窗口安排。'
        ai += f' 影响版本：{f["ver"] or "详见公告"}。'
        items.append({
            'id': f['id'], 'sev': sev,
            'cvss': round(f['score'], 1) if f['score'] is not None else 0.0,
            'poc': poc,
            'src': 'CISA KEV' if is_kev else 'NVD',
            'time': rel_zh(f['published']),
            'title': title[:160],
            'tags': tag_list[:3],
            'ai': ai,
            'ver': f['ver'] or '详见公告',
            'desc': cut(f['desc'], 900),   # NVD 英文原文描述（详情弹窗用）
            'refs': [u for u in f['refs'] if u.startswith('http')][:6],
            'link': f'https://nvd.nist.gov/vuln/detail/{f["id"]}',
            'pocs': [{'name': r['full_name'], 'lang': r.get('language') or '—',
                      'extra': rel_zh(r.get('pushed_at', '')),
                      'star': star_fmt(r.get('stargazers_count', 0)),
                      'url': r.get('html_url', '#')} for r in reps[:3]],
        })
    # items 已按发布时间新→旧（nvd_sorted），直接截取

    # POC 库表：仓库直接成行
    pocs = []
    nvd_score = {}
    for v in (nvd or []):
        f = nvd_fields(v)
        if f['id']:
            nvd_score[f['id']] = (f['score'], f['cwes'], f['desc'])
    for cid, reps in poc_by_cve.items():
        score, cwes, desc = nvd_score.get(cid, (None, [], ''))
        _, tkey = vuln_type(cwes, desc or (reps[0].get('description') or ''))
        for r in reps[:2]:
            pocs.append({
                'id': cid,
                'sev': sev_of(score) if score is not None else 'med',
                'repo': r['full_name'],
                'prod': (r.get('description') or cid)[:60],
                'type': tkey,
                'lang': r.get('language') or '—',
                'st': 'wild' if cid in kev else 'ok',
                'star': star_fmt(r.get('stargazers_count', 0)),
                'seen': rel_zh(r.get('pushed_at', '')),
                'src': 'GitHub', 'url': r.get('html_url', '#'),
            })
    pocs.sort(key=lambda p: p['star'], reverse=True)

    stats = {
        'new': len(items),
        'poc': sum(1 for i in items if i['poc'] in ('poc', 'exploited')),
    }
    return {
        'generatedAt': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'items': items[:MAX_ITEMS],
        'pocs': pocs[:MAX_POCS],
        'stats': stats,
    }

def main():
    print(f'[{datetime.now(TZ8):%Y-%m-%d %H:%M}] 开始采集（展示时区 UTC+8）')
    repos = fetch_github_repos()   # 先抓 GitHub（额度低，失败影响小）
    kev = fetch_kev()
    out = build(repos, kev)
    if not out or not out['items']:
        print('无有效数据，保留旧 data.json', file=sys.stderr)
        return 0
    os.makedirs(os.path.dirname(os.path.abspath(OUT_PATH)), exist_ok=True)
    with open(OUT_PATH, 'w', encoding='utf-8') as fp:
        json.dump(out, fp, ensure_ascii=False, separators=(',', ':'))
    print(f'  写出 {OUT_PATH}: items={len(out["items"])} '
          f'pocs={len(out["pocs"])} stats={out["stats"]}')
    return 0

if __name__ == '__main__':
    sys.exit(main())
