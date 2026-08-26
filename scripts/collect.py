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
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

# ---------------- 配置 ----------------
NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
GH_SEARCH_URL = 'https://api.github.com/search/repositories'
KEV_URL = ('https://www.cisa.gov/sites/default/files/feeds/'
           'known_exploited_vulnerabilities.json')
OUT_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'data.json')
RSS_PATH = os.path.join(os.path.dirname(__file__), '..', 'rss.xml')
SITE_URL = 'https://fidjiw.github.io/vulnwire/'

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
        except urllib.error.HTTPError as e:
            if e.code == 404:                 # 资源不存在,重试无意义(OSV 未收录等)
                return None
            last = e
            if i < tries - 1:
                time.sleep(3 * (i + 1))
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
    def ref_label(tags):
        """NVD 参考标签 → 中文徽标（详情弹窗相关参考用）"""
        if 'Patch' in tags:
            return '补丁'
        if 'Vendor Advisory' in tags:
            return '厂商公告'
        if 'Exploit' in tags:
            return 'Exploit'
        return ''
    refs = [{'u': r.get('url'), 'l': ref_label(r.get('tags') or [])}
            for r in c.get('references', []) if r.get('url')]
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

# ---------------- OSV 版本补全 ----------------
OSV_URL = 'https://api.osv.dev/v1/vulns/'

def osv_enrich(items):
    """NVD 未给出 CPE 版本时查 OSV(GHSA),返回 {id: (ver, 生态标签)};失败静默降级"""
    want = [it for it in items if not it.get('ver') or it.get('ver') == '详见公告']
    if not want:
        return {}
    out = {}
    for it in want[:40]:                    # 每小时最多 40 次查询,控总量
        d = http_json(OSV_URL + it['id'], tries=2)
        if not d:
            continue
        for aff in (d.get('affected') or [])[:3]:
            pkg = aff.get('package') or {}
            eco = (pkg.get('ecosystem') or '').split(':')[0]
            name = pkg.get('name') or ''
            rng = next((r for r in (aff.get('ranges') or [])
                        if r.get('type') in ('ECOSYSTEM', 'SEMVER')
                        and r.get('events')), None)
            if rng:
                ev = rng['events']
                intro = next((e['introduced'] for e in ev
                              if e.get('introduced') and e['introduced'] != '0'), '')
                fixed = next((e['fixed'] for e in ev if e.get('fixed')), '')
                parts = []
                if intro:
                    parts.append('≥ ' + str(intro))
                if fixed:
                    parts.append('< ' + str(fixed))
                if not parts:
                    continue
                ver = ' '.join(x for x in (eco, name, ' / '.join(parts)) if x)
                out[it['id']] = (ver, eco)
                break
            if aff.get('versions'):
                ver = ' '.join(x for x in (eco, name,
                                           ' / '.join(map(str, aff['versions'][:3]))) if x)
                out[it['id']] = (ver, eco)
                break
    print(f'  OSV 版本补全：{len(out)}/{len(want)} 条')
    return out

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
        if any(r['l'] == '补丁' for r in f['refs']):
            ai += ' 官方补丁已发布，见「相关参考」。'
        items.append({
            'id': f['id'], 'sev': sev,
            'cvss': round(f['score'], 1) if f['score'] is not None else 0.0,
            'poc': poc,
            'src': 'CISA KEV' if is_kev else 'NVD',
            'time': rel_zh(f['published']),
            'pub': f['published'],     # ISO 绝对时间（历史档案展示用）
            'title': title[:160],
            'tags': tag_list[:3],
            'ai': ai,
            'ver': f['ver'] or '详见公告',
            'desc': cut(f['desc'], 900),   # NVD 英文原文描述（详情弹窗用）
            'refs': [r for r in f['refs'] if r['u'].startswith('http')][:6],
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

# ---------------- 历史档案 ----------------
HIST_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'history.json')
HIST_MAX = 3000
HIST_FIELDS = ('id', 'sev', 'cvss', 'poc', 'src', 'time', 'pub', 'title',
               'titleZh', 'zh', 'zhBy', 'ai', 'tags', 'ver', 'link')

def load_history():
    try:
        with open(HIST_PATH, encoding='utf-8') as fp:
            h = json.load(fp)
        return h if isinstance(h.get('items'), list) else {'items': []}
    except Exception:  # noqa: BLE001 — 无档案/损坏都按冷启动处理
        return {'items': []}

def slim(it):
    """历史条目只留搜索与展示需要的字段（不带 desc/refs/pocs，控制体积）"""
    e = {k: it.get(k) for k in HIST_FIELDS if it.get(k) not in (None, '')}
    e['id'] = it['id']
    return e

# ---------------- AI 中文摘要（GLM） ----------------
def glm_url():
    """GLM 端点：GLM_BASE_URL 可覆盖为官方地址或任意 OpenAI 兼容中转"""
    base = os.environ.get('GLM_BASE_URL',
                          'https://open.bigmodel.cn/api/paas/v4').rstrip('/')
    return base if base.endswith('/chat/completions') else base + '/chat/completions'

def ai_summarize(pending):
    """批量生成中文标题 + 摘要，返回 {id: (titleZh, zh)}；无 key / 失败返回部分结果"""
    key = os.environ.get('GLM_API_KEY')
    if not key or not pending:
        return {}
    url = glm_url()
    model = os.environ.get('GLM_MODEL', 'glm-4-flash')
    out = {}
    for k in range(0, len(pending), 8):   # 每批 8 条
        batch = pending[k:k + 8]
        payload = [{'i': it['id'], 'en': it['title'][:120],
                    'desc': (it.get('desc') or '')[:500]} for it in batch]
        prompt = ('你是漏洞情报编辑。对每个漏洞给出简体中文标题（≤36字，产品名+漏洞类型）'
                  '和 2-3 句中文摘要（漏洞影响、利用条件、处置要点）。'
                  '只返回 JSON 数组，每项 {"i":"CVE编号","t":"中文标题","s":"中文摘要"}：\n'
                  + json.dumps(payload, ensure_ascii=False))
        body = json.dumps({'model': model, 'temperature': 0.2,
                           'max_tokens': 1800,
                           'messages': [{'role': 'user', 'content': prompt}]}).encode()
        req = urllib.request.Request(url, data=body, headers={
            'Authorization': f'Bearer {key}',
            'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=90) as r:
                txt = json.loads(r.read().decode())['choices'][0]['message']['content']
            m = re.search(r'\[.*\]', txt, re.S)
            if not m:
                continue
            for e in json.loads(m.group(0)):
                if e.get('i') and e.get('s'):
                    out[e['i']] = (str(e.get('t', ''))[:60], str(e['s'])[:200])
        except Exception as ex:  # noqa: BLE001 — 单批失败不拖垮整轮采集
            print(f'  ! AI 摘要批次失败：{ex}', file=sys.stderr)
    print(f'  AI 摘要：{len(out)}/{len(pending)} 条')
    return out

# ---------------- DeepL 翻译备选 ----------------
def deepl_url(key):
    """DeepL 端点：DEEPL_BASE_URL 可覆盖为自建代理；默认按 key 后缀自动选 free/pro"""
    base = os.environ.get('DEEPL_BASE_URL')
    if base:
        base = base.rstrip('/')
        return base if base.endswith('/v2/translate') else base + '/v2/translate'
    return ('https://api-free.deepl.com/v2/translate' if key.endswith(':fx')
            else 'https://api.deepl.com/v2/translate')

def deepl_translate(pending):
    """GLM 之外的兜底:DeepL 翻译标题+描述,返回 {id: (titleZh, zh)}"""
    key = os.environ.get('DEEPL_KEY')
    if not key or not pending:
        return {}
    url = deepl_url(key)
    out = {}
    for k in range(0, len(pending), 20):   # 每批 20 条(每条 2 段文本)
        batch = pending[k:k + 20]
        texts = []
        for it in batch:
            texts.append(it['title'][:200])
            texts.append((it.get('desc') or it['title'])[:450])
        body = json.dumps({'text': texts, 'target_lang': 'ZH'}).encode()
        req = urllib.request.Request(url, data=body, headers={
            'Authorization': f'DeepL-Auth-Key {key}',
            'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                ts = json.loads(r.read().decode())['translations']
            for i, it in enumerate(batch):
                t = ts[2 * i]['text'].strip()[:80]
                s = ts[2 * i + 1]['text'].strip()[:300]
                if t:
                    out[it['id']] = (t, s)
        except Exception as ex:  # noqa: BLE001
            print(f'  ! DeepL 批次失败：{ex}', file=sys.stderr)
    print(f'  DeepL 翻译：{len(out)}/{len(pending)} 条')
    return out

# ---------------- 订阅推送 ----------------
def send_text(text):
    """文本 → Telegram Bot + 飞书 webhook;未配置静默跳过"""
    tg_tok, tg_chat = os.environ.get('TG_BOT_TOKEN'), os.environ.get('TG_CHAT_ID')
    if tg_tok and tg_chat:
        try:
            body = json.dumps({'chat_id': tg_chat, 'text': text}).encode()
            req = urllib.request.Request(
                f'https://api.telegram.org/bot{tg_tok}/sendMessage', data=body,
                headers={'Content-Type': 'application/json'})
            urllib.request.urlopen(req, timeout=30)
            print('  推送 Telegram：OK')
        except Exception as ex:  # noqa: BLE001
            print(f'  ! Telegram 推送失败：{ex}', file=sys.stderr)
    fs = os.environ.get('FEISHU_WEBHOOK')
    if fs:
        try:
            body = json.dumps({'msg_type': 'text',
                               'content': {'text': text}}).encode()
            req = urllib.request.Request(fs, data=body,
                                         headers={'Content-Type': 'application/json'})
            urllib.request.urlopen(req, timeout=30)
            print('  推送飞书：OK')
        except Exception as ex:  # noqa: BLE001
            print(f'  ! 飞书推送失败：{ex}', file=sys.stderr)

def push_notify(new_items):
    """新增 crit/high/在野利用 → Telegram Bot + 飞书 webhook"""
    hits = [i for i in new_items
            if i['sev'] in ('crit', 'high') or i['poc'] == 'exploited'][:10]
    if not hits:
        return
    lines = [f'🔴 VulnWire 新增高危漏洞 {len(hits)} 条']
    for i in hits:
        name = i.get('titleZh') or i['title'][:60]
        lines.append(f"▪ {i['id']}〔{SEV_LABEL[i['sev']]}〕{name}\n  {i['link']}")
    send_text('\n'.join(lines)[:3800])

# ---------------- RSS 输出 ----------------
def write_rss(items):
    """情报流 → 根目录 rss.xml(≤30 条),供订阅器与浏览器自动发现"""
    def x(s):
        return (str(s or '')).replace('&', '&amp;').replace('<', '&lt;') \
            .replace('>', '&gt;').replace('"', '&quot;')
    rows = []
    for it in items[:30]:
        try:
            dt = format_datetime(datetime.fromisoformat(
                (it.get('pub') or '').replace('Z', '+00:00')).astimezone(timezone.utc))
        except Exception:  # noqa: BLE001 — 无有效时间就不输出 pubDate
            dt = ''
        title = f"{it['id']}〔{SEV_LABEL[it['sev']]}〕{it.get('titleZh') or it['title']}"
        desc = it.get('zh') or it.get('ai') or it.get('title') or ''
        rows.append(
            '<item><title>' + x(title) + '</title>'
            '<link>' + x(it['link']) + '</link>'
            '<guid>' + x(it['link']) + '</guid>'
            + (f'<pubDate>{dt}</pubDate>' if dt else '') +
            '<description>' + x(desc) + '</description></item>')
    xml = ('<?xml version="1.0" encoding="UTF-8"?>\n'
           '<rss version="2.0"><channel>'
           '<title>漏讯 VulnWire · 实时漏洞情报</title>'
           f'<link>{SITE_URL}</link>'
           '<description>NVD / GitHub POC / CISA KEV 每小时聚合，附 AI 中文摘要</description>'
           '<language>zh-CN</language>'
           f'<lastBuildDate>{format_datetime(datetime.now(timezone.utc))}</lastBuildDate>'
           + ''.join(rows) + '</channel></rss>\n')
    with open(RSS_PATH, 'w', encoding='utf-8') as fp:
        fp.write(xml)
    print(f'  写出 {RSS_PATH}: {len(rows)} 条')

def main():
    print(f'[{datetime.now(TZ8):%Y-%m-%d %H:%M}] 开始采集（展示时区 UTC+8）')
    repos = fetch_github_repos()   # 先抓 GitHub（额度低，失败影响小）
    kev = fetch_kev()
    out = build(repos, kev)
    if not out or not out['items']:
        print('无有效数据，保留旧 data.json', file=sys.stderr)
        # 数据滞留告警：所有源都挂了要让人知道（页面只会显示旧数据）
        send_text('⚠️ VulnWire 采集失败：所有数据源不可达，已保留旧数据。'
                  f'（{datetime.now(TZ8):%m-%d %H:%M}）')
        return 0

    # OSV 补全：NVD 未给出 CPE 版本时，用 OSV 结构化范围填影响版本
    osv_fix = osv_enrich(out['items'])
    for it in out['items']:
        fix = osv_fix.get(it['id'])
        if fix:
            it['ver'], eco = fix
            it['ai'] = it['ai'].replace('影响版本：详见公告', f'影响版本：{it["ver"]}')
            if eco and eco not in it['tags']:
                it['tags'] = (it['tags'] + [eco])[:4]

    # 历史档案：命中缓存的复用 AI 摘要，其余调 GLM 生成
    cold_start = not os.path.exists(HIST_PATH)
    old = load_history()
    old_by_id = {h['id']: h for h in old['items']}
    zh = {cid: (h['titleZh'], h['zh']) for cid, h in old_by_id.items() if h.get('zh')}
    pending = [it for it in out['items'] if it['id'] not in zh]
    glm = ai_summarize(pending)                       # GLM 优先(摘要质量高)
    rest = [it for it in pending if it['id'] not in glm]
    dl = deepl_translate(rest)                        # DeepL 兜底(GLM 失败/缺 key)
    zh.update(glm)
    zh.update(dl)
    for it in out['items']:
        pair = zh.get(it['id'])
        if pair:
            it['titleZh'], it['zh'] = pair
            if it['id'] in glm:
                it['zhBy'] = 'glm'
            elif it['id'] in dl:
                it['zhBy'] = 'deepl'
    new_ids = {it['id'] for it in out['items'] if it['id'] not in old_by_id}

    os.makedirs(os.path.dirname(os.path.abspath(OUT_PATH)), exist_ok=True)
    with open(OUT_PATH, 'w', encoding='utf-8') as fp:
        json.dump(out, fp, ensure_ascii=False, separators=(',', ':'))
    print(f'  写出 {OUT_PATH}: items={len(out["items"])} '
          f'pocs={len(out["pocs"])} stats={out["stats"]}')
    write_rss(out['items'])

    # 合并历史：窗口内条目字段刷新（保 firstSeen），窗口外原样保留，新→旧截断
    now_iso = datetime.now(timezone.utc).isoformat(timespec='seconds')
    merged = {}
    for it in out['items']:
        e = slim(it)
        e['firstSeen'] = old_by_id.get(it['id'], {}).get('firstSeen', now_iso)
        merged[it['id']] = e
    for h in old['items']:
        merged.setdefault(h['id'], h)
    hist_items = sorted(merged.values(),
                        key=lambda x: x.get('firstSeen', ''), reverse=True)[:HIST_MAX]
    with open(HIST_PATH, 'w', encoding='utf-8') as fp:
        json.dump({'updatedAt': now_iso, 'items': hist_items},
                  fp, ensure_ascii=False, separators=(',', ':'))
    print(f'  历史档案：{len(hist_items)} 条（本轮新增 {len(new_ids)}）')

    # 订阅推送（冷启动不推，避免建档时一次性轰炸）
    if not cold_start and new_ids:
        push_notify([it for it in out['items'] if it['id'] in new_ids])
    return 0

if __name__ == '__main__':
    sys.exit(main())
