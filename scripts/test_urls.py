#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""URL 解析逻辑单测:GLM/DeepL 自定义 Base URL 的三种书写习惯"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))
import collect  # noqa: E402

cases_glm = [
    ({}, 'https://open.bigmodel.cn/api/paas/v4/chat/completions'),
    ({'GLM_BASE_URL': 'https://relay.example.com/v1'},
     'https://relay.example.com/v1/chat/completions'),
    ({'GLM_BASE_URL': 'https://relay.example.com/v1/chat/completions'},
     'https://relay.example.com/v1/chat/completions'),
    ({'GLM_BASE_URL': 'https://relay.example.com/v1/'},
     'https://relay.example.com/v1/chat/completions'),
]
for env, want in cases_glm:
    for k in list(os.environ):
        if k.startswith('GLM_'):
            del os.environ[k]
    os.environ.update(env)
    got = collect.glm_url()
    assert got == want, f'GLM {env} -> {got}, want {want}'

cases_dl = [
    ({}, 'KEY:fx', 'https://api-free.deepl.com/v2/translate'),
    ({}, 'PROKEY', 'https://api.deepl.com/v2/translate'),
    ({'DEEPL_BASE_URL': 'https://dl-proxy.example.com'}, 'K',
     'https://dl-proxy.example.com/v2/translate'),
    ({'DEEPL_BASE_URL': 'https://dl-proxy.example.com/v2/translate'}, 'K',
     'https://dl-proxy.example.com/v2/translate'),
]
for env, key, want in cases_dl:
    os.environ.pop('DEEPL_BASE_URL', None)
    os.environ.update(env)
    got = collect.deepl_url(key)
    assert got == want, f'DeepL {env} {key} -> {got}, want {want}'

print('URL-RESOLUTION-TESTS: 8/8 PASS')
