#!/usr/bin/python
from hashlib import sha256
from mitmproxy import http, ctx
from mitmproxy.tools.main import mitmdump
import os
import requests
from urllib.parse import urlparse, urlunparse
def hash_url(url: str) -> str:
  url = urlparse(url)._replace(query='')
  url = urlunparse(url)
  return 'cache/' + sha256(url.encode('utf-8')).hexdigest()

def load(loader: http.HTTPFlow) -> None:
  ctx.options.connection_strategy = 'lazy'
  ctx.options.upstream_cert = False

def request(flow: http.HTTPFlow) -> None:
  host = flow.request.host
  if host == '127.0.0.1' and flow.request.port == 8080:
    #flow.request.url = flow.request.url.replace('127.0.0.1:8080', 'hk-bundle-west-mihayo.akamaized.net')
    flow.request.url = flow.request.url.replace('127.0.0.1:8080', 'bundle.bh3.com')
    host = flow.request.host
  #if host == 'hk-bundle-west-mihayo.akamaized.net':
  if host == 'bundle.bh3.com':
    path = hash_url(flow.request.url)
    if not os.path.exists(path):
      print('Cache miss on ' + flow.request.url)
      os.makedirs('cache', exist_ok=True)
      session = requests.Session()
      session.trust_env = False
      res = session.get(flow.request.url)
      with open(path, 'wb') as f:
        f.write(res.content)
    with open(path, 'rb') as file:
      flow.response = http.Response.make(200, file.read())
    return
  if host == 'westglobal01.honkaiimpact3.com' or host == 'api-account-os.hoyoverse.com' or host == 'bh3-sdk-os.hoyoverse.com' or host == 'client-report.bh3.com' or host == 'global1.bh3.com' or host == 'api-sdk.mihoyo.com' or host =='minor-api.mihoyo.com' or host =='webstatic.hoyoverse.com' or host =='sg-public-data-api.hoyoverse.com':
    flow.request.host = '127.0.0.1'
    flow.request.port = 80
    flow.request.scheme = 'http'
    return
  flow.kill()
if __name__ == '__main__':
  mitmdump(['-s', 'proxy.py'])
