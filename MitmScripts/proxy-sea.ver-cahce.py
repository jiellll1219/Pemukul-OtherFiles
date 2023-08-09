from mitmproxy import http
from mitmproxy import ctx
from mitmproxy.proxy import layer, layers

from hashlib import sha256
from mitmproxy.tools.main import mitmdump
import os
import requests
from urllib.parse import urlparse, urlunparse

def hash_url(url: str) -> str:
  url = urlparse(url)._replace(query='')
  url = urlunparse(url)
  return 'cache/' + sha256(url.encode('utf-8')).hexdigest()

def load(loader):
    # ctx.options.web_open_browser = False
    # We change the connection strategy to lazy so that next_layer happens before we actually connect upstream.
    ctx.options.connection_strategy = "lazy"
    ctx.options.upstream_cert = False
    ctx.options.ssl_insecure = True
    
def next_layer(nextlayer: layer.NextLayer):
    # ctx.log(
    #     f"{nextlayer.context=}\n"
    #     f"{nextlayer.data_client()[:70]=}\n"
    # )
    sni = nextlayer.context.client.sni
    if sni and (sni.endswith("yuanshen.com") or sni.endswith("mihoyo.com") or sni.endswith("hoyoverse.com") or sni.endswith("starrails.com") or sni.endswith("bhsr.com") or sni.endswith("kurogame.com") or sni.endswith("zenlesszonezero.com") or sni.endswith("api.g3.proletariat.com") or sni.endswith("global01.os.honkaiimpact3.com") or sni.endswith("overseas01-appsflyer-report.honkaiimpact3.com") or sni.endswith("westglobal01.honkaiimpact3.com") or sni.endswith("bh3.com") and not (sni.endswith("bundle.bh3.com") or sni.endswith("qcloud.bh3.com") or sni.endswith("bh3rd-beta.bh3.com") or sni.endswith('global1.bh3.com'))):
        ctx.log('sni:' + sni)
        nextlayer.context.server.address = ("127.0.0.1", 443)

def request(flow: http.HTTPFlow) -> None:
    # flow.request.scheme = "http"
    
    # pretty_host takes the "Host" header of the request into account
    if flow.request.pretty_url.startswith('http://global01.west.honkaiimpact3.com') or flow.request.pretty_url.startswith('http://global1.bh3.com'):
        flow.request.host = "127.0.0.1"
        flow.request.headers["Host"] = "127.0.0.1"
    if flow.request.pretty_url.startswith('http://log-upload-os.mihoyo.com') or flow.request.pretty_url.startswith('http://client-report.bh3.com'):
        flow.response = http.Response.make(
            404,  # (optional) status code
            b"404 not found",  # (optional) content
            {"Content-Type": "text/html"}  # (optional) headers
        )
        return

def request(flow: http.HTTPFlow) -> None:
  host = flow.request.host
  if host == '127.0.0.1' and flow.request.port == 8080:
    flow.request.url = flow.request.url.replace('127.0.0.1:8080', 'hk-bundle-west-mihayo.akamaized.net')
    host = flow.request.host
  if host == 'hk-bundle-west-mihayo.akamaized.net':
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