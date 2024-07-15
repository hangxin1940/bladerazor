import base64
import hashlib
from urllib.parse import urlparse, urlunparse, urljoin

import httpx
import mmh3
from bs4 import BeautifulSoup
from config import logger

AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.79 Safari/537.36'


class Favicon:
    def __init__(self, b64data: str, md5hash: str, mmh3hash: int):
        self.b64data = b64data
        self.md5hash = md5hash
        self.mmh3hash = mmh3hash

    def __eq__(self, other):
        return self.md5hash == other.md5hash

    def __hash__(self):
        return hash(self.md5hash)

    def to_dict(self):
        return {
            'b64data': self.b64data,
            'md5hash': self.md5hash,
            'mmh3hash': self.mmh3hash
        }

    def __repr__(self) -> str:
        return f"Favicon(md5hash={self.md5hash!r}, mmh3hash={self.mmh3hash!r})"


class HttpHtml:
    def __init__(self,
                 host: str,
                 url: str,
                 schema: str,
                 title: str,
                 headers: dict,
                 status: int,
                 body: str,
                 current_redirects: int = 0,
                 redirect_to: str = None,
                 favicons: [Favicon] = None,
                 ip=None,
                 port=None,
                 certs=None):
        self.host = host
        self.url = url
        self.schema = schema
        self.current_redirects = current_redirects
        self.redirect_to = redirect_to
        self.favicons = favicons
        self.title = title
        self.headers = headers
        self.status = status
        self.body = body
        self.ip = ip
        self.port = port
        self.certs = certs

    def __repr__(self) -> str:
        return f"HttpHtml(host={self.host!r}, favicons={self.favicons!r}, headers={self.headers!r}, title={self.title!r})"


def _get_favicon_hash(url: str) -> Favicon | None:
    try:
        with httpx.Client(headers={'User-Agent': AGENT}, timeout=5, verify=False) as client:
            res = client.get(url)
            if res.status_code != 200:
                return None
            if len(res.content) == 0:
                return None
            b64data = base64.encodebytes(res.content)
            md5data = hashlib.md5(res.content).hexdigest()
            mmh3hash = mmh3.hash(b64data)

            favicon = Favicon(b64data.decode("utf-8"), md5data, mmh3hash)

            return favicon
    except httpx.RequestError as e:
        return None


LINK_RELS = [
    'icon',
    'shortcut icon',
    'apple-touch-icon',
    'apple-touch-icon-precomposed',
]

META_NAMES = ['msapplication-TileImage', 'og:image']


def _get_favicons_urls(host: str, body: str) -> [str]:
    soup = BeautifulSoup(body, features='html.parser')
    link_tags = set()
    for rel in LINK_RELS:
        for link_tag in soup.find_all(
                'link', attrs={'rel': lambda r: r and r.lower() == rel, 'href': True}
        ):
            link_tags.add(link_tag)

    meta_tags = set()
    for meta_tag in soup.find_all('meta', attrs={'content': True}):
        meta_type = meta_tag.get('name') or meta_tag.get('property') or ''
        meta_type = meta_type.lower()
        for name in META_NAMES:
            if meta_type == name.lower():
                meta_tags.add(meta_tag)

    urls = set()
    hu = urlparse(host)
    urls.add(urlunparse((hu.scheme, hu.netloc, 'favicon.ico', '', '', '')))

    for tag in link_tags | meta_tags:
        href = tag.get('href', '') or tag.get('content', '')
        href = href.strip()

        if not href or href.startswith('data:image/'):
            continue

        if bool(urlparse(href).netloc):
            url_parsed = href
        else:
            url_parsed = urljoin(host, href)

        # repair '//cdn.network.com/favicon.png' or `icon.png?v2`
        scheme = urlparse(host).scheme
        url_parsed = urlparse(url_parsed, scheme=scheme)
        urls.add(urlunparse((url_parsed.scheme, url_parsed.netloc, url_parsed.path, '', '', '')))

    return list(urls)


def _get_favicons_from_urls(urls: [str]) -> [Favicon]:
    favicons = set()
    if urls is None or len(urls) == 0:
        return favicons
    for url in urls:
        logger.debug("crawl_host: favicon {}", url)
        favicon = _get_favicon_hash(url)
        if favicon is not None:
            favicons.add(favicon)
    return list(favicons)


def crawl_host(host: str) -> [HttpHtml]:
    """
    从host获取html
    :param host: 要抓取的主机地址
    :return: 包含HttpHtml对象的列表，每个对象都是从一次HTTP请求中获得的HTML和相关信息
    """
    logger.debug("crawl_host: {}", host)
    MAX_REDIRECTS = 3  # 定义最大重定向次数

    def fetch_url(url, current_redirects=0) -> [HttpHtml]:
        """
        辅助函数，用于处理单个URL的获取和重定向
        :param url: 请求的URL
        :param current_redirects: 当前重定向次数
        :return: 收集的Html对象列表
        """
        if current_redirects > MAX_REDIRECTS:
            logger.debug("crawl_host: Reached max redirects: {}", MAX_REDIRECTS)
            return []

        with httpx.Client(headers={'User-Agent': AGENT}, timeout=5, verify=False) as client:
            res = client.get(url)
            socket = res.stream._stream._httpcore_stream._stream._connection._network_stream._sock
            try:
                server_ip, server_port = socket.getpeername()
            except OSError:
                server_ip, server_port = None, None

            certs = None
            if hasattr(socket, '_sslobj') and socket._sslobj:
                certs = [c.get_info() for c in socket._sslobj.get_unverified_chain()]

            title = ''
            if res.content:
                soup = BeautifulSoup(res.content, features='html.parser')
                if soup.title:
                    title = str(soup.title.string)
            htmlobj = HttpHtml(
                host=res.url.host,
                url=str(res.url),
                schema=res.url.scheme,
                title=title,
                headers=dict(res.headers),
                status=res.status_code,
                body=res.text,
                ip=server_ip,
                port=server_port,
                certs=certs
            )

        favicons_url = _get_favicons_urls(htmlobj.url, htmlobj.body)
        htmlobj.favicons = _get_favicons_from_urls(favicons_url)
        htmlobj.current_redirects = current_redirects
        htmls = [htmlobj]

        # 处理重定向
        if res.is_redirect:
            new_url = httpx.URL(res.headers['Location'])
            if new_url.is_relative_url:
                new_url = res.url.join(new_url)
            htmlobj.redirect_to = str(new_url)
            logger.debug("crawl_host: Redirecting to: {}", htmlobj.redirect_to)
            htmls += fetch_url(htmlobj.redirect_to, current_redirects + 1)

        return htmls

    return fetch_url(host)
