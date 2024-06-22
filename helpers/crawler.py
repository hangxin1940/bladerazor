import base64
import hashlib
from urllib.parse import urlparse, urlunparse, urljoin

import urllib3

urllib3.disable_warnings()
import mmh3
import requests
from bs4 import BeautifulSoup

from helpers.utils import new_lowsec_requests_session

AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.5112.79 Safari/537.36'


class Favicon:
    def __init__(self, b64data: str, md5hash: str, inthash: int):
        self.b64data = b64data
        self.md5hash = md5hash
        self.inthash = inthash

    def __eq__(self, other):
        return self.md5hash == other.md5hash

    def __hash__(self):
        return hash(self.md5hash)

    def __repr__(self) -> str:
        return f"Favicon(md5hash={self.md5hash!r}, inthash={self.inthash!r})"


class HttpHtml:
    def __init__(self, host: str, favicons: [Favicon], title: str, headers: dict, status: int, body: str):
        self.host = host
        self.favicons = favicons
        self.title = title
        self.headers = headers
        self.status = status
        self.body = body

    def __repr__(self) -> str:
        return f"HttpHtml(host={self.host!r}, favicons={self.favicons!r}, headers={self.headers!r}, title={self.title!r})"


def _get_favicon_hash(url: str) -> Favicon | None:
    try:
        session = new_lowsec_requests_session()
        res = session.get(url, headers={'User-Agent': AGENT}, timeout=5, allow_redirects=True, verify=False)
        if res.status_code != 200:
            return None
        if len(res.content) == 0:
            return None
        b64data = base64.encodebytes(res.content)
        md5data = hashlib.md5(res.content).hexdigest()
        inthash = mmh3.hash(b64data)

        favicon = Favicon(b64data.decode("utf-8"), md5data, inthash)

        return favicon
    except requests.exceptions.RequestException as e:
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
        favicon = _get_favicon_hash(url)
        if favicon is not None:
            favicons.add(favicon)
    return list(favicons)


def crawl_host(host: str) -> HttpHtml:
    """
    从host获取html
    :param host:
    :return:
    """
    session = new_lowsec_requests_session()
    res = session.get(host, headers={'User-Agent': AGENT}, timeout=5, allow_redirects=True, verify=False)

    favicons_url = _get_favicons_urls(host, res.content)
    favicons = _get_favicons_from_urls(favicons_url)
    title = ''
    soup = BeautifulSoup(res.content, features='html.parser')
    if soup.title:
        title = str(soup.title.string)

    html = HttpHtml(host, favicons, title, dict(res.headers), res.status_code, res.text)
    return html
