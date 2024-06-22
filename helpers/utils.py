import requests
import tiktoken
from ipaddress import ip_address, IPv4Address, IPv6Address

import urllib3

from helpers import CustomSSLContextHTTPAdapter


def num_tokens_from_string(string: str, encoding_name: str) -> int:
    """Returns the number of tokens in a text string."""
    # TODO
    encoding = tiktoken.encoding_for_model(encoding_name)
    num_tokens = len(encoding.encode(string))
    return num_tokens


def valid_ip_address(ip: str) -> bool:
    try:
        return type(ip_address(ip)) is IPv4Address or IPv6Address
    except ValueError:
        return False


def get_ip_type(IP: str) -> str:
    try:
        if type(ip_address(IP)) is IPv4Address:
            return "ipv4"
        else:
            return "ipv6"
    except ValueError:
        return "invalid"


def is_private_ip(ip: str) -> bool:
    try:
        ip_obj = ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False


def new_lowsec_requests_session():
    session = requests.Session()
    ctx = urllib3.util.create_urllib3_context()
    ctx.load_default_certs()
    ctx.check_hostname = False
    ctx.set_ciphers("DEFAULT@SECLEVEL=0")
    session.adapters.pop("https://", None)
    session.mount("https://", CustomSSLContextHTTPAdapter(ssl_context=ctx))
    return session
