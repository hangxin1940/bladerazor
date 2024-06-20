import tiktoken
from ipaddress import ip_address, IPv4Address, IPv6Address


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
