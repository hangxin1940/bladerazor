import re

import tiktoken
from ipaddress import ip_address, IPv4Address, IPv6Address

import validators
from validators.domain import _iana_tld


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


def is_domain(
    value: str, /, *, consider_tld: bool = False, rfc_1034: bool = False, rfc_2782: bool = False
):
    """Return whether or not given value is a valid domain.

    Examples:
        >>> domain('example.com')
        # Output: True
        >>> domain('example.com/')
        # Output: ValidationError(func=domain, ...)
        >>> # Supports IDN domains as well::
        >>> domain('xn----gtbspbbmkef.xn--p1ai')
        # Output: True

    Args:
        value:
            Domain string to validate.
        consider_tld:
            Restrict domain to TLDs allowed by IANA.
        rfc_1034:
            Allows optional trailing dot in the domain name.
            Ref: [RFC 1034](https://www.rfc-editor.org/rfc/rfc1034).
        rfc_2782:
            Domain name is of type service record.
            Allows optional underscores in the domain name.
            Ref: [RFC 2782](https://www.rfc-editor.org/rfc/rfc2782).


    Returns:
        (Literal[True]): If `value` is a valid domain name.
        (ValidationError): If `value` is an invalid domain name.

    Raises:
        (UnicodeError): If `value` cannot be encoded into `idna` or decoded into `utf-8`.
    """
    sr = validators.domain(value, consider_tld=consider_tld, rfc_1034=rfc_1034, rfc_2782=rfc_2782)
    if sr is True:
        return True

    if not value:
        return False

    if consider_tld and value.rstrip(".").rsplit(".", 1)[-1].upper() not in _iana_tld():
        return False

    try:

        service_record = r"_" if rfc_2782 else ""
        trailing_dot = r"\.?$" if rfc_1034 else r"$"

        return re.match(
            # First character of the domain
            rf"^(?:[a-z0-9{service_record}]"
            # Sub-domain
            + rf"(?:[a-z0-9-{service_record}]{{0,61}}"
            # Hostname
            + rf"[a-z0-9{service_record}])?\.)"
            # First 61 characters of the gTLD
            + r"+[a-z0-9][a-z0-9-_]{0,61}"
            # Last character of the gTLD
            + rf"[a-z]{trailing_dot}",
            value.encode("idna").decode("utf-8"),
            re.IGNORECASE,
        )
    except UnicodeError as err:
        raise UnicodeError(f"Unable to encode/decode {value}") from err