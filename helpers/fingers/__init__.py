from helpers.fingers.web_fingers import WebFingers, MatchItem

_webFingersObj: WebFingers = WebFingers()


def Match(headers: dict = None, body: str = None, favicon_int: int | str | list[int] | list[str] = None,
          favicon_md5: int | str | list[int] | list[str] = None) -> \
        [MatchItem]:
    return _webFingersObj.match(headers, body, favicon_int, favicon_md5)
