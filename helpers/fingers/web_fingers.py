import json
import os
from enum import Enum
from os import path


class MatchType(Enum):
    HEADER = "header"
    BODY = "body"
    FAVICON = "favicon"


class MatchItem:
    def __init__(self, mtype: MatchType, matches: dict[str, str]):
        self.match_type = mtype
        self.matches = matches


class FingerPrint:
    def __init__(self,
                 name: str,
                 headers=None,
                 body=None,
                 favicons=None
                 ):
        self.name = name
        self.headers = headers
        self.body = body
        self.favicons = favicons

    def _match_favicon(self, favicon: str = None) -> MatchItem | None:
        if favicon is None:
            return None
        if self.favicons is None:
            return None
        for sv in self.favicons:
            if sv == favicon:
                return MatchItem(MatchType.FAVICON, {favicon: sv})
        return None

    def _match_body(self, body: str = None) -> MatchItem | None:
        if body is None:
            return None
        if self.body is None:
            return None

        matches = {}
        for sv in self.body:
            if sv in body:
                matches[sv] = "<body>"

        if len(matches) == len(self.body):
            return MatchItem(MatchType.BODY, matches)
        return None

    def _match_headers(self, headers: dict = None) -> MatchItem | None:
        if headers is None:
            return None

        if self.headers is None:
            return None

        if type(self.headers) is dict:
            matches = {}
            for key, value in self.headers.items():
                if key in headers:
                    if value in headers[key]:
                        matches[key] = f"{value} <in> {headers[key]}"
            if len(matches) == len(self.headers):
                return MatchItem(MatchType.HEADER, matches)

        elif type(self.headers) is list:
            items = headers.items()
            matches = {}
            for sv in self.headers:
                for index, tv in enumerate([i[1] for i in items]):
                    if sv in tv:
                        matches[list(headers)[index]] = f"{sv} <in> {tv}"
            if len(matches) >= len(self.headers):
                return MatchItem(MatchType.HEADER, matches)

        return None

    def match(self, headers: dict = None, body: str = None, favicon_int: int | str | list[int] | list[str] = None,
              favicon_md5: int | str | list[int] | list[str] = None) -> MatchItem | None:
        matched = self._match_headers(headers)
        if matched is not None:
            return matched

        matched = self._match_body(body)
        if matched is not None:
            return matched

        favs = []
        if type(favicon_int) is str or type(favicon_int) is int:
            favs.append(str(favicon_int))
        elif type(favicon_int) is list:
            for fav in favicon_int:
                favs.append(str(fav))

        if type(favicon_md5) is str or type(favicon_md5) is int:
            favs.append(str(favicon_md5))
        elif type(favicon_md5) is list:
            for fav in favicon_md5:
                favs.append(str(fav))

        for fav in favs:
            matched = self._match_favicon(favicon_md5)
            if matched is not None:
                return matched

        return None

    def __repr__(self):
        return f"FingerPrint(name={self.name!r}, headers={self.headers!r}, body={self.body!r}, favicons={self.favicons!r})"


class WebFingers:
    fingers: [FingerPrint] = []

    def __init__(self, base_path=os.path.dirname(__file__)):
        self.base_path = base_path
        self.fingers = self._parse_arl_fingers() + self._parse_web_fingerprint()

    def match(self, headers: dict = None, body: str = None, favicon_int: int | str | list[int] | list[str] = None,
              favicon_md5: int | str | list[int] | list[str] = None) -> \
            [MatchItem]:
        matched = []
        for finger in self.fingers:
            matechitem = finger.match(headers, body, favicon_int, favicon_md5)
            if matechitem is not None:
                matched.append(matechitem)
        return matched

    def _parse_web_fingerprint(self) -> [FingerPrint]:
        fingers = []
        # https://github.com/0x727/FingerprintHub/
        with open(path.join(self.base_path, 'assets/web_fingerprint_v3.json'), encoding='utf-8') as f:
            data = json.load(f)
            for item in data:
                if item['request_data'] != "":
                    continue
                elif item['request_method'] != "get":
                    continue
                elif item['path'] != "/":
                    continue

                finger = FingerPrint(name=item['name'])
                if len(item['headers']) > 0:
                    finger.headers = item['headers']
                if len(item['keyword']) > 0:
                    finger.body = item['keyword']
                if len(item['favicon_hash']) > 0:
                    finger.favicons = item['favicon_hash']

                fingers.append(finger)

        return fingers

    def _parse_arl_fingers(self) -> [FingerPrint]:
        # https://github.com/loecho-sec/ARL-Finger-ADD
        datas = []
        with open(path.join(self.base_path, 'assets/arl_finger.json'), encoding='utf-8') as f:
            data = json.load(f)
            datas += data['fingerprint']
        # https://github.com/EASY233/Finger/
        with open(path.join(self.base_path, 'assets/finger.json'), encoding='utf-8') as f:
            data = json.load(f)
            datas += data['fingerprint']

        fingers = []
        for item in datas:
            finger = FingerPrint(name=item['cms'])
            if item['method'] == "keyword":
                if item['location'] == "header":
                    finger.headers = item['keyword']
                else:
                    finger.body = item['keyword']
            elif item['method'] == "faviconhash":
                finger.favicons = item['keyword']
            else:
                continue
            fingers.append(finger)

        return fingers
