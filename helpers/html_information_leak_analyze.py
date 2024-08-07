import re

from bs4 import BeautifulSoup, Comment


def analyze(html: str) -> str:
    soup = BeautifulSoup(html, 'html.parser')
    datas = ""
    puretext = '\n'.join([line.rstrip() for line in soup.get_text(separator='\n').split('\n') if line.rstrip()])

    # 匹配HTML注释
    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
    comments = list(set(comments))
    if len(comments) > 0:
        datas = f"{datas}\n\nHTML注释: {comments}"

    # 匹配隐藏字段
    hidden_fields = [(tag['name'], tag['value']) for tag in soup.find_all('input', type='hidden')]
    hidden_fields = list(set(hidden_fields))
    if len(hidden_fields) > 0:
        datas = f"{datas}\n隐藏字段: {hidden_fields}"

    # 匹配电子邮件地址
    emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', html)
    emails = list(set(emails))
    if len(emails) > 0:
        datas = f"{datas}\nemail地址: {emails}"

    # 匹配文件路径
    file_paths = [tag['src'] for tag in soup.find_all(src=True)] + [tag['href'] for tag in soup.find_all(href=True)]
    file_paths.extend(_find_paths(puretext))
    file_paths = list(set(file_paths))
    if len(file_paths) > 0:
        datas = f"{datas}\n文件路径: {file_paths}"

    # 匹配内部IP地址
    ips = re.findall(
        r'(?:\d|1?\d\d|2[0-4]\d|25[0-5])(?:\.(?:\d|1?\d\d|2[0-4]\d|25[0-5])){3}', html)
    ips = list(set(ips))
    if len(ips) > 0:
        datas = f"{datas}\nIP地址: {ips}"

    # 匹配meta标签中的信息
    meta_tags = [f"{tag['name']}={tag['content']}" for tag in
                 soup.find_all('meta', attrs={'name': True, 'content': True})]
    meta_tags = list(set(meta_tags))
    if len(meta_tags) > 0:
        datas = f"{datas}\nmeta标签中的信息: {meta_tags}"

    # 匹配表单字段
    form_fields = [(tag['name'], tag['value']) for tag in
                   soup.find_all('input', attrs={'name': True, 'value': True})]
    form_fields = list(set(form_fields))
    if len(form_fields) > 0:
        datas = f"{datas}\n表单字段: {form_fields}"

    if puretext != "":
        datas = f"{datas}\n\n纯文本内容:\n`{puretext}`"

    datas = datas.strip()


def _find_paths(text: str) -> []:
    # 正则表达式模式，用于匹配潜在的路径信息
    path_patterns = [
        r"(?:[a-z]:)?(?:[\\\/][a-z0-9_. -]*)+",
    ]

    paths = set()
    for pattern in path_patterns:
        matches = re.findall(pattern, text, re.MULTILINE | re.IGNORECASE)
        for match in matches:
            p = match.strip()
            slashs = p.replace('\\', '').replace('/', '').strip()
            if slashs == "":
                continue
            paths.add(match.strip())

    return list(paths)
