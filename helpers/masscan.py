"""
https://github.com/MyKings/python-masscan/
"""
from config import logger
import json
import re
import sys
import shlex

if sys.platform == "win32":
    shlex.split = lambda s, comments=False, posix=True: s
import os
import shutil
import subprocess
from pydantic.v1 import BaseModel, Field
from typing import Optional


class MasscanNotFound(Exception):
    pass


class PortResult(BaseModel):
    ip: Optional[str] = Field(description="ip")
    port: Optional[str] = Field(description="port")
    proto: Optional[str] = Field(description="协议")


class Masscan:
    """
    Class which allows to use masscan from Python.
    """

    def __init__(self, masscanPath=None):
        self._masscan_path = shutil.which("masscan", path=masscanPath)
        if not self._masscan_path:
            raise MasscanNotFound("[ERROR] Masscan not found in path")

    def scan(self, hosts='127.0.0.1', ports="1-65535", arguments='') -> [PortResult]:
        """
        Scan given hosts.

        May raise PortScannerError exception if masscan output was not XML

        Test existence of the following key to know
        if something went wrong : ['masscan']['scaninfo']['error']
        If not present, everything was ok.
        """

        assert type(hosts) is str, 'Wrong type for [hosts], should be a string [was {0}]'.format(
            type(hosts))  # noqa
        assert type(ports) in (str, type(None)), 'Wrong type for [ports], should be a string [was {0}]'.format(
            type(ports))  # noqa
        assert type(arguments) is str, 'Wrong type for [arguments], should be a string [was {0}]'.format(
            type(arguments))  # noqa

        h_args = shlex.split(hosts)
        f_args = shlex.split(arguments)

        # Launch scan
        args = [self._masscan_path, '-oJ', '-'] + h_args + ['-p', ports] * (ports is not None) + f_args

        logger.debug("{args}", args=' '.join(args))
        p = subprocess.Popen(
            args,
            bufsize=100000,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        # wait until finished
        # get output
        masscan_output, masscan_err = p.communicate()

        if isinstance(masscan_output, bytes):
            masscan_output = masscan_output.decode('utf-8')
        if isinstance(masscan_err, bytes):
            masscan_err = masscan_err.decode('utf-8')

        # If there was something on stderr, there was a problem so abort...  in
        # fact not always. As stated by AlenLPeacock :
        # This actually makes python-masscan mostly unusable on most real-life
        # networks -- a particular subnet might have dozens of scannable hosts,
        # but if a single one is unreachable or unroutable during the scan,
        # masscan.scan() returns nothing. This behavior also diverges significantly
        # from commandline masscan, which simply stderrs individual problems but
        # keeps on trucking.

        masscan_err_keep_trace = []
        masscan_warn_keep_trace = []
        if len(masscan_err) > 0:
            regex_warning = re.compile('^Warning: .*', re.IGNORECASE)
            for line in masscan_err.split(os.linesep):
                if len(line) > 0:
                    rgw = regex_warning.search(line)
                    if rgw is not None:
                        # sys.stderr.write(line+os.linesep)
                        masscan_warn_keep_trace.append(line + os.linesep)
                    else:
                        # raise PortScannerError(masscan_err)
                        masscan_err_keep_trace.append(masscan_err)
        return self._load_scan_result(masscan_output)

    def _load_scan_result(self, scan_result: str) -> [PortResult]:
        datas = []
        result = json.loads(scan_result)
        for r in result:
            for port in r['ports']:
                datas.append(PortResult(ip=r['ip'], port=port['port'], proto=port['proto']))
        return datas
