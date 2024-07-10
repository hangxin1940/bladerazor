"""
https://github.com/kushvaibhav/PyNuclei/
"""
import glob
import json
import yaml

import datetime

import os
import shutil
import string
import tempfile
import subprocess
from pydantic.v1 import BaseModel, Field
from typing import Optional

from fake_useragent import FakeUserAgent

FILE_SEPARATOR = "SEP"


class NucleiNotFound(Exception):
    pass


class TemplatesNotFound(Exception):
    pass


class IllegalArgumentException(Exception):
    pass


class NucleiResult(BaseModel):
    template_id: Optional[str] = Field()
    host: Optional[str] = Field()
    vulnerability_name: Optional[str] = Field()
    vulnerability_detail: Optional[str] = Field()
    description: Optional[str] = Field()
    type: Optional[str] = Field()
    result: Optional[list[str]]
    vulnerable_at: Optional[str] = Field()
    solution: Optional[str] = Field()
    curl: Optional[str] = Field()
    severity: Optional[str] = Field()
    tags: Optional[list[str]] = Field()
    reference: Optional[list[str]] = Field()
    cvss_metrics: Optional[str] = Field()
    cvss_score: Optional[str] = Field()
    cve_id: Optional[list[str]] = Field()
    cwe_id: Optional[list[str]] = Field()

    def __eq__(self, other):
        return self.__hash__() == other.__hash__()

    def __hash__(self):
        return hash(
            f"{self.template_id}-{self.cvss_metrics}-{self.vulnerability_name}-{self.curl}-{self.vulnerable_at}-{self.host}-{self.description}-{self.severity}-{self.type}")


class NucleiTemplate(BaseModel):
    dir: Optional[str] = Field()
    file: Optional[str] = Field()
    id: Optional[str] = Field()
    name: Optional[str] = Field()
    severity: Optional[str] = Field()
    description: Optional[str] = Field()
    tags: Optional[list[str]] = Field()


class Nuclei:
    """
    Class handling the Nuclei scans and result generation.
    """

    def __init__(self, nucleiAbsPath=None, templatesAbsPath=None):
        self.nucleiPath = shutil.which("nuclei", path=nucleiAbsPath)
        if not self.nucleiPath:
            raise NucleiNotFound("[PyNuclei] [ERROR] Nuclei not found in path")
        if not templatesAbsPath:
            raise TemplatesNotFound()
        self.nucleiPath = os.path.dirname(self.nucleiPath)
        self.done = int()
        self.running = int()
        self.verbose = bool()
        self.findings = int()
        self.templatesPath = templatesAbsPath
        self.eta = datetime.timedelta(seconds=0)
        self.creationflags = subprocess.CREATE_NO_WINDOW if subprocess.sys.platform == 'win32' else 0

        # Allow changing the path where nuclei is installed (instead of expecting it to be in $PATH)
        # Check if the '/' is at the end - and remove it if "yes"
        if nucleiAbsPath is not None and nucleiAbsPath[-1] == "/":
            self.nucleiPath = nucleiAbsPath[:-1]

        self.nucleiBinary = "nuclei"
        if self.nucleiPath:
            self.nucleiBinary = os.path.join(self.nucleiPath, self.nucleiBinary)

        self.checkFirstRun()
        self.outputPath = os.path.join(tempfile.gettempdir(), 'nuclei_tmp')
        try:
            os.makedirs(os.path.expanduser(self.outputPath))
        except FileExistsError:
            print(f"[PyNuclei] [WARN] Output directory already exist {self.outputPath}")

    def checkFirstRun(self):
        if not os.path.exists(self.templatesPath):
            os.makedirs(self.templatesPath)
            self.updateNuclei(True)

    def updateNuclei(self, verbose=False):
        out = self.exec(["-update-templates", "-update-template-dir", self.templatesPath], verbose=False,
                        silent=False, disableup=False)
        if verbose:
            print(out)

    @property
    def ignoredTemplates(self):
        return [
            "headless", "fuzzing", "helpers",
        ]

    def nucleiTemplates(self, tree=False):
        yaml_files = []

        # os.walk生成一个三元组(root, dirs, files)，用于遍历目录
        for root, dirs, files in os.walk(self.templatesPath):
            # glob模式匹配当前目录下的.yaml和.yml文件
            for file in glob.glob(os.path.join(root, '*.yaml')):
                yaml_files.append(file)
            for file in glob.glob(os.path.join(root, '*.yml')):
                yaml_files.append(file)

        if tree:
            templates = {}
        else:
            templates = []
        for yaml_file in yaml_files:
            yaml = self._parseTemplate(yaml_file)
            if yaml is not None and 'id' in yaml and 'info' in yaml:
                nt = NucleiTemplate()
                nt.file = os.path.relpath(yaml_file, self.templatesPath)
                nt.dir = os.path.dirname(nt.file)
                nt.id = yaml['id']
                nt.name = yaml['info']['name']
                if 'severity' in yaml['info']:
                    nt.severity = yaml['info']['severity']
                else:
                    nt.severity = ""

                if 'description' in yaml['info']:
                    nt.description = yaml['info']['description']
                else:
                    nt.description = ""
                if 'tags' in yaml['info']:
                    nt.tags = yaml['info']['tags'].split(",")
                else:
                    nt.tags = []

                if tree:
                    nested_dict = templates
                    path_parts = nt.file.split(os.sep)
                    for part in path_parts[:-1]:
                        if part not in nested_dict:
                            nested_dict[part] = {}
                        nested_dict = nested_dict[part]
                    if path_parts[-1] not in nested_dict:
                        nested_dict[path_parts[-1]] = []
                    nested_dict[path_parts[-1]].append(nt)
                else:
                    templates.append(nt)

        # TODO
        return templates

    def _parseTemplate(self, yaml_file):
        with open(yaml_file, 'r', encoding='utf-8') as stream:
            try:
                return yaml.safe_load(stream)
            except yaml.YAMLError as exc:
                print(exc)
        return None

    def createResultDir(self, host):
        epath = os.path.join(self.outputPath, host)
        try:
            os.makedirs(os.path.expanduser(epath))
        except FileExistsError:
            if self.verbose:
                print(f"[PyNuclei] [WARN] Result directory exist {epath}")

    def stringifyTimeDelta(self, tdelta, fmt="{D:02}d {H:02}h {M:02}m {S:02}s", inputType="timedelta"):
        """Convert a datetime.timedelta object or a regular number to a custom-
        formatted string, just like the stftime() method does for datetime.datetime
        objects.

        The fmt argument allows custom formatting to be specified.  Fields can
        include seconds, minutes, hours, days, and weeks.  Each field is optional.

        Some examples:
            '{D:02}d {H:02}h {M:02}m {S:02}s' --> '05d 08h 04m 02s' (default)
            '{W}w {D}d {H}:{M:02}:{S:02}'     --> '4w 5d 8:04:02'
            '{D:2}d {H:2}:{M:02}:{S:02}'      --> ' 5d  8:04:02'
            '{H}h {S}s'                       --> '72h 800s'

        The input type argument allows time delta to be a regular number instead of the
        default, which is a datetime.timedelta object.  Valid input type strings:
            's', 'seconds',
            'm', 'minutes',
            'h', 'hours',
            'd', 'days',
            'w', 'weeks'
        """

        # Convert time delta to integer seconds.
        if inputType == "timedelta":
            remainder = int(tdelta.total_seconds())
        elif inputType in ["s", "seconds"]:
            remainder = int(tdelta)
        elif inputType in ["m", "minutes"]:
            remainder = int(tdelta) * 60
        elif inputType in ["h", "hours"]:
            remainder = int(tdelta) * 3600
        elif inputType in ["d", "days"]:
            remainder = int(tdelta) * 86400
        elif inputType in ["w", "weeks"]:
            remainder = int(tdelta) * 604800

        f = string.Formatter()
        desiredFields = [fieldTuple[1] for fieldTuple in f.parse(fmt)]
        possibleFields = ("W", "D", "H", "M", "S")
        constants = {"W": 604800, "D": 86400, "H": 3600, "M": 60, "S": 1}
        values = dict()
        for field in possibleFields:
            if field in desiredFields and field in constants:
                values[field], remainder = divmod(remainder, constants[field])
        return f.format(fmt, **values)

    def _parseNucleiScan(self, host, templates):
        """Parse nuclei scan results in json object"""

        report = list()
        if not templates:
            templateOutputPath = os.path.join(self.outputPath, host, "all-templates")
            with open(templateOutputPath, "r") as scanResult:
                report.extend(json.load(scanResult))
        else:
            for template in templates:
                try:
                    templateOutputPath = os.path.join(self.outputPath, host, template)
                    if ".yaml" in template or ".yml" in template:
                        templateOutputPath = os.path.join(self.outputPath, host, template.split('/')[-1].split('/')[0])

                    with open(templateOutputPath, "r") as scanResult:
                        report.extend(json.load(scanResult))

                except FileNotFoundError:
                    if self.verbose:
                        print(f"[PyNucleiParser] [ERROR] File not found for {templateOutputPath}")

                except Exception as e:
                    print(f"[PyNucleiParser] [ERROR] : {e}")

        return report

    def _formatNucleiReport(self, report) -> [NucleiResult]:
        """
        Reformats the raw Nuclei scan results from file into a cleaner list.
        Args:
            report (list): The raw report from file
        Returns:
            list: The list of formatted report
        """
        formattedReport = set()
        for vuln in report:
            try:
                data = NucleiResult()
                data.template_id = vuln["template-id"]
                data.host = vuln["host"]
                data.vulnerability_name = vuln["info"]["name"]
                data.type = vuln["type"]
                data.vulnerable_at = vuln["matched-at"]
                data.severity = vuln["info"]["severity"]
                data.tags = vuln["info"]["tags"]

                if "description" in vuln["info"] and vuln["info"]["description"]:
                    data.description = vuln["info"]["description"]

                if "severity" in vuln["info"] and vuln["info"]["severity"]:
                    data.severity = vuln["info"]["severity"]

                if "reference" in vuln["info"] and vuln["info"]["reference"]:
                    if isinstance(vuln["info"]["reference"], str):
                        data.reference = [vuln["info"]["reference"]]
                    elif isinstance(vuln["info"]["reference"], list):
                        data.reference = vuln["info"]["reference"]

                if "remediation" in vuln["info"] and vuln["info"]["remediation"]:
                    data.solution = vuln["info"]["remediation"]

                if "classification" in vuln["info"] and vuln["info"]["classification"]:

                    if "cvss-metrics" in vuln["info"]["classification"] and vuln["info"]["classification"][
                        "cvss-metrics"]:
                        data.cvss_metrics = vuln["info"]["classification"]["cvss-metrics"]

                    if "cvss-score" in vuln["info"]["classification"] and vuln["info"]["classification"]["cvss-score"]:
                        data.cvss_score = vuln["info"]["classification"]["cvss-score"]

                    if "cve-id" in vuln["info"]["classification"] and vuln["info"]["classification"]["cve-id"]:
                        data.cve_id = vuln["info"]["classification"]["cve-id"]

                    if "cwe-id" in vuln["info"]["classification"] and vuln["info"]["classification"]["cwe-id"]:
                        if isinstance(vuln["info"]["classification"]["cwe-id"], list) and \
                                vuln["info"]["classification"]["cwe-id"]:
                            data.cwe_id = vuln["info"]["classification"]["cwe-id"]
                        else:
                            data.cwe_id = [vuln["info"]["classification"]["cwe-id"]]

                if "extracted-results" in vuln and vuln["extracted-results"]:
                    data.result = vuln["extracted-results"]

                if "curl-command" in vuln and vuln["curl-command"]:
                    data.curl = vuln["curl-command"]

                if "matcher-name" in vuln and vuln["matcher-name"]:
                    data.vulnerability_detail = vuln["matcher-name"]

                formattedReport.add(data)

            except Exception as e:
                print(f"[PyNucleiResultFormatter] [ERROR] : {e}")
                continue

        return list(formattedReport)

    def returnTemplatesDetails(self):
        """
        Process the templates available and return them as a structure
        WARNING: This is a VERY time consuming function
        """
        command = ["nuclei", "--no-color", "--template-display"]

        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, _ = process.communicate()
        output = output.decode()

        templates = list()
        startTemplate = output.find("Template: ")
        while startTemplate != -1:
            endTemplate = output.find("# digest: ", startTemplate)
            if endTemplate == -1 and not templates:
                raise ValueError("Cannot find '# digest: ")

            template = output[startTemplate:endTemplate]
            templateObj = yaml.safe_load(template)

            keys = list(templateObj.keys())
            for key in keys:
                # Keep only the info we want
                if key not in ["Template", "id", "info"]:
                    del templateObj[key]

            templates.append(templateObj)

            # Reducing the size of 'output' is very time consuming, we will avoid it
            startTemplate = output.find("Template: ", endTemplate)

        return templates

    def scan(self, host, templates=None, userAgent="", rateLimit=150, verbose=False, maxHostError=30):
        """
        Runs the nuclei scan and returns a formatted dictionary with the results.
        Args:
            host [str]: The hostname of the target which Nuclei will run against
            templates [list][Optional]: If templates list not provided all nuclei templates from "nucleiTemplates" property will be executed
            userAgents [str][Optional]: If not provided random User-Agents will be used.
            rateLimit [int][Optional]: Defaults to 150.
            maxHostError [int][Optional]: It determine to skip host for scanning after n number of connection failures

        Returns:
            result [dict]: Scan result from all templates.
        """

        self.verbose = verbose

        fileNameValidHost = host.replace('/', FILE_SEPARATOR)

        self.createResultDir(fileNameValidHost)

        commands = list()
        if not templates:
            if not userAgent:
                userAgent = FakeUserAgent().random
            templateOutputPath = os.path.join(self.outputPath, fileNameValidHost, "all-templates")

            command = [
                '-header', f"'User-Agent: {userAgent}'",
                "-rl", str(rateLimit), "-u", host,
                "--json-export", templateOutputPath,

            ]

            if maxHostError != 30:
                command.extend(["-max-host-error", str(maxHostError)])

            commands.append(command)
        else:
            for template in templates:
                if not userAgent:
                    userAgent = FakeUserAgent().random

                templateOutputPath = os.path.join(self.outputPath, fileNameValidHost, template)
                if ".yaml" in template or ".yml" in template:
                    templateOutputPath = os.path.join(self.outputPath, fileNameValidHost,
                                                      template.split('/')[-1].split('/')[0])

                command = [
                    '-header', f"'User-Agent: {userAgent}'",
                    "-rl", str(rateLimit), "-u", host, "-t",
                    template if ".yaml" in template or ".yml" in template else f"{template}/",
                    "--json-export", templateOutputPath,

                ]

                if maxHostError != 30:
                    command.extend(["-max-host-error", str(maxHostError)])

                commands.append(command)

        for command in commands:
            self.exec(command, bufsize=1, verbose=verbose)

        report = self._parseNucleiScan(fileNameValidHost, templates)

        # shutil.rmtree(os.path.join(self.outputPath, fileNameValidHost), ignore_errors=True)

        return self._formatNucleiReport(report)

    def exec(self, cmd: [], bufsize=-1, silent=True, disableup=True, verbose=False) -> str:
        command = [self.nucleiBinary, "--no-color"]
        if silent:
            command.append("-silent")
        if disableup:
            command.append("-disable-update-check")
        command.extend(cmd)
        print(f"[PyNuclei] [INFO] {' '.join(command)}")

        # 启动进程
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                   bufsize=bufsize,
                                   creationflags=self.creationflags)

        outputs = []
        try:
            for line in iter(process.stdout.readline, ''):
                if verbose:
                    print(line, end='')
                outputs.append(line)
        except KeyboardInterrupt:
            print(f"[PyNuclei] [INFO] Process interrupted by user.")
        finally:
            process.stdout.close()
            process.wait()

        output = ''.join(outputs)

        return output
