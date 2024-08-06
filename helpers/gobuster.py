# https://github.com/OJ/gobuster
import os
import re
import shutil
import subprocess


class GobusterNotFound(Exception):
    pass


class WordlistNotFound(Exception):
    pass


class IllegalArgumentException(Exception):
    pass


class GobusterException(Exception):
    pass


class Gobuster:

    def __init__(self, wordlist, threads=10, gobusterAbsPath=None):
        self.gobusterPath = gobusterAbsPath
        if self.gobusterPath is None:
            self.gobusterPath = shutil.which("gobuster")

        if self.gobusterPath is None or not os.path.exists(self.gobusterPath):
            raise GobusterNotFound("gobuster not found in path")

        self.wordlist = wordlist
        if not os.path.exists(self.wordlist):
            raise WordlistNotFound(f"Wordlist not found at {self.wordlist}")
        self.threads = threads
        self.gobusterPath = os.path.dirname(self.gobusterPath)
        self.verbose = bool()
        self.creationflags = subprocess.CREATE_NO_WINDOW if subprocess.sys.platform == 'win32' else 0

        # Allow changing the path where nuclei is installed (instead of expecting it to be in $PATH)
        # Check if the '/' is at the end - and remove it if "yes"
        if gobusterAbsPath is not None and gobusterAbsPath[-1] == "/":
            self.nucleiPath = gobusterAbsPath[:-1]

        self.gobusterBinary = "gobuster"
        if self.gobusterPath:
            self.gobusterBinary = os.path.join(self.gobusterPath, self.gobusterBinary)

    def dir(self, url, exclude_status_code=None, verbose=False) -> [str]:
        command = [
            '--url', url,
            '--no-tls-validation',
            '--no-status',
            '--hide-length'
        ]

        if exclude_status_code is not None:
            command.extend(['--status-codes-blacklist', exclude_status_code])

        report = self.exec('dir', command, bufsize=1, verbose=verbose)
        paths = set()
        for line in report.split('\n'):
            paths.add(line.strip())
        return list(paths)

    def exec(self, mode, cmd: [], bufsize=-1, verbose=False) -> str:
        command = [self.gobusterBinary, mode, "--no-color", "--no-progress", "--quiet",
                   "--threads", str(self.threads),
                   "--wordlist", self.wordlist]
        command.extend(cmd)
        print(f"[Gobuster] [INFO] {' '.join(command)}")

        # 启动进程
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                   bufsize=bufsize,
                                   creationflags=self.creationflags)

        outputs = []
        try:
            for line in iter(process.stdout.readline, ''):
                line = line.strip().lstrip('\r\x1b[2K')
                line = re.sub(r'\[.*?\]', '', line).strip()

                if verbose:
                    print(line)
                if line != '':
                    outputs.append(line)
        except KeyboardInterrupt:
            print(f"[Gobuster] [INFO] Process interrupted by user.")
        finally:
            process.stdout.close()
            process.wait()

        output = '\n'.join(outputs)
        if output.startswith("Error: "):
            raise GobusterException(output)
        return output
