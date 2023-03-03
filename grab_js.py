"""Grab JavaScript Code Blocks"""
import os
import random
import re
import sys
from pathlib import Path

import jsbeautifier
import requests
from bs4 import BeautifulSoup

__author__ = "DFIRSec (@pulsecode)"
__version__ = "0.0.3"
__license__ = "MIT"


class TermColors:
    """Returns terminal color options."""

    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    BOLD = "\033[1m"
    GRAY = "\033[90m"
    UNDERLINE = "\033[4m"
    RST = "\033[0m"
    SEP = f"{GRAY}{('.' * 50)}{RST}"


TC = TermColors()

UA = [
    # Chrome
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36",
    "Mozilla/5.0 (Windows NT 5.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.2; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36",
    # Firefox
    "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1)",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)",
    "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 6.2; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0)",
    "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)",
    "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
    "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)",
]

HEADERS = {"User-Agent": random.choice(UA)}

if len(sys.argv) > 1:
    URL = sys.argv[1]
else:
    sys.exit("Usage: python grab_js.py <URL>")

try:
    PARENT = Path(__file__).parent
    EXAMINE = Path.joinpath(PARENT, "examine_js.txt")
    EXTRACTED = Path.joinpath(PARENT, "extracted_js.txt")

    RESP = requests.get(URL, headers=HEADERS, timeout=3).text
    SOUP = BeautifulSoup(RESP, "lxml")
    JSCODE = SOUP.find_all("script")
    CODEBLOCKS = [str(x) for x in JSCODE]

    REGEX_PATTERN = (
        r"(?!document\.createElement\((\"|')(script|style|img|link|meta)(\"|')\))"
        r"(eval\(\S+\)|document\.write\(.+\)|unescape\(.+\)|setcookie\(.+\)|getcookie\(\S+\)|chrw?\(\S+\)"
        r"|strreverse\(\S+\)|charcode|tostring\((\S+|)\)|document\.createElement\(\S+\)|window\.open\(\S+\)"
        r"|window\.parent|window\.frameElement|window\.document($|\S+)|window\.onload|"
        r"(?=iframe).+(visibility=\"false\")|(?=iframe).+(width=\"0\" height=\"0\" frameborder=\"0\")|"
        r"<iframe src=.+<\/iframe>|var\s[a-z0-9_]{25,}\s?=|(?!\\x00)\\x[0-9a-fA-F]{2}\b|(?!\\u0000|\\u0026|"
        r"\\u2029|\\u2026|\\u2028|\\u003c|\\u003e)\\u[0-9a-fA-F]{4})"
    )

    #    (?!document\.createElement\((\"|')(script|style|img|link|meta)(\"|')\))        # negative lookahead for certain strings
    #    eval\(\S+\)                                                                    # matches eval() function
    #    document\.write\(.+\)                                                          # matches document.write() function
    #    unescape\(.+\)                                                                 # matches unescape() function
    #    setcookie\(.+\)                                                                # matches setcookie() function
    #    getcookie\(\S+\)                                                               # matches getcookie() function
    #    chrw?\(\S+\)                                                                   # matches chr() or chrw() functions
    #    strreverse\(\S+\)                                                              # matches strreverse() function
    #    charcode                                                                       # matches charcode string
    #    tostring\((\S+|)\)                                                             # matches tostring() function
    #    document\.createElement\(\S+\)                                                 # matches document.createElement() function
    #    window\.open\(\S+\)                                                            # matches window.open() function
    #    window\.parent                                                                 # matches window.parent
    #    window\.frameElement                                                           # matches window.frameElement
    #    window\.document($|\S+)                                                        # matches window.document or window.document.foo
    #    window\.onload                                                                 # matches window.onload
    #    (?=.*<iframe)(?=.*visibility=\"false\")                                        # positive lookahead for iframe with visibility="false"
    #    (?=.*<iframe)(?=.*width=\"0\" height=\"0\" frameborder=\"0\")                  # positive lookahead for iframe with certain attributes
    #    <iframe src=.+?<\/iframe>                                                      # matches iframe tag with certain src
    #    var\s+[a-zA-Z0-9_]{25,}\s*=\s*                                                 # matches var declaration with long variable name
    #    (?!\\x00)\\x[0-9a-fA-F]{2}\b                                                   # matches hex encoding with a value other than \\x00
    #    (?!\\u0000|\\u0026|\\u2029|\\u2026|\\u2028|\\u003c|\\u003e)\\u[0-9a-fA-F]{4}   # matches unicode encoding with disallowed characters

    # erase file contents
    if EXAMINE.exists() or EXTRACTED.exists():
        with open(EXAMINE, "w", encoding="utf-8"):
            pass
        with open(EXTRACTED, "w", encoding="utf-8"):
            pass

    # jsbeautifier options -- https://github.com/beautify-web/js-beautify
    OPTS = jsbeautifier.default_options()
    OPTS.jslint_happy = True
    OPTS.max_preserve_newlines = -1

    for code in CODEBLOCKS:
        RESULTS = jsbeautifier.beautify(code, OPTS)

        if re.findall(REGEX_PATTERN, code, re.IGNORECASE | re.VERBOSE):
            with open(EXAMINE, "a", errors="ignore", newline="", encoding="utf-8") as f:
                f.write(f"{RESULTS}\n")

        with open(EXTRACTED, "a", errors="ignore", newline="", encoding="utf-8") as f:
            f.write(f"{RESULTS}\n")

    print(TC.SEP)
    if EXAMINE.exists() and os.path.getsize(EXAMINE) != 0:
        print(f"[*] Scrutinize this JS: {TC.CYAN}{EXAMINE.parts[-1]}{TC.RST}")
        with open(EXAMINE, encoding="utf-8") as f:
            LINES = [line.strip() for line in f.readlines()]
            for n, line in enumerate(LINES, start=1):
                MATCHES = re.finditer(REGEX_PATTERN, line, re.IGNORECASE)
                for match in MATCHES:
                    print(f"    > Line {n}: {TC.WARNING}{match.group()}{TC.RST} (chars {match.start()}-{match.end()})")
    else:
        print("[-] Hmm, nothing to scrutinize")

    if EXTRACTED.exists() and os.path.getsize(EXTRACTED) != 0:
        print(f"[~] All JS extracted: {TC.CYAN}{EXTRACTED.parts[-1]}{TC.RST}")
    print(TC.SEP)

except (requests.exceptions.MissingSchema, requests.exceptions.InvalidSchema) as err:
    print(err)
    sys.exit()
except ConnectionError as err:
    sys.exit(f"{TC.FAIL}[ERROR]{TC.RST} Please check the URL: {URL}")
