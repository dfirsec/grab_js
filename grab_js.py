import os
import random
import re
import sys
from pathlib import Path

import requests
from bs4 import BeautifulSoup
import jsbeautifier
from requests.exceptions import ConnectionError

__author__ = "DFIRSec (@pulsecode)"
__version__ = "0.0.3"
__description__ = "Grab JavaScript Code Blocks"

ua_list = [
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

headers = {"User-Agent": random.choice(ua_list)}

if len(sys.argv) > 1:
    url = sys.argv[1]
else:
    sys.exit("Usage: python grab_js.py <URL>")

try:
    parent = Path(__file__).parent
    examine = Path.joinpath(parent, "examine_js.txt")
    extracted = Path.joinpath(parent, "extracted_js.txt")
    resp = requests.get(url, headers=headers, timeout=3).text
    soup = BeautifulSoup(resp, "lxml")
    js_code = soup.find_all("script")
    code_blocks = [str(x) for x in js_code]

    regex = r"(eval|document\.write|unescape|setcookie|getcookie|chr(W|w)?\(\S+\)|strreverse\(\S+\)|document\.createElement|window\.open|window\.parent|window\.frameElement|window\.document($|.+)|window\.onload)"

     # erase file contents
    if examine.exists() or extracted.exists():
        open(examine, 'w').close()
        open(extracted, 'w').close()
        
    for code in code_blocks:
        res = jsbeautifier.beautify(code)
        if re.findall(regex, code, re.IGNORECASE):
            with open(examine, "a", errors="ignore") as f:
                f.write(f"{res}\n")
        else:
            with open(extracted, "a", errors="ignore") as f:
                f.write(f"{res}\n")

    if examine.exists() and os.path.getsize(examine) != 0:
        print(f"[+] JS to scrutinize: {examine}")

    if extracted.exists() and os.path.getsize(extracted) != 0:
        print(f"[+] All JS extracted: {extracted}")

except requests.exceptions.MissingSchema as e:
    sys.exit(e)
except ConnectionError as e:
    sys.exit(f"[ERROR] Please check the URL: {url}")
