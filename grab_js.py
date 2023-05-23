"""Grab JavaScript Code Blocks."""

import os
import random
import re
import sys
from pathlib import Path

import jsbeautifier
import requests
from bs4 import BeautifulSoup


class TermColors:
    """Returns terminal color options."""

    blue = "\033[94m"
    cyan = "\033[96m"
    green = "\033[92m"
    yellow = "\033[93m"
    red = "\033[91m"
    bold = "\033[1m"
    gray = "\033[90m"
    underline = "\033[4m"
    reset = "\033[0m"
    separator = f"{gray}{('.' * 50)}{reset}"


class UserAgent:
    """Returns a random user agent."""

    def __init__(self) -> None:
        """Initialize the user agent list."""
        with open("user_agents.txt") as f:
            self.user_agents = f.readlines()

    def get_random_user_agent(self) -> dict:
        """Return a random user agent."""
        return {"User-Agent": random.choice(self.user_agents).strip()}


class FilePaths:
    """File paths for output."""

    root = Path(__file__).parent
    examine = Path.joinpath(root, "examine_js.txt")
    extracted = Path.joinpath(root, "extracted_js.txt")


class RegexPatterns:
    """Regex patterns for extracting JS."""

    regex_patterns = [
        r"(?!document\.createElement\((\"|')(script|style|img|link|meta)(\"|')\))"
        r"(eval\(\S+\)|document\.write\(.+\)|unescape\(.+\)|setcookie\(.+\)|getcookie\(\S+\)|chrw?\(\S+\)"
        r"|strreverse\(\S+\)|charcode|tostring\((\S+|)\)|document\.createElement\(\S+\)|window\.open\(\S+\)"
        r"|window\.parent|window\.frameElement|window\.document($|\S+)|window\.onload|"
        r"(?=iframe).+(visibility=\"false\")|(?=iframe).+(width=\"0\" height=\"0\" frameborder=\"0\")|"
        r"<iframe src=.+<\/iframe>|var\s[a-z0-9_]{25,}\s?=|(?!\\x00)\\x[0-9a-fA-F]{2}\b|(?!\\u0000|\\u0026|"
        r"\\u2029|\\u2026|\\u2028|\\u003c|\\u003e)\\u[0-9a-fA-F]{4})",
    ]

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

    pattern = "|".join(regex_patterns)


def get_args() -> str:
    """Extract the URL argument from the command line."""
    if len(sys.argv) > 1:
        return sys.argv[1]

    sys.exit("Usage: python grab_js.py <URL>")


def make_request(url: str) -> str:
    """Create a session and make the request to the provided URL."""
    ua = UserAgent()  # create an instance of UserAgent
    headers = ua.get_random_user_agent()  # get a random user agent
    session = requests.Session()
    session.headers.update(headers)

    with requests.Session() as session:
        session.headers.update(headers)
        return session.get(url, timeout=5).text


def get_code_blocks(resp: str) -> list:
    """Extract the JavaScript blocks from the webpage response."""
    soup = BeautifulSoup(resp, "lxml")
    jscode = soup.find_all("script")
    return [str(x) for x in jscode]


def clear_files() -> None:
    """Clear the contents of the output files."""
    if FilePaths.examine.exists() or FilePaths.extracted.exists():
        open(FilePaths.examine, "w", encoding="utf-8").close()
        open(FilePaths.extracted, "w", encoding="utf-8").close()


def setup_beautifier() -> str:
    """Set up the jsbeautifier with desired options."""
    options = jsbeautifier.default_options()
    options.jslint_happy = True
    options.max_preserve_newlines = -1
    return options


def write_results_to_file(codeblocks: list, beautify_options: str) -> None:
    """Beautify the JavaScript code and write results to the output files."""
    examine_results = []
    extracted_results = []

    for code in codeblocks:
        result = jsbeautifier.beautify(code, beautify_options)

        if re.findall(RegexPatterns.pattern, code, re.IGNORECASE | re.VERBOSE):
            examine_results.append(result)

        extracted_results.append(result)

    with open(FilePaths.examine, "a", errors="ignore", newline="", encoding="utf-8") as f:
        f.write("\n".join(examine_results))

    with open(FilePaths.extracted, "a", errors="ignore", newline="", encoding="utf-8") as f:
        f.write("\n".join(extracted_results))


def print_results() -> None:
    """Print results of the JavaScript examination."""
    tc = TermColors()

    print(tc.separator)
    if FilePaths.examine.exists() and os.path.getsize(FilePaths.examine) != 0:
        print(f"[*] Scrutinize this JS: {tc.cyan}{FilePaths.examine.parts[-1]}{tc.reset}")
        with open(FilePaths.examine, encoding="utf-8") as f:
            lines = [line.strip() for line in f.readlines()]
            for n, line in enumerate(lines, start=1):
                matches = re.finditer(RegexPatterns.pattern, line, re.IGNORECASE)
                for match in matches:
                    print(f"    > Line {n}: {tc.yellow}{match.group()}{tc.reset} (chars {match.start()}-{match.end()})")
    else:
        print("[-] Hmm, nothing to scrutinize")

    if FilePaths.extracted.exists() and os.path.getsize(FilePaths.extracted) != 0:
        print(f"[~] All JS extracted: {tc.cyan}{FilePaths.extracted.parts[-1]}{tc.reset}")
    print(tc.separator)


def url_processor(url: str) -> None:
    """Process the URL and print the results."""
    resp = make_request(url)
    codeblocks = get_code_blocks(resp)
    clear_files()
    beautify_options = setup_beautifier()
    write_results_to_file(codeblocks, beautify_options)
    print_results()


def main() -> None:
    """Main function."""
    url = get_args()
    try:
        url_processor(url)
    except (requests.exceptions.MissingSchema, requests.exceptions.InvalidSchema) as err:
        print(err)
        sys.exit()
    except ConnectionError:
        sys.exit(f"{TermColors.red}[ERROR]{TermColors.reset} Please check the URL: {url}")


if __name__ == "__main__":
    main()
