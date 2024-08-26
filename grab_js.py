"""Extract and analyze JavaScript code blocks for suspicious patterns from a given URL."""

import hashlib
import logging
import random
import re
import sys
from collections.abc import Callable
from functools import wraps
from pathlib import Path
from typing import Any
from typing import ClassVar

import jsbeautifier
import requests
from bs4 import BeautifulSoup
from rich.console import Console

# Constants
USER_AGENTS_FILE = Path("user_agents.txt")
EXAMINE_JS_FILE = Path("examine_js.txt")
EXTRACTED_JS_FILE = Path("extracted_js.txt")

# Log connection sequence and any errors
logging.basicConfig(filename="js_analysis.log", level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

# Rich Console for output
console = Console(highlight=False)


class UserAgent:
    """Generate random user agents for HTTP requests."""

    def __init__(self, file_path: Path = USER_AGENTS_FILE) -> None:
        """Initialize the UserAgent with a file path."""
        self.user_agents = self._load_user_agents(file_path)

    @staticmethod
    def _load_user_agents(file_path: Path) -> list[str]:
        """Load user agents file."""
        try:
            return file_path.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            logging.error(f"User agent file '{file_path}' not found.")
            sys.exit(1)

    def get_random_user_agent(self) -> str:
        """Return random user agent."""
        return random.choice(self.user_agents)


class KnownCDNs:
    """Handle known CDNs to exclude from being flagged as suspicious."""

    KNOWN_CDN_DOMAINS: ClassVar[list[str]] = [
        "cdn.jsdelivr.net",
        "cdnjs.cloudflare.com",
        "ajax.googleapis.com",
        "stackpath.bootstrapcdn.com",
        "code.jquery.com",
        "cdn.jsdelivr.net",
    ]

    @classmethod
    def is_known_cdn(cls: type["KnownCDNs"], url: str) -> bool:
        """Check if the URL is from a known CDN."""
        return any(cdn in url for cdn in cls.KNOWN_CDN_DOMAINS)


class RegexPatterns:
    """Regex patterns for extracting and analyzing JS with explanations."""

    # JS functions and methods associated with malicious activity
    SUSPICIOUS_FUNCTIONS: ClassVar[list[tuple[str, str]]] = [
        (r"eval\(\S+\)", "Usage of eval()"),
        (r"document\.write\(.+\)", "Usage of document.write()"),
        (r"unescape\(.+\)", "Usage of unescape()"),
        (r"setcookie\(.+\)", "Cookie manipulation"),
        (r"getcookie\(\S+\)", "Cookie retrieval"),
        (r"chrw?\(\S+\)", "Usage of chr() or chrw()"),
        (r"strreverse\(\S+\)", "Usage of strreverse()"),
        (r"charcode", "Character encoding"),
        (r"tostring\((\S+|)\)", "Usage of tostring()"),
        (r"atob\(\S+\)|btoa\(\S+\)", "Base64 encoding/decoding"),
    ]

    # DOM manipulation and suspicious HTML elements
    DOM_MANIPULATION: ClassVar[list[tuple[str, str]]] = [
        (r"document\.createElement\(\S+\)", "DOM element creation"),
        (r"window\.open\(\S+\)", "Window opening"),
        (r"window\.parent", "Accessing parent window"),
        (r"window\.frameElement", "Accessing frame element"),
        (r"window\.document($|\S+)", "DOM manipulation"),
        (r"window\.onload", "Onload event handler"),
        (r"<iframe src=.+<\/iframe>", "Suspicious iframe tags"),
        (r"(?=iframe).+(visibility=\"false\")", "Hidden iframe"),
        (r"(?=iframe).+(width=\"0\" height=\"0\" frameborder=\"0\")", "Iframe with zero dimensions"),
        (r"document\.body\.innerhtml\s*=", "Setting innerHTML directly"),
        (r"document\.createelement\(\S+\)\.innerhtml\s*=", "Element creation with innerHTML"),
        (r"addeventlistener\(\S+\)|attachevent\(\S+\)", "Adding event listeners"),
        (r"window\.location\s*=\s*['\"]\S+['\"]", "Redirection"),
    ]

    # Obfuscation or encoding that hides malicious content
    OBFUSCATION: ClassVar[list[tuple[str, str]]] = [
        (r"var\s[a-z0-9_]{25,}\s?=", "Obfuscated variable"),
        (r"(?!\\x00)\\x[0-9a-fA-F]{2}\b", "Hexadecimal encoding"),
        (r"(?!\\u0000|\\u0026|\\u2029|\\u2026|\\u2028|\\u003c|\\u003e)\\u[0-9a-fA-F]{4}", "Unicode encoding"),
        (r"array\.join\(\S*\)|string\.fromcharcode\(\S+\)", "Obfuscation using array join or string fromCharCode"),
    ]

    # Network requests and potential data exfiltration
    NETWORK_REQUESTS: ClassVar[list[tuple[str, str]]] = [
        (r"xmlhttprequest\s*=\s*new\s+xmlhttprequest", "XMLHttpRequest creation"),
        (r"\.open\(\S+,\s*\S+\)", "XMLHttpRequest open() method"),
        (r"fetch\(\S+\)", "Fetch API usage"),
        (r"https?://(?:[a-z0-9\-]+\.)+[a-z]{2,6}(:\d{1,5})?(/?|/\S+)", "Suspicious URL"),
    ]

    # Script execution, crypto mining, or unauthorized access
    EXECUTION_AND_CRYPTO: ClassVar[list[tuple[str, str]]] = [
        (r"new\s+function\s*\(\S*\)", "Dynamic function creation"),
        (r"setTimeout\(\S+\)|setInterval\(\S+\)", "Delayed script execution"),
        (r"window\.name\s*=\s*", "Modifying window.name"),
        (r"new\s+worker\(\S+\)", "Web workers (potential crypto mining)"),
        (r"import\s+crypto|require\s*\(\s*['\"]crypto['\"]\s*\)", "Crypto mining libraries"),
    ]

    NEGATIVE_LOOKAHEAD = r"(?!document\.createElement\((\"|')(script|style|img|link|meta)(\"|')\))"

    # Combine all patterns into single list
    ALL_PATTERNS: ClassVar[list[tuple[str, str]]] = (
        SUSPICIOUS_FUNCTIONS + DOM_MANIPULATION + OBFUSCATION + NETWORK_REQUESTS + EXECUTION_AND_CRYPTO
    )

    @classmethod
    def get_combined_pattern(cls: type["RegexPatterns"]) -> str:
        """Return combined regex pattern."""
        return "|".join(pattern for pattern, _ in cls.ALL_PATTERNS)

    @classmethod
    def get_pattern_explanation(cls: type["RegexPatterns"], line: str) -> str:
        """Return explanation for regex match."""
        return next(
            (explanation for pattern, explanation in cls.ALL_PATTERNS if re.search(pattern, line, re.IGNORECASE)),
            "Potentially suspicious code",
        )


class JSExtractor:
    """Extracts and analyzes JS code from web pages."""

    def __init__(self, url: str) -> None:
        """Initialize JSExtractor with a URL."""
        self.url = url
        self.user_agent = UserAgent()
        self.beautifier_options = self._setup_beautifier()
        self.regex_pattern = re.compile(RegexPatterns.get_combined_pattern(), re.IGNORECASE)
        self.seen_hashes = set()  # track and avoid duplicate JS blocks

    @staticmethod
    def _setup_beautifier() -> dict[str, Any]:
        """Set up jsbeautifier with options."""
        options = jsbeautifier.default_options()
        options.jslint_happy = True
        options.max_preserve_newlines = -1
        return options

    def fetch_page_content(self) -> str:
        """Fetch the web page content."""
        headers = {"User-Agent": self.user_agent.get_random_user_agent()}
        try:
            with requests.Session() as session:
                return self._extracted_fetch(session, headers)
        except requests.RequestException as e:
            console.print(
                ":disappointed: [red bold]Failed to fetch the page [/red bold]\n"
                f":backhand_index_pointing_right: {e}",
            )
            logging.error(f"Failed to fetch the page: {e}")
            sys.exit(1)

    def _extracted_fetch(self, session: requests.sessions.Session, headers: dict[str, str]) -> str:
        """Extracted fetch content."""
        session.headers.update(headers)
        response = session.get(self.url, timeout=10)
        response.raise_for_status()
        logging.info(f"Fetched content from {self.url}")
        return response.text

    @staticmethod
    def random_delay(min_delay: float = 0.25, max_delay: float = 1.25) -> float:
        """Return a random delay time in seconds."""
        return random.uniform(min_delay, max_delay)

    @staticmethod
    def calculate_hash(content: str) -> str:
        """Calculate hash of the content to detect duplicates."""
        return hashlib.md5(content.encode("utf-8")).hexdigest()  # noqa: S324

    def extract_js_blocks(self, html_content: str) -> list[str]:
        """Extract JS blocks from HTML content, beautify, and avoid duplicates."""
        soup = BeautifulSoup(html_content, "lxml")
        scripts = []

        for script in soup.find_all("script"):
            if script_content := script.string or "":
                script_hash = self.calculate_hash(script_content)
                if script_hash not in self.seen_hashes:
                    self.seen_hashes.add(script_hash)
                    beautified_script = jsbeautifier.beautify(script_content, self.beautifier_options)

                    if self.is_minified(beautified_script):
                        logging.info("Detected minified script, beautifying.")
                        beautified_script = jsbeautifier.beautify(beautified_script, self.beautifier_options)

                    scripts.append(beautified_script)
                    logging.debug(f"Extracted JS block (hash: {script_hash}): {beautified_script[:80]}...")
                else:
                    logging.debug(f"Duplicate JS block detected (hash: {script_hash}), skipping.")
            elif script.has_attr("src"):  # External script
                external_url = script["src"]
                if not KnownCDNs.is_known_cdn(external_url):
                    logging.info(f"Fetching external JS script: {external_url}")
                    if external_script_content := self.fetch_external_js(external_url):
                        beautified_script = jsbeautifier.beautify(external_script_content, self.beautifier_options)
                        scripts.append(beautified_script)
                        logging.debug(f"Extracted external JS block: {beautified_script[:80]}...")

        logging.info(f"Total JS blocks extracted: {len(scripts)}")
        return scripts

    # TODO: Needs work to improve accuracy
    @staticmethod
    def is_minified(js_content: str) -> bool:
        """Attempt to check if the JS content is minified."""
        return len(js_content.splitlines()) < 2 and len(js_content) > 200

    def fetch_external_js(self, url: str) -> str:
        """Fetch external JS content."""
        headers = {"User-Agent": self.user_agent.get_random_user_agent()}
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            logging.info(f"Fetched external script from {url}")
        except requests.RequestException as e:
            logging.error(f"Failed to fetch external script {url}: {e}")
            return ""
        else:
            return response.text

    def analyze_js_blocks(self, js_blocks: list[str]) -> tuple[list[str], list[str]]:
        """Analyze JS blocks for suspicious patterns."""
        suspicious_blocks = []
        all_blocks = []

        for block in js_blocks:
            beautified = jsbeautifier.beautify(block, self.beautifier_options)
            all_blocks.append(beautified)

            if self.regex_pattern.search(block):
                logging.debug(f"Suspicious block detected: {block[:80]}...")
                suspicious_blocks.append(beautified)

        return suspicious_blocks, all_blocks

    @staticmethod
    def write_to_file(file_path: Path, content: list[str]) -> None:
        """Write content to file."""
        file_path.write_text("\n".join(content), encoding="utf-8")
        logging.info(f"Wrote {len(content)} lines to {file_path}")

    def process(self) -> None:
        """Process the URL, extract JS, and save results."""
        html_content = self.fetch_page_content()
        js_blocks = self.extract_js_blocks(html_content)
        suspicious_blocks, all_blocks = self.analyze_js_blocks(js_blocks)

        self.write_to_file(EXAMINE_JS_FILE, suspicious_blocks)
        self.write_to_file(EXTRACTED_JS_FILE, all_blocks)


class ResultPrinter:
    """Prints the results of JS extraction and analysis."""

    @staticmethod
    def print_with_separators(func: Callable) -> Callable:
        """Decorator to print separators before and after."""

        @wraps(func)
        def wrapper(*args, **kwargs) -> None:
            console.print(f"[bright_black]{('.' * 50)}[/bright_black]")
            func(*args, **kwargs)
            console.print(f"[bright_black]{('.' * 50)}[/bright_black]")

        return wrapper

    @staticmethod
    @print_with_separators  # decorate print_results
    def print_results() -> None:
        """Print results of the JS examination."""
        ResultPrinter._print_suspicious_js()
        ResultPrinter._print_extracted_js()

    @staticmethod
    def _print_suspicious_js() -> None:
        """Print information about suspicious JS."""
        if EXAMINE_JS_FILE.exists() and EXAMINE_JS_FILE.stat().st_size != 0:
            console.print(f"[*] Scrutinize this JS: [cyan]{EXAMINE_JS_FILE}[/cyan]")
            content = EXAMINE_JS_FILE.read_text(encoding="utf-8")
            max_length = 40
            for n, line in enumerate(content.splitlines(), start=1):
                matches = re.finditer(RegexPatterns.get_combined_pattern(), line, re.IGNORECASE)
                for match in matches:
                    matched_text = match.group()

                    # Exclude known CDNs from being flagged as suspicious
                    if "http" in matched_text and KnownCDNs.is_known_cdn(matched_text):
                        continue

                    explanation = RegexPatterns.get_pattern_explanation(matched_text)
                    if len(matched_text) > max_length:
                        matched_text = f"{matched_text[:max_length]}..."
                    console.print(
                        f"    > Line {n}: [yellow]{matched_text}[/yellow] "
                        f"(chars {match.start()}-{match.end()}) - {explanation}",
                    )
                    logging.debug(f"Flagged line {n}: {matched_text[:max_length]}... - {explanation}")
        else:
            print("[-] Hmm, nothing to scrutinize")

    @staticmethod
    def _print_extracted_js() -> None:
        """Print information about all extracted JS."""
        if EXTRACTED_JS_FILE.exists() and EXTRACTED_JS_FILE.stat().st_size != 0:
            console.print(f"[~] All JS extracted: [cyan]{EXTRACTED_JS_FILE}[/cyan]")


def main() -> None:
    """Main function to run the script."""
    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <URL>")
        sys.exit(1)

    url = sys.argv[1]

    with console.status("Working..."):
        extractor = JSExtractor(url)
        extractor.process()
        ResultPrinter.print_results()


if __name__ == "__main__":
    main()
