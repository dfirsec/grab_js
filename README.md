# Grab JS

Python script to retrieve and analyze JavaScript code blocks from a given URL.

## Requirements

- Python 3.11+
- BeautifulSoup4
- jsbeautifier
- requests

## Installation

1. Clone this repository:

    ```text
    git clone https://github.com/dfirsec/grab_js.git
    cd grab_js
    ```

2. Install the required packages:

    ```text
    poetry install
    ```

## Usage

1. Start the shell with the following:

    ```text
    poetry shell
    ```

2. Run the following command:

    ```text
    $ python grab_js.py <URL>
    ..................................................
    [*] Scrutinize this JS: examine_js.txt
        > Line 3: document.write('<script type="application/javascript" src="/pf/dist/engine/polyfill.js?d=295" defer=""><\/script>') (chars 0-115)
        > Line 15: document.createElement("iframe") (chars 17-49)
        > Line 20: Window.document (chars 13-28)
        > Line 22: Window.document (chars 108-123)
    [~] All JS extracted: extracted_js.txt
    ```

### Output

The script generates two files:

`examine_js.txt`: Contains JavaScript blocks flagged as potentially suspicious
`extracted_js.txt`: Contains all extracted JavaScript blocks

Console output provides a summary of suspicious patterns found, including line numbers and brief explanations.

### Logging

The script logs activities to `js_analysis.log` for debugging or auditing.

## Disclaimer

This tool is for educational and research purposes only. Always ensure you have permission before analyzing websites you do not own or operate.

## License

MIT License
