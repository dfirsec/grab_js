# Grab JS

![Generic badge](https://img.shields.io/badge/python-3.11-blue.svg) [![Twitter](https://img.shields.io/badge/Twitter-@pulsecode-blue.svg)](https://twitter.com/pulsecode)

Python script to retrieve and analyze JavaScript code blocks from a given URL.

## Installation

```text
git clone https://github.com/dfirsec/grab_js.git
cd grab_js
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
