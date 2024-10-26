# SafeScript

**SafeScript** is a powerful Python-based tool designed to identify and analyze potential Cross-Site Scripting (XSS) vulnerabilities in web applications. By assessing the HTML content from specified URLs, SafeScript helps developers enhance the security of their applications against XSS attacks.

## Features

- **Stored XSS Detection**: Identifies potential stored XSS vulnerabilities in form fields.
- **Reflected XSS Detection**: Analyzes URLs for reflected XSS payloads.
- **DOM-based XSS Detection**: Detects DOM-based XSS vulnerabilities in event handlers.
- **Comprehensive Logging**: Logs all detection results for audit and analysis.
- **User-friendly Output**: Presents vulnerabilities in a clear and understandable format.

## Installation

Before using SafeScript, ensure you have Python 3.x installed on your system. The following Python packages are required:

- `requests`
- `beautifulsoup4`
- `lxml`

You can install the required packages by running:

```bash
pip install -r requirements.txt

## Steps to install

1. Clone the repository:
  git clone https://github.com/yourusername/safescript.git
  cd safescript

2. Install the required dependencies:
  pip install -r requirements.txt

## Usage

To run SafeScript, execute the following command in your terminal:
  python safescript.py

You will be prompted to enter the URL you want to analyze:
  Enter a URL: http://example.com

SafeScript will fetch the HTML content, analyze it for XSS vulnerabilities, and display the results.

## Example output

  Detected Potential XSS Vulnerabilities:

  Stored XSS:
  - Type: Stored XSS in form field
    Field: username
    Form Action: /submit

  Reflected XSS:
  - Type: Reflected XSS in URL
    URL: http://example.com/?name=<script>alert('xss')</script>

  DOM-based XSS:
  - Type: Potential DOM-based XSS in attribute
    Element: <div>
    Attribute: onmouseover
    Value: alert('xss')

## Testing

To ensure SafeScript functions correctly, you can run the unit tests provided:
  python -m unittest test_safescript.py
This will execute the tests defined in test_safescript.py and report any issues.

## Contributing

Contributions are welcome! If you have suggestions for enhancements or new features, please fork the repository and submit a pull request. Be sure to include tests for any new functionality.

## License

SafeScript is licensed under the MIT License. See the LICENSE file for details.

## Acknowledgments

  -Requests for HTTP requests.
  -BeautifulSoup for HTML parsing.
  -lxml for efficient XML and HTML processing.

## Contact

For any inquiries or feedback, please contact your.email@example.com.

