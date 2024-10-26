import requests
import re
from bs4 import BeautifulSoup
import logging

# Set up logging
logging.basicConfig(filename='xss_detection.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def fetch_page(url):
    """
    Fetch the HTML content of a given URL.
    
    Args:
        url (str): The URL to fetch.
    
    Returns:
        str or None: The HTML content of the page, or None if the request fails.
    """
    try:
        # Check if the URL starts with "http://" or "https://"
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for bad responses
        return response.text
    except requests.RequestException as e:
        # Log the error and return None
        logging.error(f"Error fetching {url}: {e}")
        return None

def analyze_html(html_content):
    """
    Analyze the HTML content for potential XSS vulnerabilities.
    
    Args:
        html_content (str): The HTML content to analyze.
    
    Returns:
        dict: A dictionary containing information about potential vulnerabilities.
    """
    # Parse the HTML using BeautifulSoup
    soup = BeautifulSoup(html_content, 'lxml')
    
    # Collect information about potential entry points
    entry_points = {
        'forms': [],
        'urls': [],
        'other_elements': []
    }
    
    # Find form elements
    for form in soup.find_all('form'):
        entry_points['forms'].append({
            'action': form.get('action'),
            'fields': [field.get('name') for field in form.find_all('input')]
        })
    
    # Find URL parameters
    for link in soup.find_all('a'):
        href = link.get('href')
        if '?' in href:
            entry_points['urls'].append(href)
    
    # Find other potential entry points (e.g., attributes, event handlers)
    for element in soup.find_all():
        for attr, value in element.attrs.items():
            if attr.lower() in ['onclick', 'onerror', 'onload']:
                entry_points['other_elements'].append({
                    'element': element.name,
                    'attribute': attr,
                    'value': value
                })
    
    return entry_points

def detect_xss(entry_points):
    """
    Detect potential XSS vulnerabilities based on entry points.
    
    Args:
        entry_points (dict): Dictionary containing potential entry points.
    
    Returns:
        dict: A dictionary categorizing detected XSS vulnerabilities.
    """
    vulnerabilities = {
        'stored_xss': [],
        'reflected_xss': [],
        'dom_based_xss': []
    }

    # Common XSS patterns
    xss_patterns = [
        r'<script.*?>.*?</script>',  # Inline script tags
        r'javascript:',               # JavaScript URLs
        r'(<img.*?src=.*?onerror=.*?>)',  # Image onerror handlers
        r'(<iframe.*?src=.*?>)',     # Iframes
        r'(<a.*?href=.*?javascript:)', # Anchor tags with JS
        r'\b(alert|confirm|prompt)\b',  # Common JS functions
        r'(<body.*?onload=.*?>)',    # Body onload handlers
        r'(<div.*?onmouseover=.*?>)'  # Mouseover handlers
    ]

    # Check forms for potential stored XSS in input fields
    for form in entry_points['forms']:
        for field in form['fields']:
            if field:  # Check if field name is not empty
                vulnerabilities['stored_xss'].append({
                    'type': 'Stored XSS in form field',
                    'field': field,
                    'form_action': form['action'],
                })

    # Check URLs for potential reflected XSS
    for url in entry_points['urls']:
        if any(re.search(pattern, url, re.IGNORECASE) for pattern in xss_patterns):
            vulnerabilities['reflected_xss'].append({
                'type': 'Reflected XSS in URL',
                'url': url,
            })

    # Check other elements for potential DOM-based XSS
    for entry in entry_points['other_elements']:
        if any(re.search(pattern, entry['value'], re.IGNORECASE) for pattern in xss_patterns):
            vulnerabilities['dom_based_xss'].append({
                'type': 'Potential DOM-based XSS in attribute',
                'element': entry['element'],
                'attribute': entry['attribute'],
                'value': entry['value'],
            })

    return vulnerabilities

def print_vulnerabilities(vulnerabilities):
    """
    Print the detected XSS vulnerabilities in a user-friendly format.
    
    Args:
        vulnerabilities (dict): Dictionary categorizing detected XSS vulnerabilities.
    """
    print("\nDetected Potential XSS Vulnerabilities:\n")

    if vulnerabilities['stored_xss']:
        print("Stored XSS:")
        for vuln in vulnerabilities['stored_xss']:
            print(f"- Type: {vuln['type']}")
            print(f"  Field: {vuln['field']}")
            print(f"  Form Action: {vuln['form_action']}\n")

    if vulnerabilities['reflected_xss']:
        print("Reflected XSS:")
        for vuln in vulnerabilities['reflected_xss']:
            print(f"- Type: {vuln['type']}")
            print(f"  URL: {vuln['url']}\n")

    if vulnerabilities['dom_based_xss']:
        print("DOM-based XSS:")
        for vuln in vulnerabilities['dom_based_xss']:
            print(f"- Type: {vuln['type']}")
            print(f"  Element: <{vuln['element']}>")
            print(f"  Attribute: {vuln['attribute']}")
            print(f"  Value: {vuln['value']}\n")

    if not any(vulnerabilities.values()):
        print("No potential XSS vulnerabilities detected.")

if __name__ == "__main__":
    url = input("Enter a URL: ")
    html_content = fetch_page(url)
    if html_content:
        entry_points = analyze_html(html_content)
        vulnerabilities = detect_xss(entry_points)
        print_vulnerabilities(vulnerabilities)
        logging.info("Detected Potential XSS Vulnerabilities: %s", vulnerabilities)  # Log the results
    else:
        print("Failed to retrieve content.")

