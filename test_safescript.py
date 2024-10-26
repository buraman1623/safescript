import unittest
from safescript import analyze_html, detect_xss  # Replace with the actual module name if different

class TestXSSDetection(unittest.TestCase):

    def test_stored_xss(self):
        html_content = '''
        <html>
            <body>
                <form action="/submit">
                    <input type="text" name="username">
                    <input type="submit">
                </form>
            </body>
        </html>
        '''
        entry_points = analyze_html(html_content)
        vulnerabilities = detect_xss(entry_points)
        self.assertIn('stored_xss', vulnerabilities)
        self.assertEqual(len(vulnerabilities['stored_xss']), 1)
        self.assertEqual(vulnerabilities['stored_xss'][0]['field'], 'username')

    def test_reflected_xss(self):
        html_content = '''
        <html>
            <body>
                <a href="http://example.com/?name=<script>alert('xss')</script>">Click here</a>
            </body>
        </html>
        '''
        entry_points = analyze_html(html_content)
        vulnerabilities = detect_xss(entry_points)
        self.assertIn('reflected_xss', vulnerabilities)
        self.assertEqual(len(vulnerabilities['reflected_xss']), 1)
        self.assertIn('<script>alert(\'xss\')</script>', vulnerabilities['reflected_xss'][0]['url'])

    def test_dom_based_xss(self):
        html_content = '''
        <html>
            <body>
                <div onmouseover="alert('xss')">Hover over me</div>
            </body>
        </html>
        '''
        entry_points = analyze_html(html_content)
        vulnerabilities = detect_xss(entry_points)
        self.assertIn('dom_based_xss', vulnerabilities)
        self.assertEqual(len(vulnerabilities['dom_based_xss']), 1)
        self.assertEqual(vulnerabilities['dom_based_xss'][0]['element'], 'div')
        self.assertEqual(vulnerabilities['dom_based_xss'][0]['attribute'], 'onmouseover')

    def test_no_xss(self):
        html_content = '''
        <html>
            <body>
                <h1>Welcome to our website</h1>
            </body>
        </html>
        '''
        entry_points = analyze_html(html_content)
        vulnerabilities = detect_xss(entry_points)
        self.assertIn('stored_xss', vulnerabilities)
        self.assertEqual(len(vulnerabilities['stored_xss']), 0)
        self.assertIn('reflected_xss', vulnerabilities)
        self.assertEqual(len(vulnerabilities['reflected_xss']), 0)
        self.assertIn('dom_based_xss', vulnerabilities)
        self.assertEqual(len(vulnerabilities['dom_based_xss']), 0)

if __name__ == '__main__':
    unittest.main()

