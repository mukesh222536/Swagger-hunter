# Swagger-hunter
**Swagger-hunter**

📌 **Swagger / OpenAPI Endpoint Hunter
**
This script automates the detection of publicly exposed Swagger/OpenAPI endpoints on a list of domains.
It checks across multiple URL patterns and ports (80, 443, 8080, and optionally others during deep scans) to find accessible API documentation endpoints like /swagger.json or /v3/api-docs.

Exposed Swagger/OpenAPI endpoints can reveal sensitive API details, which attackers may exploit.

✅ **Features**

Scans multiple domains concurrently (asynchronous & fast).

Checks http, https, and common alternative ports (8080 by default, 8000/9000 in deep mode).

Supports scanning single domains or a list of domains from a file.

Detects Swagger/OpenAPI endpoints by validating JSON structure (keywords: swagger, openapi, paths, info).

Saves results into a CSV file (swagger_results.csv).

Highlights vulnerable findings directly in the terminal.

Supports ignoring SSL certificate errors (--insecure).

Allows deep scans with additional ports (8000, 9000).

📦 **Requirements**

Python 3.8+

Install required packages (httpx for async requests):

pip install httpx

🚀 **Usage**
1. Scan a single domain
python3 swagger_hunter.py example.com

2. Scan multiple domains
python3 swagger_hunter.py example.com test.com api.example.org

3. Scan from a file
python3 swagger_hunter.py --list domains.txt

4. Ignore SSL errors
python3 swagger_hunter.py --list domains.txt --insecure

5. Enable deep scan (check extra ports)
python3 swagger_hunter.py --list domains.txt --deep


