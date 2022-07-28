# pXSS v0.2a

pXSS is a simple Python script that parses a payloads text file for all possible XSS payloads and WAF evasion included. Development version, and just publicizing
some simple auditing tools for web application testing.

pXSS checks for XSS vulnerabilities on a target web application from list of XSS payloads you provided

Requires: Python 3 and bs4 module (pip install bs4)

```
Run : $ python pXSS.py http://example.com <vuln_page> <XSS_payloads_list.txt> <HTTP_request_type>
```
# Example: 

```
$ python pXSS.py http://example.com test.php payloads.txt POST
```

# Payloads file:
```
(XSS_payloads_list.txt) included for parsing
```
