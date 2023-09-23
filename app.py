from flask import Flask, request, redirect, url_for, render_template
import os
import requests
import builtwith
import socket
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import ssl
from OpenSSL import crypto
from datetime import datetime
import logging

from logging.config import dictConfig

dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'stream': 'ext://flask.logging.wsgi_errors_stream',
        'formatter': 'default'
    }},
    'root': {
        'level': 'INFO',
        'handlers': ['wsgi']
    }
})

app = Flask(__name__)

logging.basicConfig(filename='app.log', level=logging.INFO,
                    format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        domain = request.form.get('domain')
        checks = request.form.getlist('checks')

        logging.info('Domain entered: %s', domain)  # Log domain

        results = {}

        if 'protocol' in checks:
            results['protocol'] = check_protocol(domain)
        if 'technology' in checks:
            results['technologies'] = check_technology(domain)
        if 'ports' in checks:
            results['open_ports'] = check_ports(domain)
        if 'hosting' in checks:
            results['hosting'] = check_hosting(domain)
        if 'mixed_content' in checks:
            results['mixed_content'] = check_mixed_content(domain)
        if 'ssl' in checks:
            results['ssl'] = check_ssl(domain)

        return render_template('index.html', results=results, checks=checks)
    return render_template('index.html')

def check_protocol(domain):
    if not domain.startswith(('http://', 'https://')):
        domain = f'http://{domain}'
    response = requests.get(domain)
    return {'protocol': 'https' if response.history else 'http',
            'color': 'green' if response.history else 'red'}

def check_technology(domain):
    if not domain.startswith(('http://', 'https://')):
        domain = f'http://{domain}'
    try:
        response = requests.get(domain)
        final_url = response.url  # This is the URL after all redirects
        return builtwith.parse(final_url)
    except UnicodeDecodeError:
        print(f"Couldn't decode url: {domain}")
        return {}

def check_ports(domain):
    open_ports = []
    for port in [22, 80, 443, 2082, 2083, 2086, 2087, 8880, 8443, 10000]:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            if sock.connect_ex((domain, port)) == 0:
                open_ports.append(port)
    return open_ports

def check_hosting(domain):
    ip = socket.gethostbyname(domain)
    response = requests.get(f'http://ip-api.com/json/{ip}')
    data = response.json()
    return (f"IP: {data['query']} \nISP: {data['isp']}")

def check_ssl(domain):
    cert = ssl.get_server_certificate((domain, 443))
    x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
    issuer = dict(x509.get_issuer().get_components())
    issuer = issuer.get(b'O', b'').decode()

    validity_start = datetime.strptime(x509.get_notBefore().decode('utf-8'), "%Y%m%d%H%M%SZ").strftime("%m/%d/%Y, %H:%M:%S")
    validity_end = datetime.strptime(x509.get_notAfter().decode('utf-8'), "%Y%m%d%H%M%SZ").strftime("%m/%d/%Y, %H:%M:%S")

    serial_number = x509.get_serial_number()

    return {'issuer': issuer, 'validity_start': validity_start, 'validity_end': validity_end, 'serial_number': serial_number}

def check_mixed_content(domain):
    potential_mixed_domains = ['http://gmpg.org', 'http://w3.org']
    ignored_uris = ['/wp-json/', '/wp-content/']
    clean_pages = set()

    if not domain.startswith(('http://', 'https://')):
        domain = f'https://{domain}'
    
    pages_to_check = set([domain])
    checked_pages = set()
    mixed_content_pages = {}

    while pages_to_check:
        page = pages_to_check.pop()

        # skip this iteration if the page has already been checked
        if page in checked_pages:
            continue

        checked_pages.add(page)

        # log the page that's being scanned
        logging.info(f"Scanning page: {page}")

        # add the page to clean_pages set
        clean_pages.add(page)

        # make a request to the page with a timeout
        try:
            response = requests.get(page, timeout=5)
        except requests.exceptions.Timeout:
            logging.warning(f"Timeout exceeded for {page}")
            continue

        soup = BeautifulSoup(response.content, 'html.parser')

        mixed_content_found = False
        for tag_name in ['img', 'script', 'link', 'iframe', 'embed', 'object', 'video', 'audio', 'source']:
            for tag in soup.find_all(tag_name):
                url = tag.get('src') or tag.get('href')
                if url and url.startswith('http://'):
                    mixed_content_found = True
                    mixed_content_pages[page] = {'url': url, 'type': 'confirmed'}
                    break
                elif url and any(domain in url for domain in potential_mixed_domains):
                    mixed_content_found = True
                    mixed_content_pages[page] = {'url': url, 'type': 'potential'}
                    break
            if mixed_content_found:
                break

        # If mixed content is found, remove the page from clean_pages set
        if mixed_content_found and page in clean_pages:
            clean_pages.remove(page)

        for tag in soup.find_all(['a', 'link'], href=True):
            url = urljoin(page, tag['href'])
            if url not in checked_pages and domain in url and not url.endswith(('.jpg', '.jpeg', '.png', '.gif', '.pdf')):
                if not any(uri in url for uri in ignored_uris):
                    pages_to_check.add(url)

    num_good_pages = len(clean_pages)
    num_bad_pages = len(mixed_content_pages)

    return {
        'mixed': mixed_content_pages,
        'clean': list(clean_pages),
        'num_good_pages': num_good_pages,
        'num_bad_pages': num_bad_pages,
    }

if __name__ == "__main__":
    app.run(debug=True)
