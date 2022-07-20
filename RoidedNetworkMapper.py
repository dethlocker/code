# Integrating Nmap with Vulners, Censys, and Shodan
# Felix Alcala dethlocker@0xdeadbeef.ai
# "I am a 10, but on the pH scale; I'm just basic. A simple human. Being."
from __future__ import print_function
import os
import sys
import subprocess
import re
import time
import socket
import requests
import json
import urllib
import urllib3
import argparse
import threading
import logging
import logging.handlers
import datetime
import xml.etree.ElementTree as ET
try:
    # Python 2
    from Queue import Queue
except ImportError:
    # Python 3
    from queue import Queue

# Global variables
# ----------------------------------------------------------------------------------------------------------------------
# Logging
logger = logging.getLogger('nmap_scanner')
logger.setLevel(logging.DEBUG)

# create file handler which logs even debug messages
fh = logging.handlers.RotatingFileHandler('nmap_scanner.log', maxBytes=10485760, backupCount=5)
fh.setLevel(logging.DEBUG)

# create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)

# create formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
ch.setFormatter(formatter)

# add the handlers to the logger
logger.addHandler(fh)
logger.addHandler(ch)

# Nmap
nmap_path = '/usr/bin/nmap'
nmap_args = '-sV -Pn -T4 -p- -oX'
nmap_output_file = 'nmap_scan.xml'
nmap_output_file_path = os.path.join(os.getcwd(), nmap_output_file)

# Shodan
shodan_api_key = 'YOUR_SHODAN_API_KEY'
shodan_api_url = 'https://api.shodan.io/shodan/host/'

# Censys
censys_api_id = 'YOUR_CENSYS_API_ID'
censys_api_secret = 'YOUR_CENSYS_API_SECRET'
censys_api_url = 'https://censys.io/api/v1/search/ipv4'

# Vulners
vulners_api_url = 'https://vulners.com/api/v3/burp/software/'

# Threads
threads_number = 10

# Queues
queue_lock = threading.Lock()
ip_queue = Queue()

# ----------------------------------------------------------------------------------------------------------------------


def nmap_scan(ip_address):
    """
    Run nmap with the entered IP range
    :param ip_address: IP address
    :return:
    """
    logger.info('Running nmap scan for %s' % ip_address)
    nmap_command = '%s %s %s %s %s' % (nmap_path, nmap_args, nmap_output_file, ip_address, ip_address)
    logger.debug('Nmap command: %s' % nmap_command)
    try:
        subprocess.check_output(nmap_command, shell=True)
    except subprocess.CalledProcessError as e:
        logger.error('Nmap scan failed for %s' % ip_address)
        logger.error(e.output)
        return False
    logger.info('Nmap scan completed for %s' % ip_address)
    return True


def verify_services(ip_address):
    """
    Verify services and applications running on open TCP ports
    :param ip_address: IP address
    :return:
    """
    logger.info('Verifying services for %s' % ip_address)
    try:
        tree = ET.parse(nmap_output_file_path)
        root = tree.getroot()
    except Exception as e:
        logger.error('Failed to parse nmap output file')
        logger.error(e)
        return False
    for host in root.findall('host'):
        for address in host.findall('address'):
            if address.get('addr') == ip_address:
                for port in host.findall('ports/port'):
                    if port.find('state').get('state') == 'open':
                        port_number = port.get('portid')
                        port_protocol = port.get('protocol')
                        port_service = port.find('service').get('name')
                        port_product = port.find('service').get('product')
                        port_version = port.find('service').get('version')
                        logger.info('%s/%s %s %s %s' % (port_number, port_protocol, port_service, port_product,
                                                        port_version))
    logger.info('Services verified for %s' % ip_address)
    return True


def shodan_scan(ip_address):
    """
    Find vulnerabilities to the open TCP ports
    :param ip_address: IP address
    :return:
    """
    logger.info('Running Shodan scan for %s' % ip_address)
    try:
        shodan_api_request = requests.get(shodan_api_url + ip_address,
                                          params={'key': shodan_api_key},
                                          timeout=10)
    except requests.exceptions.RequestException as e:
        logger.error('Shodan scan failed for %s' % ip_address)
        logger.error(e)
        return False
    if shodan_api_request.status_code == 200:
        shodan_api_response = json.loads(shodan_api_request.text)
        logger.info('Shodan scan completed for %s' % ip_address)
        logger.info('Shodan scan results for %s' % ip_address)
        logger.info(json.dumps(shodan_api_response, indent=4, sort_keys=True))
        return True
    else:
        logger.error('Shodan scan failed for %s' % ip_address)
        logger.error(shodan_api_request.text)
        return False


def censys_scan(ip_address):
    """
    Find vulnerabilities to the open TCP ports
    :param ip_address: IP address
    :return:
    """
    logger.info('Running Censys scan for %s' % ip_address)
    try:
        censys_api_request = requests.post(censys_api_url,
                                           auth=(censys_api_id, censys_api_secret),
                                           data=json.dumps({'query': ip_address, 'page': 1, 'fields': ['ip', 'protocols']}),
                                           timeout=10)
    except requests.exceptions.RequestException as e:
        logger.error('Censys scan failed for %s' % ip_address)
        logger.error(e)
        return False
    if censys_api_request.status_code == 200:
        censys_api_response = json.loads(censys_api_request.text)
        logger.info('Censys scan completed for %s' % ip_address)
        logger.info('Censys scan results for %s' % ip_address)
        logger.info(json.dumps(censys_api_response, indent=4, sort_keys=True))
        return True
    else:
        logger.error('Censys scan failed for %s' % ip_address)
        logger.error(censys_api_request.text)
        return False


def vulners_scan(ip_address):
    """
    Find vulnerabilities to the open TCP ports
    :param ip_address: IP address
    :return:
    """
    logger.info('Running Vulners scan for %s' % ip_address)
    try:
        tree = ET.parse(nmap_output_file_path)
        root = tree.getroot()
    except Exception as e:
        logger.error('Failed to parse nmap output file')
        logger.error(e)
        return False
    for host in root.findall('host'):
        for address in host.findall('address'):
            if address.get('addr') == ip_address:
                for port in host.findall('ports/port'):
                    if port.find('state').get('state') == 'open':
                        port_number = port.get('portid')
                        port_protocol = port.get('protocol')
                        port_service = port.find('service').get('name')
                        port_product = port.find('service').get('product')
                        port_version = port.find('service').get('version')
                        logger.info('%s/%s %s %s %s' % (port_number, port_protocol, port_service, port_product,
                                                        port_version))
                        vulners_api_request = requests.get(vulners_api_url + port_product,
                                                           params={'version': port_version},
                                                           timeout=10)
                        if vulners_api_request.status_code == 200:
                            vulners_api_response = json.loads(vulners_api_request.text)
                            logger.info('Vulners scan completed for %s' % ip_address)
                            logger.info('Vulners scan results for %s' % ip_address)
                            logger.info(json.dumps(vulners_api_response, indent=4, sort_keys=True))
                            return True
                        else:
                            logger.error('Vulners scan failed for %s' % ip_address)
                            logger.error(vulners_api_request.text)
                            return False
    logger.info('Vulners scan completed for %s' % ip_address)
    return True


def process_ip(thread_name):
    """
    Process IP address
    :param thread_name: Thread name
    :return:
    """
    while not ip_queue.empty():
        queue_lock.acquire()
        if not ip_queue.empty():
            ip_address = ip_queue.get()
            queue_lock.release()
            logger.info('%s processing %s' % (thread_name, ip_address))
            nmap_scan(ip_address)
            verify_services(ip_address)
            shodan_scan(ip_address)
            censys_scan(ip_address)
            vulners_scan(ip_address)
        else:
            queue_lock.release()
    logger.info('%s exiting' % thread_name)


def main():
    """
    Main function
    :return:
    """
    # Parse arguments
    parser = argparse.ArgumentParser(description='Nmap scanner')
    parser.add_argument('-i', '--ip', help='IP address', required=True)
    args = parser.parse_args()

    # Check if IP address is valid
    try:
        socket.inet_aton(args.ip)
    except socket.error:
        logger.error('Invalid IP address')
        sys.exit(1)

    # Create new threads
    for i in range(threads_number):
        thread = threading.Thread(target=process_ip, args=('Thread-%s' % i,))
        thread.start()

    # Fill the queue
    queue_lock.acquire()
    ip_queue.put(args.ip)
    queue_lock.release()

    # Wait for queue to empty
    while not ip_queue.empty():
        pass

    # Notify threads it's time to exit
    exit()


if __name__ == '__main__':
    main()
