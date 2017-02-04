#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Main script for udemy-list."""
from __future__ import unicode_literals
from __future__ import print_function
from builtins import str
from builtins import input

import re
import os
import sys
import getpass
import argparse
import errno
import time
import logging

try:
    from urllib import unquote
except ImportError:
    from urllib.parse import unquote

import requests
import requests.sessions
import colorlog


# global variable
debug = False
debug_path = ''
logger = colorlog.getLogger(__name__)
USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:39.0) Gecko/20100101 Firefox/39.0'


# udemy.com api
LOGOUT_URL = 'http://www.udemy.com/user/logout'
LOGIN_POPUP_URL = 'https://www.udemy.com/join/login-popup'
OWN_COURSES_LIST = 'https://www.udemy.com/api-2.0/users/me/subscribed-courses?fields%5Bcourse%5D=@min,visible_instructors,image_480x270,favorite_time,archive_time,completion_ratio,last_accessed_time,enrollment_time,features&fields%5Buser%5D=@min,job_title&ordering=-enroll_time&page={page_num}&page_size={page_size}'
LOGIN_URL = 'https://www.udemy.com/join/login-popup/?displayType=ajax&display_type=popup&showSkipButton=1&returnUrlAfterLogin=https%3A%2F%2Fwww.udemy.com%2F&next=https%3A%2F%2Fwww.udemy.com%2F&locale=en_US'


def logging_exception(type_, value, tb):
    """Catch Exception message."""
    logger.error("Exception",
                 exc_info=(type_, value, tb))
    # sys.__excepthook__(type_, value, tb)


# Install exception handler
sys.excepthook = logging_exception


class Session:

    """Starting session with proper headers to access udemy site."""

    headers = {'User-Agent': USER_AGENT,
               'X-Requested-With': 'XMLHttpRequest',
               'Host': 'www.udemy.com',
               'Referer': LOGIN_POPUP_URL}

    def __init__(self):
        """Init session."""
        self.session = requests.sessions.Session()

    def set_auth_headers(self, access_token, client_id):
        """Setting up authentication headers."""
        self.headers['X-Udemy-Bearer-Token'] = access_token
        self.headers['X-Udemy-Client-Id'] = client_id
        self.headers['Authorization'] = "Bearer " + access_token
        self.headers['X-Udemy-Authorization'] = "Bearer " + access_token

    def get(self, url):
        """Retrieving content of a given url."""
        return self.session.get(url, headers=self.headers)

    def post(self, url, data):
        """HTTP post given data with requests object."""
        return self.session.post(url, data, headers=self.headers)


session = Session()


def save_debug_data(debug_data, debug_name, ext):
    """Save debug data to find bugs."""
    debug_str = str(debug_data)
    debug_str = re.sub(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", 'USER@DOMAIN.COM', debug_str)
    debug_time = time.strftime("%Y%m%d-%H%M%S")
    debug_file_name = os.path.join(debug_path, 'DEBUG-{0}-{1}.{2}'.format(debug_name, debug_time, ext))

    with open(debug_file_name, 'w', encoding='utf-8') as save_debug:
        save_debug.write(debug_str)


def get_csrf_token():
    """Extractig CSRF Token from login page."""
    try:
        response = session.get(LOGIN_POPUP_URL)
        match = re.search(r"name='csrfmiddlewaretoken'\s+value='(.*)'", response.text)
        return match.group(1)
    except AttributeError:
        session.get(LOGOUT_URL)
        response = session.get(LOGIN_POPUP_URL)
        match = re.search(r"name='csrfmiddlewaretoken'\s+value='(.*)'", response.text)
        return match.group(1)


def login(username, password):
    """Login with popup-page."""
    logger.info("Trying to log in ...")
    csrf_token = get_csrf_token()
    payload = {'isSubmitted': 1, 'email': username, 'password': password,
               'displayType': 'ajax', 'csrfmiddlewaretoken': csrf_token}
    response = session.post(LOGIN_URL, payload)

    access_token = response.cookies.get('access_token')
    client_id = response.cookies.get('client_id')
    response_text = response.text

    if '<li>You have exceeded the maximum number of requests per hour.</li>' in response_text:
        logger.error('You have exceeded the maximum number of login requests per hour.')
        sys.exit(1)

    elif '<li>Please check your email and password.</li>' in response_text:
        logger.error('Wrong Username or Password!')
        sys.exit(1)

    elif access_token is None:
        logger.error("Couldn't fetch token!")
        sys.exit(1)

    elif 'error' in response_text:
        print(response_text)
        logger.error('Found error in login page')
        sys.exit(1)

    session.set_auth_headers(access_token, client_id)

    logger.info("Login success.")

def unescape(strs):
    """Replace HTML-safe sequences "&amp;", "&lt;"" and "&gt;" to special characters."""
    strs = strs.replace("&amp;", "&")
    strs = strs.replace("&lt;", "<")
    strs = strs.replace("&gt;", ">")
    return strs

def sanitize_path(path):
    """Cleaning up path for saving files."""
    return "".join([c for c in path if c.isalpha() or c.isdigit() or c in ' .-_,']).rstrip()


def mkdir(directory):
    """Creating output directory structure, if not exist."""
    if not os.path.exists(directory):
        try:
            os.makedirs(directory)
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                raise

def is_integer(num):
    """Check if given value is an integer."""
    try:
        int(num)
        return True
    except ValueError:
        return False

def get_courses_list(user_page_num, user_page_size):
    """Return list of courses in a given page"""
    course_list_url = OWN_COURSES_LIST.format(page_num=user_page_num, page_size=user_page_size)
    courses_json = session.get(course_list_url).json()
    course_list = []

    for course in courses_json['results']:
        entry = {}
        entry['title'] = course['title']
        entry['url'] = "https://www.udemy.com" + course['url']
        print(entry['title'].encode('utf-8').strip(), ",", entry['url'])
        logger.debug('entry: %s', entry)
        course_list.append(entry)

    logger.debug('course_list: %s', course_list)
    return course_list

def get_total_pages_count(page_size_user):
    """Return total number of pages"""
    total_page_count = OWN_COURSES_LIST.format(page_num=1, page_size=32)
    total_page_count_json = session.get(total_page_count).json()
    logger.debug('total courses are: %s', total_page_count_json['count'])
    return total_page_count_json['count']/page_size_user

def list_courses(username, password, max_pages, page_size):
    """List user's courses"""
    if page_size is None or not is_integer(page_size) or page_size <= 0 or page_size > 200:
        page_size = 200
    if max_pages is None or not is_integer(max_pages) or max_pages < 0:
        max_pages = 1

    login(username, password)
    total_pages = get_total_pages_count(page_size)
    logger.debug('Total pages: %s', total_pages)
    if max_pages > total_pages or max_pages is 0:
        max_pages = total_pages

    course_list = []
    for num in range(1, max_pages+1):
        course_list.append(get_courses_list(num, page_size))

def udemy_list():
    return

def main():
    """Accepting arguments and preparing."""
    global debug
    global debug_path

    parser = argparse.ArgumentParser(description='Fetch all the courses of your udemy account', prog='udemy-list')
    parser.add_argument('-u', '--username', help='Username / Email', default=None, action='store')
    parser.add_argument('-p', '--password', help='Password', default=None, action='store')
    parser.add_argument('-ps', '--page_size', help='Number of courses in each page, max 200', default=200, action='store')
    parser.add_argument('-mp', '--max_pages', help='Max number of pages to fetch. 0 for all pages', default=1, action='store')
    parser.add_argument('--debug', help='Enable debug mode', action='store_const', const=True, default=False)

    args = vars(parser.parse_args())

    username = args['username']
    password = args['password']
    max_pages = args['max_pages']
    page_size = args['page_size']
    debug_status = args['debug']

    if debug_status:
        debug = True
        debug_path = os.path.abspath(os.path.join(".", 'debug_udemy-list', time.strftime("%Y%m%d-%H%M%S")))
        mkdir(debug_path)
        logging_name = os.path.join(debug_path, 'debugging.log')
        logging.basicConfig(filename=logging_name, filemode='w', level=0,
                            format='%(asctime)s - [%(levelname)s-%(name)s-%(lineno)d] - %(message)s')
        logger.setLevel(level=logging.DEBUG)
        logger.debug('Debug mode is enabled, debug files will be saved in : \n%s\n', debug_path)
    else:
        debug = False

    if not username:
        username = input("Username / Email : ")

    if not password:
        password = getpass.getpass(prompt='Password : ')

    list_courses(username, password, int(max_pages), int(page_size))
    sys.exit(1)


if __name__ == '__main__':
    main()
