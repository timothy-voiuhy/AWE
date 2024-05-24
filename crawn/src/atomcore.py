from utiliities import (
    red, 
    green, 
    cyan, 
    yellow, 
    makelogger, 
    rm_same, 
    parse_php_code, 
    NoneResException, 
    RxnLinkFinder, 
    isInternetAvailable,
    internet_check
)
from browser import Browser, BrHandler
from args import parse_args

import selenium.common.exceptions as sel_exceptions
from concurrent.futures import ProcessPoolExecutor
from bs4 import BeautifulSoup
import requests

import aiohttp
import json
import re
import queue

import tracemalloc
from typing import Text
import time
import asyncio

import sys
from pathlib import Path
from jsbeautifier import beautify
import css_html_js_minify

import os
import random
from PIL import Image
from io import BytesIO

import logging
import atexit
import urllib.parse as url_parser
import subprocess
from fileutils import ProcessJsFile, w_data_to_file, DetectXml, extract_html_forms, extract_html_inputs, replace_link

# from slimit import ast
# from slimit.parser import Parser
# from slimit.visitors import nodevisitor


# def ExtractFuncGline(javascript, target_line):
#     _parser = Parser()
#     js_tree = _parser.parse(javascript)
#     for node in nodevisitor.visit(js_tree):
#         if isinstance(node, ast.FuncDecl):
#             if (
#                     node.start_location.line <= target_line >= node.end_location.line
#             ):
#                 return javascript[node.start_pos:node.end_pos]
#     return None


def get_sources_sinks(html, file=None):
    """description: receives either raw html or an html file and
    then returns all the possible sources and sinks directed by the javascript
    in the script tags """
    sources = r"""\b(?:document\.(URL|documentURI|URLUencoded|baseURI|cookie|referrer)|location\.(href|search|hash|pathname)|window\.name|history\.(pushState|replaceState)(local|session)Storage)\b"""
    sinks = r'''\b(?:eval|evaluate|execCommand|assign|navigate|getResponseHeaderopen|showModalDialog|Function|set(Timeout|Interval|Immediate)|execScript|crypto.generateCRMFRequest|ScriptElement\.(src|text|textContent|innerText)|.*?\.onEventName|document\.(write|writeln)|.*?\.innerHTML|Range\.createContextualFragment|(document|window)\.location)\b'''
    soup = BeautifulSoup(html, 'html.parser')
    script_tags = soup.find_all(name="script")
    for tag in script_tags:
        inline_js = tag.string  # get inline js as a string
        # parse the javascript if not parserd
        parserd_js = beautify(inline_js)  # beautify the javascript that is not beautified within the DOM
        inline_js_lines = parserd_js.split("\n")
        for js_line in inline_js_lines:
            # print(js_line)
            js_line.strip().split("var")
        # extracting out variables declared by the word var


class MainRunner:
    """The main runner class for the atom 
    main_domain: main domain of the site that is to be worked on
    main_dir: the name of the directory where to save all the results of the tools
    recursive: whether to be recursive on the local files(html files)
    use:browser: whether to use the browser for handling some request blockings: Note
    that if you enable this functionality then you have to work with tool eg you may be needed to manually solve some
    captcha
    maximum_tabs: the maximum number of tabs to open when the browser is open
    tab_sleep_time: the time for which each function run asynchronously should sleep
    while waiting for manual intervention"""

    def __init__(self, main_domain="", main_dir="",projectDirPath=None, recursive=False,
                 use_browser=False, maximum_tabs=20, tab_sleep_time=10,
                 nmax_retry=5, use_http=False, requests_count=10, requests_sleep_time=1) -> None:
        if internet_check() is True:
            self.run_dir = "/media/program/01DA55CA5F28E000/MYAPPLICATIONS/AWE/AWE/crawn/"
            headers = {'Accept': '*/*',
                    'Accept-Encoding': 'gzip, deflate',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Referrer-Policy': 'origin-when-cross-origin'}
            user_agents = open(self.run_dir + "resources/user-agents.txt").readlines()
            user_agent = random.choice(user_agents).replace("\n", " ").strip()
            headers["User-Agent"] = user_agent
            self.MAIN_DOMAIN = main_domain
            self.USE_HTTP = use_http
            if main_domain.startswith(("https://", "http://")):
                self.MAIN_DOMAIN = main_domain.replace("https://", "").strip()
                self.MAIN_DOMAIN = main_domain.replace("http://", "").strip()
            else:
                self.MAIN_DOMAIN = main_domain
            # print(self.MAIN_DOMAIN)   
            self.homeDirectory = os.path.expanduser("~")
            self.projectDirPath = projectDirPath
            if self.projectDirPath is None or self.projectDirPath == "None":
                self.projectDirPath = os.path.join(self.homeDirectory,"AtomProjects/") 
            self.MAIN_DIR = os.path.join(self.projectDirPath,main_dir)
            self.headers = headers
            self.index_file = Path(self.MAIN_DIR + "/index.html")
            self.init_js_srcs_file = Path(self.MAIN_DIR + "/js_srcs")
            self.recursive = recursive
            self.init_htmlhreflinks_file = Path(self.MAIN_DIR + "/href_links")
            self.session = aiohttp.ClientSession()
            self.session_cookies = self.session.cookie_jar  # session cookies
            self.JSON_data_dir = self.MAIN_DIR + "/RESULTS"
            if os.path.exists(self.JSON_data_dir):
                pass
            else:
                os.makedirs(self.JSON_data_dir)
            self.Json_data_path = self.JSON_data_dir + "/DATA.json"
            self.current_dir = self.MAIN_DIR
            self.Data_dict = {}
            # atexit.register(self.exit_function)
            self.ip_load_b = []  # ip_address returned by the packet handler function
            self.main_domain_ips = []
            self.pg_failed_urls = []
            self.use_browser = use_browser
            self.browser_logger = makelogger("FIREFOX_LOGGER", "firefox_logger", level=logging.ERROR, projectDir=self.MAIN_DIR)
            Brw = Browser()
            if self.use_browser:
                print(cyan("\t\t Opening Browser ........"))
                self.firefox = Brw.open_firefox()
                print(yellow("\t\t Browser Open"))
                self.firefox.set_page_load_timeout(45)
                # self.firefox.start_client()
                # self.firefox.start_session()  
            self.Input_idx = 0
            self.Form_idx = 0
            self.finished_urls = set()
            self.selenium_queue = queue.Queue()
            self.REQUESTS_COUNT = requests_count
            self.REQUESTS_SLEEP_TIME = requests_sleep_time
            self.BROWSER_MAX_TABS = maximum_tabs
            self.BROWSER_TAB_SLEEP_TIME = tab_sleep_time
            self.NMAX_RETRY = nmax_retry  # retry these number of times on a site that does not return does not return a
            # status code
            self.xnlinkfinder_path =self.MAIN_DIR + "/LinkFinderResults/"
        else:
            logging.error("No internet connection")
            logging.info("Closing atomcore")
            sys.exit(1)
            


    def open_url_in_tab(self, url):
        """description: opens a new url in a new tab and then waits for manual action on 
        the page and then returns the page sources of the url and closes the window"""
        try:
            self.firefox.execute_script("window.open('', '_blank');")
            tab_index = len(self.firefox.window_handles) - 1
            self.firefox.switch_to.window(self.firefox.window_handles[tab_index])
            # self.firefox.add_cookie(self.session_cookies) 
            self.firefox.get(url)
            time.sleep(self.BROWSER_TAB_SLEEP_TIME)
            page_source = self.firefox.page_source
            return page_source
        except sel_exceptions.UnableToSetCookieException as b:
            self.browser_logger.error("Unable to add session cookies")
        except sel_exceptions.NoSuchWindowException as v:
            self.browser_logger.error("Window tab index not found")
        except sel_exceptions.WebDriverException:
            self.browser_logger.error("Getting Web driver exception")
            # self.firefox.close()
            # print(f"Getting a web driver exception ")

    # def BrowserTabHandler(self, url):
    #     """description: This handles the opening of tabs in the browser it does not allow
    #     more that the Maximum of number of tabs to run in the browser in one go"""
    #     while True:
    #         if self.Browser_open_tabs <= self.BROWSER_MAX_TABS:
    #             return self.open_url_in_tab(url)

    async def exit_function(self):
        """close the aiohttp session created by the __init__ method of the object"""
        await self.session.close()

    def w_link_content_to_file(self, link: str, data, type_="html"):
        """extract the file path from the link and then save the link content from the
        response to the file
        link: the whole link to which to save the data        : the content /response from that link
        It generally helps in restructuring the original path as it came from the server"""
        scheme_path = link.split("//")  # scheme_path = [https: , path] or  #shceme_path = [https: , path?jfdk]
        # print(scheme_path)
        if "?" in link:
            path_ver = scheme_path[1].split("?")
            _path = self.MAIN_DIR + "/" + path_ver[0]  # now after removing the ? the path we want is at index 0
        else:
            _path = self.MAIN_DIR + "/" + scheme_path[1]
            # print(_path) #path for example a/b/d/h.ext
        dir_path, file_name = os.path.split(_path)
        try:
            if not os.path.exists(path=_path):
                os.makedirs(dir_path)
                with open(_path,
                          'a') as file:  # this is where we caught the error after we try to a file that does not exist
                    file.writelines(data)
                    file.close()
            else:
                os.rmdir(_path)
                os.makedirs(dir_path)
                with open(_path, 'a') as g:
                    g.writelines(data)
                    g.close()
            return _path
        except NotADirectoryError as e:
            print(f"failed to save file with error {e}")
        except:  # #edit# if the path has no file extension
            new_filename = "new" + str(random.randint(1, 100)) + "." + type_
            new_path = os.path.join(dir_path, new_filename)
            with open(new_path, 'a') as file:
                file.writelines(data)
                file.close()
            return new_path

    def save_json_results_file(self):
        encoder = json.JSONEncoder(indent=4)
        json_str = encoder.encode(self.Data_dict)
        with open(self.Json_data_path, 'w') as file:
            file.write(json_str)

    def ConstructTagData(self, url="", element="", attrs=None, type_=""):
        if attrs is None:
            attrs = {}
        Values = {"TYPE": type_, "URL": url, "ATTRS": attrs}
        self.Data_dict[element] = Values

    async def PerformGet(self, url, get_logger) -> requests.Response.text:
        """description: makes a get request to a server and returns the contents of response.text()"""
        if self.use_browser:
            print(green(f"Processing get on url: {url}"))
            response = self.SeleniumGetPage(url)
            return "html", response, 0
        else:
            for idx in range(self.NMAX_RETRY):
                async with self.session.get(url, allow_redirects=True, headers=self.headers,
                                            timeout=300) as get_response:
                    response = await get_response.text()
                    content_type = get_response.headers.get("Content-Type", None)
                    if get_response.status in range(199, 299):
                        print(f"using url :: {green(url)}")
                        print(f"returned: {green(get_response.status)}: {cyan(get_response.reason)}")
                        break

                    elif get_response.status in [301, 302, 303, 307, 308]:
                        print(f"using url :: {green(url)}")
                        print(f"returned: {yellow(get_response.status)}: {cyan(get_response.reason)}")
                        print(f"redirected to : {yellow(get_response.url)}")
                        break

                    elif get_response.status > 399:
                        try:
                            if dict(get_response.headers)["WWW-Authenticate"] == "Basic":
                                print(f"{cyan(f'Page {url} requires basic http authentication')}")
                        except KeyError:
                            pass
                        print(f"using url :: {green(url)}")
                        print(f"returned: {red(get_response.status)}: {cyan(get_response.reason)}")

                        try:
                            br_handler = BrHandler("firefox", url, cookie_jar=None)
                            if br_handler.solve_cloudflare_V1():
                                pass
                            else:
                                if br_handler.M_detect_captcha_challenge():
                                    # self.BrowserTabHandler(url)
                                    pass
                        except TypeError as e:
                            print(f"{red('antiwaf result:')} {yellow('unable to proceed on url ')} {cyan(url)}")
                        except Exception as error:
                            print(f"anti-waf result: {error}")
                        break
                if idx == self.NMAX_RETRY - 1:
                    print(yellow("Maximum retries reached"))
            return content_type, response, get_response.status

    def ProcessUrl(self, url: str):
        w_url = None
        if url != self.MAIN_DOMAIN:
            url = url.replace("\n", "")  # strip off the newline character
            if not url.endswith("/"):  # add global page line
                url = url + "/"
            if not url.startswith(
                    ("https://", "http://", "https://www.", "http://www")):  # add scheme if does not exist
                if self.USE_HTTP:
                    url = "http://" + self.MAIN_DOMAIN + url
                    w_url = url.replace("http://", "https://www.")
                else:
                    url = "https://" + self.MAIN_DOMAIN + url
                    w_url = url.replace("http://", "https://www.")

            elif url.startswith(("https://", "http://")) and not url.startswith(("https://www.", "http://www")):
                w_url = url.replace("https://", "https://www.")
            elif url.startswith(("https://www.", "http://www")):
                w_url = url.replace("https://www.", "https://")
        else:
            url = url.replace("\n", "")  # strip off the newline character
            if not url.endswith("/"):  # add trailing line character
                url = url + "/"
            if not url.startswith(("https://", "http://")):  # add scheme if does not exist
                if self.USE_HTTP:
                    url = "http://" + url   
                else:
                    url = "https://" + url
            if url.startswith(("https://", "http://")) and not url.startswith(("https://www.", "http://www")):
                w_url = url.replace("https://", "https://www.")
                w_url = url.replace("http://", "http://www.")
        return url, w_url

    async def ProcessGet_core(self, urll, w_url, get_logger):
        try:
            response = await self.PerformGet(urll, get_logger)
            if response is not None:
                return response
            elif response is None:
                print("None")
                w_response = await self.PerformGet(w_url, get_logger)
                if w_response is not None:
                    return w_response
                else:
                    self.pg_failed_urls.append(urll)
                    raise NoneResException
        except aiohttp.ServerTimeoutError:
            print(red('server timeout:'))
        except aiohttp.TooManyRedirects:
            print(red("Too many redirects"))
        # except Exception as exception:
        #     print(exception)
        #     try:
        #         res__= await self.PerformGet(w_url,get_logger)
        #         if res__  is not None:
        #             return res__
        #         else:
        #             print(f"{red('failed to perform get with error:')} {red(f'{exception} :URL {urll}')}")
        #             self.pg_failed_urls.append(w_url)
        except aiohttp.ClientConnectionError as e:
            print(cyan(f"Encountering error : {e}"))
            return None
            # print(f"{red('check your internet connection and try again')}")
        # except Exception as excep_n:
        #     print(f"{red('failed to perform get with error:')} {yellow(excep_n)} {red(f'on url {urll}')}")    
        except TimeoutError as error:
            print(f"{yellow('request has been timed out on url: ')} {green(urll)}")
            return None
        except NoneResException:
            print(yellow("Response is None"))
            return None

    async def ProcessGet(self, urll: str):

        """processes a get request to a url and then returns a response you can\n 
        either choose to use a session or a normal get requests\n
        it also does a manual redirect if session is false but if session is true \n
        it leaves the redirect handling to the session"""

        get_logger = makelogger("ProcessGet", "get_requests.log", level=logging.INFO, projectDir=self.MAIN_DIR)
        url, w_url = self.ProcessUrl(urll)

        def get_http_v(url, w_url):
            http_url = url.replace("https://", "http://")
            http_wurl = url.replace("https://www.", "http://www.")
            return http_url, http_wurl

        # if urll not in self.finished_urls:    
        if self.USE_HTTP:
            http_url, http_w_url = get_http_v(url, w_url)
            # self.finished_urls.add(urll)
            return await  self.ProcessGet_core(http_url, http_w_url, get_logger)
        else:
            # self.finished_urls.add(urll)
            return await self.ProcessGet_core(url, w_url, get_logger)

    async def process_post(self, urll, data: dict):

        def _verbose_print(post_response, url):
            if post_response.status == 200:
                print(f"{cyan('using url:')} {url} ")
                print(f"returned {green(post_response.status)}: {cyan(post_response.reason)}")
            if post_response.status in range(299, 399):
                print(f"{cyan('using url:')} {url} ")
                print(f"returned {green(post_response.status)}: {cyan(post_response.reason)}")
            if post_response.status in range(399, 499):
                print(f"{cyan('using url:')} {url} ")
                print(f"returned {(post_response.status)}: {cyan(post_response.reason)}")

        urll, w_urll = self.ProcessUrl(urll)
        async with self.session.post(url=urll, data=data, headers=self.headers, allow_redirects=False) as post_response:
            response = await post_response.text()
            _verbose_print(post_response, urll)
            if post_response.status == 302:
                print(f"{yellow('redirecting to:')} {dict(post_response.headers)['Location']}")
                # self.session.post(new_url)
                new_url = self.MAIN_DOMAIN + str(dict(post_response.headers)["Location"])
                # print(f"main_domain {self.MAIN_DOMAIN}")
                if not new_url.startswith(("http", "https")):
                    if self.USE_HTTP:
                        new_url = "http://" + new_url
                    else:
                        new_url = "https://" + new_url
                # print(f"new_url: {new_url} ")
                new_url_u, new_url_w = self.ProcessUrl(new_url)
                # print(f"new_url_u : {new_url_u}")
                async with self.session.post(url=new_url_u, data=data, headers=self.headers,
                                             allow_redirects=False) as _post_response:
                    response = await _post_response.text()
                    _verbose_print(_post_response, new_url_u)
            else:
                pass
            return response, post_response.status

    def SeleniumGetPage(self, url):
        """uses selenium wrapper functions to get a page and return its page source"""
        if len(self.firefox.window_handles) >= self.BROWSER_MAX_TABS:
            self.selenium_queue.put(url)
        else:
            return self.open_url_in_tab(url)

    def extract_js_links(self, html):
        """description: extract the javascript sources attributed to src in the script tag"""
        # extract links
        Soup = BeautifulSoup(html, 'html.parser')
        js_scripts_tags = Soup.find_all(name="script")
        javascript_srcs = [script.get('src') for script in js_scripts_tags if script.get('src')]
        # save them to a file
        # determine file if recursive or not
        if self.recursive:
            _save_file_path = self.current_dir + "/js_srcs"
        else:
            _save_file_path = str(self.init_js_srcs_file)
        # save
        file_d = os.open(_save_file_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
        for src in javascript_srcs:
            src_str = str(src) + "\n"
            os.write(file_d, src_str.encode("utf-8"))
        os.close(file_d)
        return _save_file_path

    async def CreateIndexFiles(self):
        # create the index file and also the js_srcs file
        get_response = await self.ProcessGet(self.MAIN_DOMAIN)
        response_html = get_response[1]

        await self.retrieve_forms4rmhtml(html=response_html, url=self.MAIN_DOMAIN)
        await self.retrieve_inputs4rmhtml(html=response_html, url=self.MAIN_DOMAIN)
        # print(self.Data_dict)
        Soup = BeautifulSoup(response_html, 'html.parser')
        a = Soup.prettify()
        # creating and saving the index.html file
        # if not url.startswith("https://"):
        #     url = "https://"+url
        #     if not url.endswith("/"):
        #         url = url+"/"
        # recursively saving the index file
        if self.recursive:  # the recursive function automatically switches the current directory putting the js_srcs
            # file in the current directory
            pass
        else:
            w_data_to_file(str(self.index_file), a)
        # saving the js file
        js_scripts_tags = Soup.find_all(name="script")
        javascript_srcs = [script.get('src') for script in js_scripts_tags if script.get('src')]
        if self.recursive:  # if recursive
            path = Path("js_srcs")
            file_d = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND)
            for src in javascript_srcs:
                src_str = str(src) + "\n"
                os.write(file_d, src_str.encode("utf-8"))
            os.close(file_d)
            rm_same(path)
            return path
        else:  # if not recursive
            file_dd = os.open(self.init_js_srcs_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
            for src in javascript_srcs:
                src_str = str(src) + "\n"
                os.write(file_dd, src_str.encode("utf-8"))
            os.close(file_dd)
            return self.init_js_srcs_file

    async def get_js_links(self, url="", from_file=None) -> str:
        """description :extracts js_links from either a page given through the url 
        or through a give file at the input
          returns the file to which it has saved the js_links"""
        if from_file is not None:
            fd = os.open(from_file, os.O_RDONLY)
            html = os.read(fd, 1024 * 1024 * 1024)
            return self.extract_js_links(html)

        else:
            # create the index file and also the js_srcs file
            get_response = await self.ProcessGet(self.MAIN_DOMAIN)
            response_html = get_response[1]

            await self.retrieve_forms4rmhtml(html=response_html, url=self.MAIN_DOMAIN)
            await self.retrieve_inputs4rmhtml(html=response_html, url=self.MAIN_DOMAIN)
            # print(self.Data_dict)
            Soup = BeautifulSoup(response_html, 'html.parser')
            a = Soup.prettify()
            # creating and saving the index.html file
            if not url.startswith("https://"):
                url = "https://" + url
                if not url.endswith("/"):
                    url = url + "/"
                # recursively saving the index file
                if self.recursive:  # the recursive function automatically switches the current directory putting the
                    # js_src file in the current directory
                    pass
                else:
                    w_data_to_file(str(self.index_file), a)
            # saving the js file
            js_scripts_tags = Soup.find_all(name="script")
            javascript_srcs = [script.get('src') for script in js_scripts_tags if script.get('src')]
            if self.recursive:  # if recursive
                path = Path("js_srcs")
                file_d = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND)
                for src in javascript_srcs:
                    src_str = str(src) + "\n"
                    os.write(file_d, src_str.encode("utf-8"))
                os.close(file_d)
                rm_same(path)
                return str(path)
            else:  # if not recursive
                file_dd = os.open(self.init_js_srcs_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
                for src in javascript_srcs:
                    src_str = str(src) + "\n"
                    os.write(file_dd, src_str.encode("utf-8"))
                os.close(file_dd)
                return str(self.init_js_srcs_file)

    async def fetch_js_data(self, _link: str):
        """ fetches the js data from multiple links and saves it to a file"""
        link = _link.replace("\n", "")
        if not link.endswith("/"):
            link = link + "/"
        try:
            if link.startswith("/"):
                url = "https://" + self.MAIN_DOMAIN + link

                js_response = await self.ProcessGet(url)

                formatted_js = beautify(js_response[1])
                idx = 0
                while idx < len(formatted_js.splitlines()):
                    if DetectXml(formatted_js.splitlines()[idx]):
                        print(f"xml detected in file {url} on line {idx}")
                    idx = idx + 1
                file_path_ = self.w_link_content_to_file(url, formatted_js, type_="js")
                replace_link(self.index_file, link, file_path_)
            else:
                js_response = await self.ProcessGet(link)
                formatted_js = beautify(js_response[1])
                file_path__ = self.w_link_content_to_file(link, formatted_js, type_="js")
                replace_link(self.index_file, link, file_path__)
        except Exception as error:
            print(f"failed to process url :: {link} with error \n\t {error}")
        print("\n")

    async def get_js_content(self, file_path=None):
        """ receives a file containing links that point to javascript files of webapps
        and then gets the javascript source file, formats it and then writes it to a file 
        named its_name.js in its specific path of the mirror\n
        it also detects for the keyword xml in all the javascript downloaded files
        file_path: the file that contains all the javascript links extracted from the html of a file"""

        print("\t\t\t-------------------------------------")
        print(f"{cyan('getting the content from the js_src links in file js_srcs')}")
        print("\t\t\t-------------------------------------")

        get_js_logger = makelogger("get_js_data", "get_js_data.log", level=logging.INFO, projectDir=self.MAIN_DIR)
        try:
            # finished_links = []
            if file_path is not None:  # if file_path is not an empty string meaning that provide_file is True
                print(f"{cyan('using file')}: {yellow(file_path)}")

                file_path_ = await self.get_js_links(from_file=self.current_dir + "/" + file_path)

                with open(file_path_, 'r') as file:
                    js_links = file.readlines()
                    file.close()
                    async_tasks = []

                for link in js_links:
                    async_task = asyncio.create_task(self.fetch_js_data(link))
                    async_tasks.append(async_task)
                await asyncio.gather(*async_tasks)

            elif file_path is None:  # file_path is empty and so use self.MAIN_DOMAIN
                print(f"{red('No file provided')} :: {yellow('Using main_domain')}")

                file_path_ = await self.get_js_links()

                with open(file_path_, 'r') as file:
                    js_links = file.readlines()
                    file.close()
                    async_tasks = []
                for link in js_links:
                    async_task = asyncio.create_task(self.fetch_js_data(link))
                    async_tasks.append(async_task)
                await asyncio.gather(*async_tasks)

        except AttributeError as error:
            print(f"{cyan('failed to get the js_sources with error')} {red(error)}")
            get_js_logger.warning(f"{error}")
        except Exception as err:
            print(f"{cyan('failed to get js_sources with error')} {red(err)}")

    async def retrieve_inputs4rmhtml(self, url=None, from_file=None, html=None):
        """description : retrieve all the inputs in the DOM for each url entered
        or from a file
        """

        def inner_construct_tag_data(input_attrrs):
            for input_attr_ in input_attrrs:
                self.ConstructTagData(url, "INPUT" + str(self.Input_idx), input_attr_, type_="INPUT")
                self.Input_idx = self.Input_idx + 1

        if from_file is not None:
            fd = os.open(from_file, os.O_RDONLY)
            html = os.read(fd, 1024 * 1024 * 1024)
            input_attrrs = extract_html_inputs(html)
            inner_construct_tag_data(input_attrrs)

        elif url is None and from_file is None and html is None:
            response = await  self.ProcessGet(self.MAIN_DOMAIN)
            input_attrs = extract_html_inputs(response)
            inner_construct_tag_data(input_attrs)

        elif html is not None and url is not None:
            input_attrs__ = extract_html_inputs(html)
            inner_construct_tag_data(input_attrs__)

        elif url is not None:
            response = await self.ProcessGet(url)
            url_inputs_attrs = extract_html_inputs(response)
            inner_construct_tag_data(url_inputs_attrs)

    async def retrieve_forms4rmhtml(self, url=None, from_file=None, html=None):
        """description : retrieve all the forms in the DOM for each url entered
        or from a file
        """

        def inner_construct_tag_data(form_attrrs):
            for form_attr_ in form_attrrs:
                self.ConstructTagData(url, "FORM" + str(self.Form_idx), form_attr_, type_="FORM")
                self.Form_idx = self.Form_idx + 1

        if from_file is not None:
            fd = os.open(from_file, os.O_RDONLY)
            html = os.read(fd, 1024 * 1024 * 1024)
            form_attrrs = extract_html_forms(html.decode("utf-8"))
            inner_construct_tag_data(form_attrrs)

        elif url is None and from_file is None and html is None:
            response = await  self.ProcessGet(self.MAIN_DOMAIN)
            form_attrs = extract_html_forms(response)
            inner_construct_tag_data(form_attrs)

        elif html is not None and url is not None:
            form_attrs__ = extract_html_forms(html)
            inner_construct_tag_data(form_attrs__)

        elif url is not None:
            response = await self.ProcessGet(url)
            url_forms_attrs = extract_html_forms(response)
            inner_construct_tag_data(url_forms_attrs)

    def ExtractHrefLinks(self, html):
        """description: extract the links that are attributed to href
        from the provided html\n
        html: html from which to extract the links"""
        # print(html)
        soup = BeautifulSoup(html, 'html.parser')
        anchor_tags = soup.find_all(name='a')
        anchor_links = [tag.get("href") for tag in anchor_tags if
                        tag.get("href") and "Countries" not in tag.get("data-analytics-category", "")]
        link_tags = soup.find_all(name="link")
        links = [tag.get("href") for tag in link_tags if tag.get("href") and "alternate" not in tag.get("rel", "")]
        links = links + anchor_links
        if self.recursive:
            path = self.current_dir + "/" + "href_links"
            with open(path, 'a') as file:
                for link in links:
                    link = str(link)
                    # if self._is_inscope(link):
                    if link.endswith((".js", ".css")):
                        pass
                    else:
                        data = link + "\n"
                        file.writelines(data)
                file.close()
                rm_same(path)
            return path
        else:
            # use xnLinkFinder to get the rest the html links 
            RxnLinkFinder(rundir = self.run_dir,project_dir=self.MAIN_DIR, url=self.MAIN_DOMAIN, output_dir=self.xnlinkfinder_path, scope=[self.MAIN_DOMAIN], depth=0,
                          output_file=str(self.init_htmlhreflinks_file))
            with open(str(self.init_htmlhreflinks_file), "r") as file:
                lines = file.readlines()
                new_lines = []
                for line in lines:
                    url_ = self.ProcessUrl(line.replace("\n", "").strip())[0]
                    new_lines.append(url_ + "\n")
                file.close()
                os.remove(self.init_htmlhreflinks_file)
                with open(str(self.init_htmlhreflinks_file), "a") as file_:
                    file_.writelines(new_lines)
            with open(self.init_htmlhreflinks_file, 'a') as file:
                for link in links:
                    # if self._is_inscope(link):
                    if link.endswith((".css", ".js")):
                        pass
                    # elif link.startswith("http"): url_netloc = url_parser.urlparse(link)[1] main_domain_netloc=
                    # url_parser.urlparse(self.ProcessUrl(self.MAIN_DOMAIN))[1].replace("www.","") if url_netloc !=
                    # main_domain_netloc: pass
                    else:
                        if self.CheckScope(link):
                            link = self.ProcessUrl(link)[0]
                            data = link + "\n"
                            file.writelines(data)
                file.close()
                rm_same(self.init_htmlhreflinks_file)
            return self.init_htmlhreflinks_file

    def CheckScope(self, url):
        if url.startswith("/"):
            return True
        url_netloc = url_parser.urlsplit(url)[1]
        main_domain_netloc = url_parser.urlsplit(self.ProcessUrl(self.MAIN_DOMAIN)[0])[1].replace(".com", "").strip()
        if main_domain_netloc in url_netloc:
            return True
        else:
            return False

    async def GetHtmlLinks(self, url=None, from_file=None):
        """description: get all the links defined by the anchor and link tags from a given url\n
        or a file\n
        provide file: boolean to let the function know if the from file\n
        is to be used  :True if from_file is to be provided\n
        from_file: file from which to get the already downloaded html\n
        returns the path to which it has stored the html_links"""

        if from_file is not None:
            print(f"{cyan('File provided to GetHtmlLinks')}: {yellow(from_file)}")
            from_file = str(from_file)
            print(f"{cyan('using file path')}: {red(from_file)}")
            with open(from_file, 'r', encoding="utf-8") as m:
                html = m.read()
            # html = os.read(fd, 1024*1024*1024).decode("utf-8")
            return self.ExtractHrefLinks(html)

        elif url is not None:  # note you are not specifying to the extract function where to save the links
            response = await self.ProcessGet(urll=url)
            return self.ExtractHrefLinks(response[1])
        else:
            response = await self.ProcessGet(self.MAIN_DOMAIN)
            return self.ExtractHrefLinks(response[1])

    async def FetchHtmlData(self, _link):
        """description: retrieves all the html from a remote server and saves it to a file\n
        named by the name the file comes with or a random name"""

        global s
        link_rep = _link
        try:
            url, w_url = self.ProcessUrl(_link)
            res = await self.ProcessGet(_link)
            if res is not None:
                await self.retrieve_forms4rmhtml(html=res[1], url=url)
                await self.retrieve_inputs4rmhtml(html=res[1], url=url)
                # print(self.Data_dict)
                if "html" or "xml" in res[0]:
                    passer_options = ['html.parser', "xml.parser"]
                    for passer_ in passer_options:
                        try:
                            s = BeautifulSoup(res[1], passer_)
                            break
                        except Exception as e:
                            print(f"failed to parse data with error: {e}")
                    hmtl_data = s.prettify()
                    print(cyan("attempting to detect xml"))
                    if DetectXml(hmtl_data):
                        print(f"{red('xml detected')} in file {red(url)}")
                    else:
                        print(cyan("no xml detected"))
                    file_path = self.w_link_content_to_file(url, hmtl_data)
                    replace_link(self.index_file, link_rep, file_path)
                elif "javascript" in res[0]:
                    js_data = beautify(res[1])
                    print(cyan("attempting to detect xml"))
                    if DetectXml(js_data):
                        print(f"{red('xml detected')} in file {red(url)}")
                    else:
                        print("no xml detected")
                    file_path_ = self.w_link_content_to_file(UnicodeTranslateError, js_data, type="js")
                    replace_link(self.index_file, link_rep, file_path_)
                elif "php" in res[0]:
                    php_data = parse_php_code(res[1])
                    print(cyan("attempting to detect xml"))
                    if DetectXml(content=php_data):
                        print(f"{red('xml detected')} in file {red(url)}")
                    else:
                        print("no xml detected")
                    file_path___ = self.w_link_content_to_file(url, php_data, "php")
                    replace_link(self.index_file, link_rep, file_path___)
                elif "css" in res[0]:
                    parsed_css = css_html_js_minify.css_minify(res[0])
                    file_path____ = self.w_link_content_to_file(url, parsed_css)
                    replace_link(self.index_file, link_rep, file_path____)
                elif "png" or "gif" or "bmp" or "tif" or "jpeg" or "jpg" in res[0]:
                    image_data = BytesIO(res.content)
                    try:
                        img_data = Image.open(image_data)
                        file_path__ = self.w_link_content_to_file(url, img_data)
                        replace_link(self.index_file.html, link_rep, file_path__)
                    except OSError:
                        print("failed to open image")
                        print(f"image is of type:{res[0]}")
                print("\n")
            else:
                if not url in self.pg_failed_urls:
                    self.pg_failed_urls.append(url)
                raise Exception("Response is None")
        except Exception as exception:
            print(f"{cyan('encountered error while processing url')} {yellow(url)} : {red(exception)}")

    async def GetHtmlContent(self, html_index_file=None, dirr=""):  # on edit
        """get the content from all the links in the href tag from either a file
        if provided or a url"""
        print("\t\t\t-----------------------------------------")
        print(f"{cyan('Fetching the content from the href_links')}")
        print("\t\t\t-----------------------------------------")
        try:
            await self.CreateIndexFiles()
        except:
            logging.error("Failed to create Index files and cannot continue")
            sys.exit(1)

        async def FetchHtmlData(links):
            asyc_tasks = []
            count = 0
            for link in links:
                if count == self.REQUESTS_COUNT:
                    count = 0
                    await asyncio.sleep(self.REQUESTS_SLEEP_TIME)
                asyc_task = self.FetchHtmlData(link)
                asyc_tasks.append(asyc_task)
                count += 1
            await asyncio.gather(*asyc_tasks)

        async def WaitQueue():
            queue_links = []
            while not self.selenium_queue.empty():
                q_link = self.selenium_queue.get_nowait()
                queue_links.append(q_link)
            await FetchHtmlData(queue_links)

        if html_index_file is not None:
            print(f"{cyan('file provided')}:{yellow(html_index_file)}")
            file_path = await self.GetHtmlLinks(from_file=dirr + "/" + html_index_file)
            print(file_path)
            with open(file_path, 'r') as w:
                links = w.readlines()
                w.close()

                if self.use_browser:
                    await FetchHtmlData(links)
                    if self.selenium_queue.empty():
                        pass
                    else:
                        await WaitQueue()
                    # self.selenium_queue.join() # wait until all the urls in the queue have been processed
                else:
                    await FetchHtmlData(links)
        else:
            if self.use_browser:
                print(f"{cyan('No file provided')}:{yellow('using main_domain')}")
                file_path = await self.GetHtmlLinks(from_file=self.index_file)
                print(f"{cyan('html links saved to')} :{red(file_path)}")
                with open(file_path, 'r') as w:
                    links = w.readlines()
                    w.close()
                    await FetchHtmlData(links)
                    if self.selenium_queue.empty():
                        pass
                    else:
                        await WaitQueue()
            else:
                print(f"{cyan('No file provided')}:{yellow('using main_domain')}")
                file_path = await self.GetHtmlLinks()
                print(f"{cyan('html links saved to')} :{red(file_path)}")
                with open(file_path, 'r') as w:
                    links = w.readlines()
                    w.close()
                    asyc_tasks = []
                    processed_links = set()
                    for link in links:
                        if link not in processed_links:
                            processed_links.add(link)
                            asyc_task = self.FetchHtmlData(link)
                            asyc_tasks.append(asyc_task)
                    await asyncio.gather(*asyc_tasks)

        print(f"{cyan('FINISHED FETCHING HTML CONTENT FROM HREF LINKS')}")
        print(cyan("The following urls failed to resolve on the perform get function"))
        for _url in self.pg_failed_urls:
            print(_url)
        # print(self.Data_dict) 
        self.save_json_results_file()

    async def Recurse(self, directory: str, depth: int, recursive_logger: logging.Logger):
        try:
            idx = 0
            while idx < int(depth):
                print(cyan(f"RUNNING DEPTH {idx}"))
                for pth, dirs, files in os.walk(directory):
                    self.current_dir = pth
                    recursive_logger.info(f"handling path: {pth}")
                    print(f"path: {pth}\ndirs:{dirs}\nfiles:{files}")

                    for file in files:
                        if file.endswith(".html"):
                            print(f"{cyan('Processing file')}: {yellow(file)}")
                            if not self.use_browser:
                                await self.get_js_content(file_path=file)
                            print(f"{yellow('Done fetching js_content from links in file:')} {red(file)}")
                            await self.GetHtmlContent(html_index_file=file, dirr=pth)
                        elif file == "js_srcs":
                            print(f"{cyan('Processing file')}: {yellow(file)}")
                            await self.get_js_content(file_path=file)
                    for direc in dirs:
                        try:
                            os.chdir(direc)
                            await self.Recurse(direc)
                            print(f"{cyan('DIRECTORY CHANGED TO : ')} {yellow(directory)}")
                        except Exception as error:
                            print(f"{cyan('failed to open directory with error:')} {red(error)}")
                idx = idx + 1
        except RecursionError as error:
            recursive_logger.critical(f"recursion error: {error}")

    async def r_get_data(self, depth: int, directory=None):
        """description: recursively get the html and js files from the server\n
        for a given depth"""
        recursive_logger = makelogger("recursive_logger", "recursive_logger.log", level=logging.INFO,projectDir=self.MAIN_DIR)
        if self.recursive:
            if directory is None:
                print(cyan("no directory specified, using main directory"))
                await self.Recurse(self.MAIN_DIR, depth, recursive_logger)
            elif directory is not None:
                print(f"{cyan('using directory')}::{yellow(directory)}")
                await self.Recurse(directory, depth, recursive_logger)
        else:
            print(f"{red('failed')}: {yellow('recursive is set to False')}")

    def r_getdata_new_proc(self, directory: Path, depth):
        with ProcessPoolExecutor(max_workers=4) as executor:
            executor.submit(self.r_get_data, directory, depth)

    def extract_forms4rmjs(self, javascript):
        pass

    async def retrieve_forms4rmjs(self, provide_file: bool, url="", from_file=""):
        """detect the javascript that is supposed to create forms and then extract the 
        form in a way of virtual running the js\n
        js is provided by either url or file"""
        if provide_file:
            fd = os.open(from_file, os.O_RDONLY)
            javascript = os.read(fd, 1024 * 1024 * 1024)
            return self.extract_forms4rmjs(javascript)
        else:
            response = await self.ProcessGet(url)
            return self.extract_forms4rmjs(response)

    def detect_tech(self):
        pass

    def get_post_data(self):
        with open(self.Json_data_path, "r") as hh:
            Results_data = hh.read()
            ResultsData_dict = dict(json.loads(Results_data))
            list_post_data_dict = []
            post_data_dict = {"url": "", "auth_data_dict": {}}
            element_idx = 0
            for element in list(ResultsData_dict.items()):
                if element[1]["TYPE"] == "FORM":  # if the element is a form
                    urll, w_url = self.ProcessUrl(str(element[1]["URL"]))
                    url_components = url_parser.urlsplit(urll)
                    net_loc = url_components[1]
                    scheme = url_components[0]
                    post_url = (scheme + "://" + net_loc + element[1]["ATTRS"]["action"])
                    post_data_dict["url"] = post_url
                    elementary_idx = element_idx + 1
                    while elementary_idx < len(list(ResultsData_dict.items())):
                        # read the next elements until you meet another form
                        # and save all the names of the inputs found in a dict
                        if list(ResultsData_dict.items())[elementary_idx][1]["TYPE"] == "INPUT":
                            # print(list(ResultsData_dict.items())[elementary_idx][1]["ATTRS"]["name"])
                            post_data_dict["auth_data_dict"][
                                list(ResultsData_dict.items())[elementary_idx][1]["ATTRS"]["name"]] = ""
                        else:
                            list_post_data_dict.append(post_data_dict)
                            post_data_dict = {"url": "",
                                              "auth_data_dict": {}}  # set the post_data_dict to its default values
                            # print(list_post_data_dict)
                            break
                        if elementary_idx == len(list(ResultsData_dict.items())) - 1:
                            list_post_data_dict.append(post_data_dict)
                            # print(list_post_data_dict)
                            break
                        elementary_idx += 1
                element_idx += 1
                # print("finished")
            return list_post_data_dict

    async def manually_perform_posts(self):
        list_post_data_dict = self.get_post_data()
        for post_data in list_post_data_dict:
            print("\n")
            print(f"{green('HANDLING URL:')} {yellow(post_data['url'])}")
            print(cyan("post data needs to be filled up by the user... "))

            for auth_data_value in list(post_data["auth_data_dict"].keys()):
                post_data["auth_data_dict"][auth_data_value] = input(f"{auth_data_value} : ")
                data = post_data["auth_data_dict"]
                print(f"{cyan('Having :')} {data}")

            yn = input(f"{cyan('Do you want to add any extra data to the data_dict')}:(y/n): ")
            if yn == "y":
                nnum = int(input(cyan("How many: ")))
                for num in range(nnum):
                    key = input(cyan("key: "))
                    value = input(cyan("value: "))
                    data[key] = value
                    print(f"{cyan('Having : ')} {data}")
            else:
                pass
            response = await self.process_post(post_data["url"], data)
            print(f"response length: {len(response[0])}")
            print_response = input(cyan("do you want to print the output(y/n):"))
            if print_response == "y" or print_response == "yes":
                print(response[0])

    def get_csrf_token(self):
        pass

    async def test_sql_injection(self):
        # for each form
        # read all the input positions
        # choose which position to test
        # and in the other place choose whether to place random values or to place their correct values for which to use with the injection values
        list_post_data_dict = self.get_post_data()
        for post_data in list_post_data_dict:
            print("\n")
            print(f"{green('HANDLING URL:')} {yellow(post_data['url'])}")

            for auth_data_value in list(post_data["auth_data_dict"].keys()):
                post_data["auth_data_dict"][auth_data_value] = input(f"{auth_data_value} : ")
                data = post_data["auth_data_dict"]
                print(f"{cyan('Having :')} {data}")

            yn = input(f"{cyan('Do you want to add any extra data to the data_dict')}:(y/n): ")
            if yn == "y":
                nnum = int(input(cyan("How many: ")))
                for num in range(nnum):
                    key = input(cyan("key: "))
                    value = input(cyan("value: "))
                    data[key] = value
                    print(f"{cyan('Having : ')} {data}")
            else:
                pass
            for data_key in data.keys():  # assumption that there can only be one fuzz value per count
                if data[data_key] == "FUZZ":
                    payload_file_path = Path(input(cyan("input the path to payloads: ")))
                    if payload_file_path.exists():
                        with open(payload_file_path, "r") as p_file:
                            payloads = p_file.readlines()
                    else:
                        print(yellow("File path does not exist"))
                    for payload in payloads:
                        payload = str(payload).replace("\n", "").strip()
                        data[data_key] = payload
                        print(f"Using data dict {data}")
                        response = await self.process_post(post_data["url"], data)
                        print(f"payload: {payload} :: response length: {yellow(len(response[0]))}")

            # response = await self.process_post(post_data["url"],data)
            # print(f"response length: {len(response[0])}")
            # print_response = input(cyan("do you want to print the output(y/n):"))
            # if print_response == "y" or print_response == "yes":
            #     print(response[0])

    def TestReflectedXSS(self):
        # get all url:parameters (key value pairs for the url and the parameters) // in what dom components are url paramaters saved for a given url
        # inject an arbitrary parameter
        # test for reflections in the DOM
        # get all sinks
        # test different attack vectors for each and every sink
        # test for WAF
        # evade network firewalls and wafs
        # employ different injection mechanisms and advanced/complicated attack vectors
        pass

    def GetEndpoints(self):
        pass

    def ConstructUrlWithParameters(self, url, parameters_dict):
        pass

async def RunMainAtomFunction(domain, dirr, u_http, use_browser,projectDirPath = None, recur_=False):
    print(yellow(f"running Atom with command: atomcore -d {domain} --dirr {dirr} --use_http {u_http} --use_browser {use_browser} --rec {recur_}"))
    tracemalloc.start()
    url = str(domain)
    __url__ = str(domain)
    before_mem = tracemalloc.get_traced_memory()[0]
    cwl = MainRunner(url, dirr,projectDirPath=projectDirPath, recursive=recur_, use_http=u_http, use_browser=use_browser)

    # if not use_browser:
    #     await cwl.get_js_links()
    #     await cwl.get_js_content()

    await cwl.GetHtmlContent()
    await cwl.session.close()
    after_mem = tracemalloc.get_traced_memory()[0]
    print(f"MEMORY USED:: {((after_mem - before_mem) / (1024 * 1024)):.2f} MBS")

async def main(args):  # main function processes the args
    if len(args.domains) != len(args.dirr):
        print(red("you have entered non corresponding number of domains or dirs"))
        print(yellow("make sure the number of arguments is the same as the number of directories"))
        sys.exit()
    if args.domains and args.dirr and args.projectDirPath and not args.rec:
        targets = {}
        idx = 0
        while idx < len(args.domains):
            targets[args.domains[idx]] = args.dirr[idx]
            idx = idx + 1
        for domain, dirr in targets.items():
            await RunMainAtomFunction(domain, dirr,projectDirPath=args.projectDirPath, u_http=args.use_http, use_browser=args.use_browser)

    elif args.GetHtmlLinks and args.domain:
        cwl1 = MainRunner(args.domain)
        await cwl1.GetHtmlLinks(url=args.domain)

    elif args.htmlfiles and args.file:
        cwl2 = MainRunner(args.domain)
        cwl2.get_content_html_links(args.file, args.domain)

    elif args.rec and args.domains and args.dirr and args.depth:
        cwl = MainRunner(args.domains[0], args.dirr[0], recursive=True)
        await cwl.r_get_data(depth=args.depth)
        await cwl.session.close()

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format="%(asctime)s -%(levelname)s - %(filename)s:%(lineno)d - %(message)s")
    if len(sys.argv) == 1:
        print(cyan("you ran this program without arguments"))
    args = parse_args()
    asyncio.run(main(args))
