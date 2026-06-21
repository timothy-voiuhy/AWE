import argparse
import os
import sys


def parse_args():
    parser = argparse.ArgumentParser(add_help=True, description="crawl and mirror the whole front-end including all javascript and html onto a local directory")
    parser.add_argument("-d", dest="domains",nargs='+', help="domain_name of the site")
    parser.add_argument("-g", dest="get_html_links", help="get all links from the anchor and link tags and save them to a file href_links")
    parser.add_argument('-j', dest="jsfiles", help="get javascript files from the provided url")
    parser.add_argument("-a",dest="all", help="run all the funcs")
    parser.add_argument("-f", dest="htmlfiles", help="get html files from the provided url")
    parser.add_argument("-i", dest="file", help="the file for which to use with the get_<> functions")
    parser.add_argument("--version", action='version', version='main v1.0')
    parser.add_argument("--rec", dest="rec", help="crawl recursively",default=False, action='store_true')
    parser.add_argument("--depth", dest="depth", help="to what depth to crawl", action='store')
    parser.add_argument("--dirr", dest="dirr",nargs='+',default=(os.curdir), help="specify the directory into which to make the crawl")
    parser.add_argument("--use_http", dest="use_http",default=False, help="whether to use http or https", action="store_true")
    parser.add_argument("--use_browser", dest="use_browser",default=False, help="whether to use a browser for getting pages or not", action="store_true")
    parser.add_argument("-p", dest="projectDirPath", help="The project dir path incase of atomgui projects", default="None")
    args = parser.parse_args()
    if len(sys.argv) == 1:
        parser.print_help()
        exit()
    return args
