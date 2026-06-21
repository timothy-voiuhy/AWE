import os
import re
from pathlib import Path
from typing import Text

from bs4 import BeautifulSoup
from jsbeautifier import beautify


def replace_link(file, link, path):
    """description: replace the actual link with the path on the disk hence
    making it possible for traversing files even on the local disk"""
    with open(file, 'r') as fd:
        file_lines = fd.readlines()
        fd.close()
    with open(file, 'w') as fil:
        fil.write("")
        fil.close()
    with open(file, 'a') as fa:
        for line in file_lines:
            if link in line:
                line = line.replace(link, path)
                fa.write(line)
            elif link not in line:
                fa.write(line)


def w_data_to_file(file_path: str, data):
    """description :save the data to a specified filepath"""
    path = Path(file_path)
    print(f"path is : {path}")
    dir_path, file_name = os.path.split(path)
    try:
        if not os.path.exists(path=path) and not os.path.isdir(dir_path):
            os.makedirs(dir_path)
            with open(path,
                      'a') as file:  # this is where we caught the error after we try to a file that does not exist
                file.writelines(data)
                file.close()
        elif os.path.isdir(dir_path):
            with open(path,
                      'a') as file:  # this is where we caught the error after we try to a file that does not exist
                file.writelines(data)
                file.close()
    except NotADirectoryError as error:
        print(f"failed with error {error}")


def DetectXml(content):
    """detect the use of xml in the content of the webapp by detecting if the word xml is used anywhere iin
    any file"""
    xmlpattern = re.compile("/.*xml.*")
    if xmlpattern.search(content):
        return True
    else:
        return False


def extract_html_inputs(html) -> list:
    soup_ = BeautifulSoup(html, 'html.parser')
    input_tags = soup_.find_all(name="input")
    inputs = []
    for input_tag in input_tags:
        inputs.append(input_tag.attrs)
    return inputs


def extract_html_forms(html: Text) -> list:
    """description: takes as input html and returns all the form attributes for
    each and every form"""
    soup__ = BeautifulSoup(html, 'html.parser')
    form_tags = soup__.find_all(name="form")
    forms = []
    for form_tag in form_tags:
        forms.append(form_tag.attrs)
    return forms


def ProcessJsFile(file):
    """process js input file and return the urls found in it"""
    urls = ""
    with open(file, "r") as file:
        data = file.read()
        js_data = beautify(data)
    return urls

