#!/usr/bin/env python

from Wappalyzer import Wappalyzer, WebPage
import requests
from pathlib import Path
from colorama import Fore, Back, Style
import warnings
from config.config import WAPPALZER_RUN_DIR
import os
warnings.filterwarnings("ignore")

def find_version(a):
  if a == []:
   return 'nil'
  else:
   return a[0]

def getWriteFilePath(url:str):
  if not Path(WAPPALZER_RUN_DIR).is_dir():
    os.mkdir(WAPPALZER_RUN_DIR)
  filename = url.split("://")[1].replace("/", "_").replace("?", "_")
  filepath = os.path.join(WAPPALZER_RUN_DIR, filename)
  if os.path.exists(filepath):
    return filepath, True 
  else:
    return filepath, False

def find_techs(url):
  writefile, exists = getWriteFilePath(url)
  if not exists:
    if writefile != '':
      j = open(writefile, 'a')
    else:
      j = None
    if '.' in url and 'http' not in url:
      t = 'http://'+url
      try:
          url = requests.head(t, allow_redirects=True).url
      except:
          print("[+] Some error occurred while resolving")
          return

    try:
      webpage = WebPage.new_from_url(url)
      wappalyzer = Wappalyzer.latest()
      techs = wappalyzer.analyze_with_versions_and_categories(webpage)
    except:
      return Style.BRIGHT + Fore.RED + "\n[!] SOME ERROR OCCURED FOR " + url

    nurl = url.split("//")[1].rstrip("/")

    if j : 
      j.write("\n[+]" + "TECHNOLOGIES" + f"[{nurl.upper()}]" + ":\n")
    for i in techs:
      if j : 
        j.write(f"{techs[i]['categories'][0]} : {i} [version: {find_version(techs[i]['versions'])}]\n")
    j.close()
    with open(writefile, "r") as file:
      return file.read()
  else:
    with open(writefile, "r") as file:
      return file.read()
  
