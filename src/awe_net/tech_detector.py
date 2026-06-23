#!/usr/bin/env python

from wappalyzer import Wappalyzer
import requests
from pathlib import Path
from colorama import Fore, Style
import warnings
from config.config import WAPPALZER_RUN_DIR
import os
warnings.filterwarnings("ignore")

try:
  from wappalyzer.core.utils import get_cats_and_groups
  from wappalyzer.core.config import tech_db
  _has_cats = True
except Exception:
  _has_cats = False

def _get_category(tech_name):
  if _has_cats and tech_name in tech_db:
    cats, _ = get_cats_and_groups(tech_name)
    return cats[0] if cats else "Unknown"
  return "Unknown"

def getWriteFilePath(url:str):
  if not Path(WAPPALZER_RUN_DIR).is_dir():
    os.makedirs(WAPPALZER_RUN_DIR, exist_ok=True)
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
      wappalyzer = Wappalyzer()
      result = wappalyzer.analyze(url)
      techs = result.get(url, {})
    except Exception as e:
      return Style.BRIGHT + Fore.RED + f"\n[!] SOME ERROR OCCURED FOR {url}: {str(e)}"

    nurl = url.split("//")[1].rstrip("/")

    if j:
      j.write("\n[+]" + "TECHNOLOGIES" + f"[{nurl.upper()}]" + ":\n")
    for tech_name, tech_data in techs.items():
      if j:
        category = _get_category(tech_name)
        version = tech_data.get('version') or 'nil'
        j.write(f"{category} : {tech_name} [version: {version}]\n")
    if j:
      j.close()
    with open(writefile, "r") as file:
      return file.read()
  else:
    with open(writefile, "r") as file:
      return file.read()
  
