import sys
import os

if sys.platform == "linux":
    RUNDIR = "/media/program/data_drive/MYAPPLICATIONS/AWE/AWE/crawn/"
if sys.platform == "win32":
    RUNDIR = "D:\\MYAPPLICATIONS\\AWE\\AWE\\crawn\\"

PROXY_DUMP_DIR =  os.path.expanduser("~") + "/AtomProjects/Proxy/"
