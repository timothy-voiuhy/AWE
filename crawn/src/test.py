import os
import subprocess



try:
    os.pidfd_open(640)
except OSError as e :
    print(f"found exception")