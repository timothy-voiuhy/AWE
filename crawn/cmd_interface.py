import sys
from atomcore import MainRunner
import asyncio
from utiliities import green, yellow, red, cyan 
import subprocess
from asynccmd import Cmd

print("\n")
print(green("Fill the main runner configuration settings"))

class Atomcmd(Cmd):
    def __init__(self):
        main_domain = input(cyan("input the main domain: "))
        main_directory = input(cyan("input the main directory: "))
        recursive = bool(input(cyan("do you want to be recursive in the crawl(True/False): ")))
        use_browser = bool(input(cyan("do you want to use the browser for 404's(if not press Enter): ")))
        self.cwl  = MainRunner(main_domain=main_domain, main_dir=main_directory,
                  recursive=recursive,use_browser=use_browser)
        super().__init__()

    def do_process_get(self,url):
        response = asyncio.run(self.cwl.process_get(url))
        print(response[1]) 

    def do_exit(self, arg):
        return True

    def do_shell(self,command):# run a shell commmand
        sub_cmd = subprocess.Popen(command, shell=True, stdout= subprocess.PIPE)
        output = sub_cmd.communicate()[0]
        print(output)
    
async def main():
    Atomcmd_  = Atomcmd()
    await run_cmdloop(Atomcmd_)

if __name__ == "__main__":
    asyncio.run(main())