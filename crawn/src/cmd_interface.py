import sys
from atomcore import MainRunner
import asyncio
from utiliities import green, yellow, red, cyan 
import subprocess
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor

print("\n")
print(green("Fill the main runner configuration settings"))

class Atomcmd():
    """ a rudementary implementation of a commandline interface for the program"""
    def __init__(self):
        main_domain = input(cyan("input the main domain: "))
        main_directory = input(cyan("input the main directory: "))
        recursive = bool(input(cyan("do you want to be recursive in the crawl(True/False): ")))
        use_browser = bool(input(cyan("do you want to use the browser for 404's(if not press Enter): ")))
        self.cwl  = MainRunner(main_domain=main_domain, main_dir=main_directory,
                  recursive=recursive,use_browser=use_browser)
        super().__init__()

    def cmd_get(self,url):
        response = asyncio.run(self.cwl.ProcessGet(url))
        print(response[1])

    def do_exit(self, arg):
        return True

    def do_shell(self,command):# run a shell commmand
        sub_cmd = subprocess.Popen(command, shell=True, stdout= subprocess.PIPE)
        output = sub_cmd.communicate()[0]
        print(output)

    def cmdloop(self):
        # run the main loop
        pass
    
def main():
    Atomcmd_  = Atomcmd()
    Atomcmd_.cmdloop()

if __name__ == "__main__":
    main()