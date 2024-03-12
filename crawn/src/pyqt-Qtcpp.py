import re
import functools
import json 
import os

function_regex = "(?<!\s)def(?=\s).*\(.*\).*\:"
class_regex = "class(?=\s) .*\:|class .*\(.*\)\:"
class_function_regex = "def .*\(self.*\).*\:"
args_regex = "\(.*\)"
function_pattern = re.compile(function_regex)
class_pattern = re.compile(class_regex)
class_function_pattern = re.compile(class_function_regex)
args_pattern = re.compile(args_regex)

def has_args(element):
    if len(args_pattern.findall(element)) == 0:
        return False
    return True

class pythonQtParser:
    def __init__(self, filename) -> None:
        self.filename = filename
        self.classBlocks = []
        self.functionBlocks = []
        self.classes = []
        self.classesStructure = {"classes:":[]}
        self.classesStructureFile = "./classesStructure.json"
        with open(filename, "r") as file:
            self.filelines  = file.readlines()

        with open(self.filename, "r") as file:
            self.fileString = file.read()

    def getBlocks(self):
        def getBlck(fl, class_:bool=True, ln_idx=None):
            blck = []

            blocks = self.functionBlocks
            if class_:
                blocks = self.classBlocks

            blck.append(fl)
            for ln in self.filelines[(ln_idx+1):]:
                if ln.startswith(" ") or ln.startswith("#") or len(ln) == 1:
                    blck.append(ln)
                else:
                    break
            blocks.append(blck) 
        ln_idx = 0
        for fl in self.filelines:
            if len(class_pattern.findall(fl)) != 0:
                getBlck(fl, ln_idx=ln_idx)
            elif len(function_pattern.findall(fl)) != 0 and not fl.startswith("#"):
                getBlck(fl, class_=False, ln_idx=ln_idx)
            ln_idx += 1

    def writeClassesStructFile(self):
        jsonClassesStructure  = json.dumps(self.classesStructure,indent=4)
        with open(self.classesStructureFile, "w") as file:
            file.write(jsonClassesStructure)

    def getClassesStructure(self):
        for clss in self.classBlocks:

            class_repr_ = {"class_name":"","class_inherits":[],"functions":[]}
            class_decl = clss[0]
            # get class_name
            if has_args(class_decl):
                class_name = class_decl.replace("class","").strip().split("(")[0]
            else:
                class_name = class_decl.replace("class","").strip().replace(":","")
            class_repr_["class_name"] = class_name
            # get class inherits
            class_inherits = []
            if has_args(class_decl):
                args = str(args_pattern.findall(class_decl)[0]).replace("(", "").replace(")","").split(",")
                class_inherits.extend(args)
            class_repr_["class_inherits"] = class_inherits    

            class_functions = []
            # get class functions
            for fline in clss[1:]:
                class_function_decl = class_function_pattern.findall(fline)
                if len(class_function_decl) != 0: # found class function
                    function_repr_ = {"function_name":"","function_args":[]}
                    class_function_decl_ = str(class_function_decl[0])

                    # get function name
                    function_name = class_function_decl_.split("(")[0].replace("def","").strip()
                    function_repr_["function_name"] = function_name

                    # get function args
                    function_args = []
                    if has_args(class_decl):
                        args = str(args_pattern.findall(class_function_decl_)[0]).replace("(", "").replace(")","").split(",")
                        function_args.extend(args)
                    function_repr_["function_args"] = function_args 
                    class_functions.append(function_repr_)

                    class_repr_["functions"] = class_functions    
            # print(class_repr_)
            self.classes.append(class_repr_)
            self.classesStructure["classes"] = self.classes                     

parser = pythonQtParser("atomgui.py")
# parser.parseFile()
parser.getBlocks()
parser.getClassesStructure()
parser.writeClassesStructFile()
# for ll in parser.classBlocks[5]:
#     print(ll)