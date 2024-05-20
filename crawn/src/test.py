

class class_two:
    def __init__(self, parent = None) -> None:
        parent.threads.append("this is a threads")

class class_one:
    def __init__(self) -> None:
        self.threads = []
        c_t = class_two(parent=self)
    
    def printThreads(self):
        print(self.threads)

c_o = class_one()
c_o.printThreads()