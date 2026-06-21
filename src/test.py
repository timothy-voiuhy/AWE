class testClass:
    def __init__(self) -> None:
        self.test_prm = "timothy"

    @property
    def int_property(self):
        return 6
    
    @property
    def bool_propery(self):
        return True   
    
example = testClass()
print(example.__dict__)