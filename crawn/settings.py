import json
import tempfile

def convert_obj_dict(obj):
    """convert an object to a dictionary"""
    if isinstance(obj,settings):
        return obj.__dict__
    return obj

class settings():
    """recieves data from the command line that are to be passes to the thpmanager
    generates a json configuration file"""
    def __init__(self, main_url, threads = 0, n_processes=0,
                h_filename ="href_links", j_filename= "js_srcs",urls:list = [])->None: #have default settings for settings whose values has not been provided
        self.main_url = main_url
        self.urls = urls
        self.threads = threads
        self.processses = n_processes
        self.h_filename = h_filename
        self.j_filename = j_filename

    def generate_config_file(self, config_file_name="settings.json"):
        main_dict = {"main_url":self.main_url,
                     "urls":self.urls,
                     "n_processes":self.processses,
                     "j_fiilename":self.j_filename}
        json_main_dict = json.dumps(main_dict)
        with open(config_file_name, 'a') as json_file:
            json_file.write(json_main_dict)

setting0 = settings(main_url="mak.ac.ug")
setting0.generate_config_file()


# setting = settings()        