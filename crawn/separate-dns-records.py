from pathlib import Path
import os
import re

# create_name_record_files("amass_enumeration")   

def get_links(file, to_file):
    with open(file, 'r')as file:
        lines = file.readlines()
        file.close()
        file_d = os.open(to_file, os.O_WRONLY | os.O_CREAT |os.O_TRUNC)
        for line in lines:
            m =line.split("-->")
            if "stripe" in line:
                os.write(file_d, (m[0].replace("(FQDN)","")+"\t\t"+m[2].replace("(IPAddress)","")).encode("utf-8"))
                    
def get_asnlinks(file, asns_file):
    with open(file, 'r')as file:
        lines = file.readlines()
        file.close()
        file_d0 = os.open(asns_file, os.O_WRONLY | os.O_CREAT |os.O_TRUNC)
        for line in lines:
            m =line.split("-->")
            if "ASN" in line:
                os.write(file_d0, (m[0].replace("(ASN)","") + "\t\t"+m[2].replace("(Netblock)","")).encode("utf-8"))
                  
get_links("a_records", "a_record_links")
get_asnlinks("amass_enumeration", "asns")