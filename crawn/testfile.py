import os

namerecords = ["a_record", "cname_record", "mx_record", "ns_record", "ptr_record", "aaa_record"]
name_records = []
projectDir = "/home/program/AtomProjects/figma.com/"
[name_records.append(os.path.join(projectDir,namerecord+".txt")) for namerecord in namerecords]
print(name_records)