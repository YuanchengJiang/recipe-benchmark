#!/usr/bin/env python3

import os
import configparser
from pathlib import Path
from TestGenTree import testcase_getlist

conf = configparser.ConfigParser()
conf.read('TestGen.cfg', encoding='utf-8')

RECIPE_ROOT = Path(__file__).parent.resolve().parent.resolve()

### Step 1: Get Testcase List ###

attr_regions = conf.get('TestGenAttr', 'regions').split(',')
attr_techniques = conf.get('TestGenAttr', 'techniques').split(',')
attr_targets = conf.get('TestGenAttr', 'targets').split(',')
attr_functions = conf.get('TestGenAttr', 'functions').split(',')

testcase_list = testcase_getlist(
            attr_regions,
            attr_techniques,
            attr_targets,
            attr_functions
        )

### Step 2: General Config for RecIPE.h ###

header_conf = {
    "check_file": str(conf.get('CONFIG', 'check_file')),
    "log_file" : str(conf.get('CONFIG', 'log_file')),
    "bad_cmd" : str(conf.get('CONFIG', 'bad_cmd')),
    "init_char" : str(conf.get('CONFIG', 'init_char')),
    "guard_char" : str(conf.get('CONFIG', 'guard_char'))
    }

f = open("./templates/RecIPE.h", "r")
header_template = f.read()
f.close()
# Remember: move to each test case folder 
header_file = header_template.format(config=header_conf)

### External Homebrew Memcpy ###
homebrew = """
void homebrew_memcpy(void *dst, const void *src, int length) {
    char *d, *s;
    d = (char *)dst;
    s = (char *)src;
    while(length--) {
        *d++ = *s++;
    }
}
"""

### Makefile ###
makefile="""
all: main

main: main.c
\t{} -o main main.c homebrew.c
\tROPgadget --binary main > gadget

clean:
\trm main gadget
"""

compile_cmd = conf.get('CONFIG', 'compile_cmd')
makefile = makefile.format(compile_cmd)
count = 0

### Step 3: General C Code ###
for each_testcase in testcase_list:
    print("[+] Generating Test Case: {}".format(each_testcase))
    attrs = each_testcase.split("_")
    # i: get C code template
    template_name = "_".join(attrs[:2])
    f = open("{}/TestGen/templates/{}".format(RECIPE_ROOT,template_name), "r")
    ccode_template = f.read()
    f.close()
    # ii: get config
    f = open("{}/TestGen/config/{}.json".format(RECIPE_ROOT,template_name), "r")
    ccode_config = f.read()
    f.close()
    # iii: specify target and function
    ON=""
    OFF="//"
    config_dict = eval(ccode_config)
    try:
        config_dict[attrs[2]]=ON
        config_dict[attrs[3]]=ON
    except:
        print("sth wrong with config")
    # iv: format c code
    ccode = ccode_template.format(config=config_dict)
    # v: generate test case
    testcase_path = "{}/Testcases/{}".format(RECIPE_ROOT, each_testcase)
    if not os.path.exists(testcase_path):
        os.mkdir(testcase_path)
    f = open("{}/main.c".format(testcase_path), "w")
    f.write(ccode)
    f.close()
    f = open("{}/RecIPE.h".format(testcase_path), "w")
    f.write(header_file)
    f.close()
    f = open("{}/homebrew.c".format(testcase_path), "w")
    f.write(homebrew)
    f.close()
    f = open("{}/Makefile".format(testcase_path), "w")
    f.write(makefile)
    f.close()
    os.system("cd {}; make".format(testcase_path))
    count += 1
    progress = float(count/len(testcase_list))*100
    print("recipe benchmark progress: {}%: ".format(int(progress)), "▋" * (int(progress) // 2), end="\n\n")
    print()

    
    


