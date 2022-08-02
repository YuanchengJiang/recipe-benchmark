#!/usr/bin/env python3

import os
import configparser
from tqdm import tqdm
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
customizations = conf.get('TestGenAttr', 'customizations').split(',')

testcase_list = testcase_getlist(
            attr_regions,
            attr_techniques,
            attr_targets,
            attr_functions,
            customizations
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

### Customized Makefile ###
customized_makefile="""
all: main

main: main.cpp
\tg++ -o main main.cpp

clean:
\trm main
"""

### DynLink Makefile ###
DynLink_makefile="""
all: main
CXX = clang++
CXXFLAGS = -g -fsanitize=cfi -fvisibility=hidden -flto -L. -lclass

libclass.so: libclass.cpp
\t$(CXX) -c -fPIC -o libclass.o libclass.cpp
\t$(CXX) -shared -o libclass.so libclass.o

main: main.cpp libclass.so
\t$(CXX) -o main main.cpp $(CXXFLAGS)

clean:
\trm main libclass.so libclass.o
"""

### Dlopen Makefile ###
Dlopen_makefile="""
all: main
CXX = clang++
CXXFLAGS = -g -fsanitize=cfi -fvisibility=hidden -flto -ldl

libclass.so: libclass.cpp
\t$(CXX) -c -fPIC -o libclass.o libclass.cpp
\t$(CXX) -shared -o libclass.so libclass.o

main: main.cpp libclass.so
\t$(CXX) -o main main.cpp $(CXXFLAGS)

clean:
\trm main libclass.so libclass.o
"""

compile_cmd = conf.get('CONFIG', 'compile_cmd')
makefile = makefile.format(compile_cmd)

### Step 3: General C Code ###
for i in tqdm(range(len(testcase_list))):
    # for customized testcase, directly format the template
    if testcase_list[i].split("_")[0] == "cust":
        ### This is for ClassMemCorr and ClassTypeConf ###
        template_name = testcase_list[i]
        f = open("{}/TestGen/templates/{}".format(RECIPE_ROOT,template_name), "r")
        ccode_template = f.read()
        f.close()
        f = open("{}/TestGen/config/{}.json".format(RECIPE_ROOT,template_name), "r")
        ccode_config = f.read()
        f.close()
        config_dict = eval(ccode_config)
        for each_class in ["A1", "A2", "A11", "B1", "C1"]:
            config_dict["class"] = each_class
            ccode = ccode_template.format(config=config_dict)
            testcase_path = "{}/Testcases/{}{}".format(RECIPE_ROOT, template_name, each_class)
            if not os.path.exists(testcase_path):
                os.mkdir(testcase_path)
            if "DynLinkClassTypeConf" in template_name:
                os.system("cp {}/TestGen/templates/customized_files/class.h {}".format(RECIPE_ROOT, testcase_path))
                os.system("cp {}/TestGen/templates/customized_files/libclass.cpp {}".format(RECIPE_ROOT, testcase_path))
            if "DynLinkClassMemCorr" in template_name:
                os.system("cp {}/TestGen/templates/customized_files/allclass.h {}".format(RECIPE_ROOT, testcase_path))
                os.system("cp {}/TestGen/templates/customized_files/createA1.cpp {}/libclass.cpp".format(RECIPE_ROOT, testcase_path))
            if "Dlopen" in template_name:
                os.system("cp {}/TestGen/templates/customized_files/allclass.h {}".format(RECIPE_ROOT, testcase_path))
                os.system("cp {}/TestGen/templates/customized_files/createA1.cpp {}/libclass.cpp".format(RECIPE_ROOT, testcase_path))
            f = open("{}/main.cpp".format(testcase_path), "w")
            f.write(ccode)
            f.close()
            f = open("{}/Makefile".format(testcase_path), "w")
            if "DynLink" in template_name:
                f.write(DynLink_makefile)
            elif "Dlopen" in template_name:
                f.write(Dlopen_makefile)
            else:
                f.write(customized_makefile)
            f.close()
            os.system("cd {}; make > /dev/null".format(testcase_path))
        continue
    if testcase_list[i]=="":
        continue
    attrs = testcase_list[i].split("_")
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
    testcase_path = "{}/Testcases/{}".format(RECIPE_ROOT, testcase_list[i])
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
    os.system("cd {}; make > /dev/null".format(testcase_path))

    
    


