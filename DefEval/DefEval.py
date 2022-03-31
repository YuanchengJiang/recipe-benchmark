#!/usr/bin/env python3
import os
import json
import codecs
import time
import configparser
from pathlib import Path
from DefEvalLib import *

conf = configparser.ConfigParser()
conf.read('DefEval.cfg', encoding='utf-8')

RECIPE_ROOT = Path(__file__).parent.resolve().parent.resolve()
max_attack_times = int(conf.get('CONFIG', 'max_attack_times'))
result_filepath = conf.get('CONFIG', 'output_file')
exploit_list = conf.get('CONFIG', 'exploits').split(',')

def attack_all(runtime_defense=None):
    dir_list = [x[0] for x in os.walk("{}/Testcases/".format(RECIPE_ROOT))][1:]
    result_file = open(result_filepath, "w")
    head1 = "{},{},{},{},{},".format(
        "region",
        "technique",
        "target",
        "function",
        "exploit"
    )
    head2 = ','.join(["Attack {}".format(i) for i in range(max_attack_times)])
    result_file.write(head1+head2+"\n")
    current_testcase = 1
    testcase_num = len(dir_list)
    for dirpath in dir_list:
        region, technique, target, function = parse_dimensions(dirpath)
        class_name = globals()["recipe_{}_{}".format(region, technique)]
        for each_exploit in exploit_list:
            if not (technique=="BoundOFlow" and target=="retaddr" or target=="oldebp") and each_exploit!="ret2text":
                continue
            if target!="retaddr" and each_exploit=="SROP":
                continue
            result_file.write("{},{},{},{},{},".format(region, technique, target, function, each_exploit))
            for i in range(max_attack_times):
                new_attack = class_name(target, dirpath, result_file, each_exploit, runtime_defense)
                if new_attack.start():
                    break
                time.sleep(0.1)
            result_file.write("\n")
        progress = float(current_testcase/testcase_num)*100
        print("recipe benchmark progress: {}%: ".format(int(progress)), "▋" * (int(progress) // 2), end="\n\n")
        current_testcase += 1
    result_file.close()

def result_summary():
    result_file = open(result_filepath, "r")
    result_file.readline()
    total = 0
    attacked = 0
    exploited = 0
    while True:
        newline = result_file.readline()
        if not newline:
            break
        else:
            total += 1
            if "exploited" in newline:
                exploited += 1
            elif "attacked" in newline:
                attacked += 1
    
    print("total:{} attacked:{} exploited:{}".format(total, attacked, exploited))
    result_file.close()


if __name__ == "__main__":
    attack_all()
    result_summary()
