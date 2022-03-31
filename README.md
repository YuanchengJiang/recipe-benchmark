## RecIPE Benchmark

RecIPE is a newly developed benchmark for evaluating memory error defenses' effectiveness.

RecIPE will be/was presented as [RecIPE: Revisiting the Evaluation of Memory Error Defenses]() at The 17th ACM ASIA Conference on Computer and Communications Security (ACM ASIACCS 2022) in Nagasaki from May 30th to June 3rd, 2022. 

If you use, extend or build upon RecIPE we kindly ask you to cite the original AsiaCCS paper. Here's the BibTeX:

```
TBD
```

### Components

`TestGen` generates test cases from configurable templates.

`DefEval` exploits test cases and makes accurate analysis.

`Testcases` collects all generated test cases. Each of them has individual source code, Makefile, gadget info, etc. for easy debugging.

### RecIPE Dependencies

* python version: 3.6+
* pwntools==4.7.0
* configparse==0.1.5
* treelib==1.6.1

`pip install -r requirements.txt`

RecIPE supports Ubuntu18.04 and Ubuntu20.04

### Run

First, generate test cases
```
cd TestGen; ./TestGen.py
```

Then, launch attacks/exploits and collect results
```
cd DefEval; ./DefEval.py
```

**Before evaluating your memory error defense, please first check the baseline(the default compiling options; without any defense) results and make sure most attacks/exploits succeed**

### Result Format

The output file is in csv format:

| region | technique   | target  | function | exploit  | result 1  | result 2  | result 3  | ... |
|:------ | ----------- | ------- | -------- | -------- | --------- | --------- |:--------- | --- |
| stack  | NBoundOFlow | funcptr | bcopy    | ret2text | exploited | -         | -         |     |
| stack  | NBoundOFlow | funcptr | memcpy   | ret2text | attacked  | exploited | -         |     |
| stack  | NBoundOFlow | funcptr | homebrew | ret2text | failed    | failed    | exploited |     |

### Configurations

Simply modify `TestGen/TestGen.cfg` and `DefEval/DefEval.cfg` for general configurations. 

More configs for each template are available in `TestGen/config`.

**TestGen.cfg**
* RECIPE_ROOT: the root path of RecIPE
* check_file: RecIPE checks the existance of this file to get result of exploits; the default is `/tmp/recipe_check`
* log_file: RecIPE checks the content of this file to get result of attacks; the default is `/tmp/recipe_log`
* bad_cmd: malicious command used in exploits; the default is `touch /tmp/recipe_check`
* compile_cmd: compile command - defense should be applied here. 
* init_char: init char used in vulnerable C source code
* guard_char: guard buffer char used in vulnerable C source code 

*Attributes configurations: set every attr you like, RecIPE would try combine them to generate test cases*
* regions: `stack,heap,data,bss`
* techniques: `BoundOFlow,NBoundOFlow,OOBPtrHijack,PtrHijack,StructOFlow,NBoundUFlow`
* targets: `retaddr,oldebp,funcptr,GOT,hook,exit,jmpbuf`
* functions: `read,memcpy,bcopy,homebrew`

**DefEval.cfg**
* arch: architecture-32/64. this is for pwntools setting
* check_file: RecIPE checks the existance of this file to get result of exploits; the default is `/tmp/recipe_check`
* log_file: RecIPE checks the content of this file to get result of attacks; the default is `/tmp/recipe_log`
* output_file: result file path; the default is `/tmp/recipe_result.csv`
* max_attack_times: max attack times if failed
* max_waiting_time: max waiting time for a single exploit
* exploits: choose all exploits you like; the default is `ret2shellcode,ret2libc,ret2text,ROP,SROP`

### How to extend it
* To add new vulnerability, please add new template file in `TestGen/templates` and corresponding config file in `TestGen/config`.
	* To include attack checks in templates: please call `recipe_log() with the string contains "Attacked"`
* To add new exploit, please add new sub class in `DefEval/DefEvalLib.py`.
	* We use [Pwntools](https://docs.pwntools.com/en/stable/) APIs to interact with process and build exploits.

### Q&A
* If I don't like to generate all possible test case, how to control it?
	* see `TestGen/TestGenTree.py`. What to generate is from `testcase_getlist()`. 
* Exit target failed even without defense?
	* hacking exit requires hijacking `rtld` structure which needs unique offset differs among different glibcs. [This repo](https://github.com/0599jiangyc/exit_hijack) can help you auto find the offset in your system. you need to modify them in `TestGen/Config`
