#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <limits.h>
#include <setjmp.h>
#include <sys/ucontext.h>

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))
#define ADDR_SIZE sizeof(char*)

#define INIT_CHAR '{config[init_char]}'
#define GUARD_CHAR '{config[guard_char]}'

/* if modified, please also change DefEval accordingly */
#define CHECK_FILE "{config[check_file]}"
#define LOG_FILE "{config[log_file]}"

/* in RecIPE, we create tmp file and check its existance */
char cmd[]="{config[bad_cmd]}";

/* reliable ways to get the adresses of the return address and old base pointer */
#define OLD_BP_PTR   __builtin_frame_address(0)
#define RET_ADDR_PTR ((void**)OLD_BP_PTR + 1)

/* architecture */
#ifdef __i386__
   #define ROTATE 0x9
   #define PC_ENV_OFFSET 0x14
#elif __x86_64__
   #define ROTATE 0x11
   #define PC_ENV_OFFSET 0x38
#endif

extern void homebrew_memcpy(void *dst, const void *src, size_t length);

void remove_files()
{{
	remove(CHECK_FILE);
	remove(LOG_FILE);
}}

/* Hidden is reserved for evaluating Fortify */
char input_hidden[256];
void hidden(char* readin_buffer, size_t len)
{{
    printf("for clang\n");
    memcpy(input_hidden, readin_buffer, len);
    printf("for gcc\n");
}}

#ifdef __i386__
unsigned int rol(uintptr_t value)
{{
   // return (value << ROTATE) | (value >> (__WORDSIZE - ROTATE));
    unsigned int ret;
	asm volatile("xor %%gs:0x18, %0; rol $0x9, %0" : "=g"(ret) : "0"(value));
    return ret;
}}
#elif __x86_64__
unsigned long rol(uintptr_t value)
{{
   // return (value << ROTATE) | (value >> (__WORDSIZE - ROTATE));
    unsigned long ret;
    asm volatile("xor %%fs:0x30, %0; rol $0x11, %0" : "=g"(ret) : "0"(value));
    return ret;
}}
#endif

void jump_to_me()
{{
	FILE *fp;
	fp = fopen(CHECK_FILE, "w");
    fclose(fp);
    exit(0);
}}

void recipe_log(char *log_string, size_t log_string_size)
{{
	FILE *p;
	p = fopen(LOG_FILE, "aw");
	fwrite(log_string, log_string_size, 1, p);
	fclose(p);
}}

void foo()
{{
    puts("Hi, here is foo()");
    exit(0);
}}

void gadget()
{{
#ifdef __x86_64__
// code that you want to run ONLY during tests 
    __asm__("call *%rdx; ret;");
	__asm__("nop; pop %rdi; ret;");
	__asm__("nop; pop %rsi; ret;");
	__asm__("nop; pop %rdx; ret;");
	__asm__("nop; pop %rcx; ret;");
	__asm__("nop; pop %rax; ret;");
	__asm__("nop; pop %rax; syscall; ret;");
	__asm__("syscall; ret;");
	__asm__("syscall;");
#endif 

#ifdef __i386__
	__asm__("call *%edx; ret;");
	__asm__("nop; pop %edi; ret;");
	__asm__("nop; pop %esi; ret;");
	__asm__("nop; pop %edx; ret;");
	__asm__("nop; pop %ecx; ret;");
	__asm__("nop; pop %eax; ret;");
	__asm__("nop; pop %eax; syscall; ret;");
	__asm__("syscall; ret;");
	__asm__("syscall;");
	__asm__("int $0x80; ret;");
	__asm__("int $0x80;");
#endif
}}

int guard_buffer_check(char *guard_buffer, size_t buffer_size)
{{
    for(int i=0;i<buffer_size;i++){{
        if(guard_buffer[i]!=GUARD_CHAR){{
            /* out-of-bound detected */
            return -1;
        }}
    }}
    return 0;
}}

int ptraddr_compare(char **p1, char **p2)
{{
    if (*p1 > *p2) return 1;
	if (*p1 < *p2) return -1;
	return 0;
}}