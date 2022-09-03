/*
 * Copyright (c) 2014, Ryan O'Neill
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "maya.h"

#define INIT_MALLOC_SIZE 4096 << 10
#define MAX_HEAP_BINS 8
#define HEAP_BLOCK_SIZE 64 // XXX NOTE: Changed from 512 to 64 (Much more space efficient for hash map)
#define CHUNK_ROUNDUP(x)(x + HEAP_BLOCK_SIZE & ~(HEAP_BLOCK_SIZE - 1))
#define CHUNK_UNUSED_INITIALIZER 0xFFFFFFFF

int Memcmp(const void *, const void *, size_t);
char * _strdup(char *s);
void _strcpy(char *, char *);
int _strcmp(const char *, const char *);
int _strncmp(const char *s1, const char *s2, size_t n);
int _memcmp(const void *s1, const void *s2, unsigned int n);
char * _strrchr(const char *cp, int ch);
char *_strchr(const char *s, int c);
void _memcpy(void *, void *, unsigned int);
void Memset(void *, unsigned char, unsigned int);
int _printf(char *fmt, ...);
int _sprintf(char *, char *, ...);
char * itoa(long x, char *t);
char * itox(long x, char *t);
int _puts(char *str);
size_t _strlen(char *s);
void Exit(long);
void *_mmap(unsigned long, unsigned long, unsigned long, unsigned long,  long, unsigned long);
long _open(char *, unsigned long);
long _write(long, char *, unsigned long);
int _read(long, char *, unsigned long);


int _printf(char *fmt, ...)
{
        int in_p;
        unsigned long dword;
        unsigned int word;
        char numbuf[26] = {0};
        __builtin_va_list alist;

        in_p;

        __builtin_va_start((alist), (fmt));

        in_p = 0;
        while(*fmt) {
                if (*fmt!='%' && !in_p) {
                        _write(1, fmt, 1);
                        in_p = 0;
                }
                else if (*fmt!='%') {
                        switch(*fmt) {
                                case 's':
                                        dword = (unsigned long) __builtin_va_arg(alist, long);
                                        _puts((char *)dword);
                                        break;
                                case 'u':
                                        word = (unsigned int) __builtin_va_arg(alist, int);
                                        _puts(itoa(word, numbuf));
                                        break;
                                case 'd':
                                        word = (unsigned int) __builtin_va_arg(alist, int);
                                        _puts(itoa(word, numbuf));
                                        break;
                                case 'x':
                                        dword = (unsigned long) __builtin_va_arg(alist, long);
                                        _puts(itox(dword, numbuf));
                                        break;
                                default:
                                        _write(1, fmt, 1);
                                        break;
                        }
                        in_p = 0;
                }
                else {
                        in_p = 1;
                }
	    fmt++;
        }
        return 1;
}



char * itoa(long x, char *t)
{
        int i;
        int j;

        i = 0;
        do
        {
                t[i] = (x % 10) + '0';
                x /= 10;
                i++;
        } while (x!=0);

        t[i] = 0;

        for (j=0; j < i / 2; j++) {
                t[j] ^= t[i - j - 1];
                t[i - j - 1] ^= t[j];
                t[j] ^= t[i - j - 1];
        }

        return t;
}


char * itox(long x, char *t)
{
        int i;
        int j;

        i = 0;
        do
        {
                t[i] = (x % 16);

                /* char conversion */
                if (t[i] > 9)
                        t[i] = (t[i] - 10) + 'a';
                else
                        t[i] += '0';

                x /= 16;
                i++;
        } while (x != 0);

        t[i] = 0;

        for (j=0; j < i / 2; j++) {
                t[j] ^= t[i - j - 1];
                t[i - j - 1] ^= t[j];
                t[j] ^= t[i - j - 1];
        }

        return t;
}
long _write(long fd, char *buf, unsigned long len)
{
        long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov %2, %%rdx\n"
                        "mov $1, %%rax\n"
                        "syscall" : : "g"(fd), "g"(buf), "g"(len));
        asm volatile("mov %%rax, %0" : "=r"(ret));
        return ret;
}

int _read(long fd, char *buf, unsigned long len)
{
         long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov %2, %%rdx\n"
                        "mov $0, %%rax\n"
                        "syscall" : : "g"(fd), "g"(buf), "g"(len));
        asm volatile ("mov %%rax, %0" : "=r"(ret));
        return (int)ret;
}



void _strcpy(char *dst, char *src)
{
        char *s = src;
        char *d = dst;
        
        while (*s) {
                *d = *s;
                d++, s++;
        }
        *d = '\0';
}
   
	
int _fsync(int fd)
{
        long ret;
	long scn = 74;

	asm volatile("syscall" : "=D"(fd), "=a"(scn));
/*
        asm volatile(
                        "mov %0, %%rdi\n"
                        "mov $74, %%rax\n"
                        "syscall" : : "g"(fd));
	*/
	asm ("ret" : "=a"(ret)); 
        return (int)ret;
}

int _puts(char *str)
{
        _write(1, str, _strlen(str));
        _fsync(1);

        return 1;
}

size_t _strlen(char *s)
{
        size_t sz;

        for (sz=0;s[sz];sz++);
        return sz;
}

     
char *_strchr(const char *s, int c)
{
    const char ch = c;

    for ( ; *s != ch; s++)
        if (*s == '\0')
            return 0;
    return (char *)s;
}

int _strncmp(const char *s1, const char *s2, size_t n)
{
    for ( ; n > 0; s1++, s2++, --n)
        if (*s1 != *s2)
            return ((*(unsigned char *)s1 < *(unsigned char *)s2) ? -1 : +1);
        else if (*s1 == '\0')
            return 0;
    return 0;
}

int _strcmp(const char *s1, const char *s2)
{
        int r = 0;

        while (!(r = (*s1 - *s2) && *s2))
                s1++, s2++;
        if (!r)
                return r;
        return r = (r < 0) ? -1 : 1;
}

int _memcmp(const void *s1, const void *s2, unsigned int n)
{
        unsigned char u1, u2;

        for ( ; n-- ; s1++, s2++) {
                u1 = * (unsigned char *) s1;
                u2 = * (unsigned char *) s2;
        if ( u1 != u2) {
                return (u1-u2);
        }
    }
    return 0;
}

void Memset(void *mem, unsigned char byte, unsigned int len)
{
        unsigned char *p = (unsigned char *)mem; 
        int i = len;
        while (i--) {
                *p = byte;
                p++;
        }
}


void _memcpy(void *dst, void *src, unsigned int len)
{
        int i;
        unsigned char *s = (unsigned char *)src;
        unsigned char *d = (unsigned char *)dst;

        for (i = 0; i < len; i++) {
                *d = *s;
                s++, d++;
        }

}

void Exit(long status)
{
        __asm__ volatile("mov %0, %%rdi\n"
                         "mov $60, %%rax\n"
                         "syscall" : : "r"(status));
}

long _open(char *path, unsigned long flags)
{
        long ret;
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov $2, %%rax\n"
                        "syscall" : : "g"(path), "g"(flags));
        asm __volatile__("mov %%rax, %0" : "=r"(ret));              
        
        return ret;
}

int _close(unsigned int fd)
{
        long ret;
	long scn = 3;

	/*
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov $3, %%rax\n"
                        "syscall" : : "g"(fd));
 	*/
        asm volatile("syscall" : "=D"(fd), "=a"(scn));

        asm volatile("mov %%rax, %0" : "=r"(ret));  
	return (int)ret;
} 



int _getuid(void)
{
        long ret;
        __asm__ volatile(
                        "mov $102, %rax\n"
                        "syscall");
        asm __volatile__("mov %%rax, %0" : "=r"(ret));

        return (int)ret;
}




int _getgid(void)
{
        long ret;
        __asm__ volatile(
                        "mov $104, %rax\n"
                        "syscall");
        asm __volatile__ ("mov %%rax, %0" : "=r"(ret));

        return (int)ret;
}



int _getegid(void)
{
        long ret;
        __asm__ volatile(
                        "mov $108, %rax\n"
                        "syscall");
        asm __volatile__ ("mov %%rax, %0" : "=r"(ret));

        return (int)ret;
}



int _geteuid(void)
{
	long ret;
	__asm__ volatile(
			"mov $107, %rax\n"
			"syscall");
	asm __volatile__ ("mov %%rax, %0" : "=r"(ret));
	
	return (int)ret;
}

long _lseek(long fd, long offset, unsigned int whence)
{
        long ret;
	long scn = 8;
  
      asm volatile("syscall" : "=D"(fd), "=S"(offset), "=d"(whence), "=a"(scn));
	/*
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov %2, %%rdx\n"
                        "mov $8, %%rax\n"
                        "syscall" : : "g"(fd), "g"(offset), "g"(whence));
	*/

        asm __volatile__ ("mov %%rax, %0" : "=r"(ret));
        return ret;

}
	
int _mprotect(void * addr, unsigned int len, unsigned int prot)
{
        unsigned long ret;
	long scn = 10;

	asm volatile("syscall" : "=D"(addr), "=S"(len), "=d"(prot), "=a"(scn));
	
	/*
        __asm__ volatile(
                        "mov %0, %%rdi\n"
                        "mov %1, %%rsi\n"
                        "mov %2, %%rdx\n"
                        "mov $10, %%rax\n"
                        "syscall" : : "g"(addr), "g"(len), "g"(prot));
	*/
        asm __volatile__ ("mov %%rax, %0" : "=r"(ret));
        
        return (int)ret;
}

int _brk(void *);

int _brk(void *addr)
{
	long ret;
	__asm__ volatile("mov %0, %%rdi\n"
			 "mov $12, %%rax\n"
			 "syscall" : : "g"(addr));
	asm __volatile__("mov %%rax, %0" : "=r"(ret));
	return (int)ret;
}

int _stat(char *path, struct stat *buf)
{
	long ret;
	__asm__ volatile(
			"mov %0, %%rdi\n"
			"mov %1, %%rsi\n"
			"mov $4, %%rax\n"
			"syscall\n" : : "g"(path), "g"(buf));
	asm __volatile__("mov %%rax, %0" : "=r"(ret));
	return (int)ret;
}


void *_mmap(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, long fd, unsigned long off)
{
        long mmap_fd = fd;
        unsigned long mmap_off = off;
        unsigned long mmap_flags = flags;
        unsigned long ret;
	
        __asm__ volatile(
                         "mov %0, %%rdi\n"
                         "mov %1, %%rsi\n"
                         "mov %2, %%rdx\n"
                         "mov %3, %%r10\n"
                         "mov %4, %%r8\n"
                         "mov %5, %%r9\n"
                         "mov $9, %%rax\n"
                         "syscall\n" : : "g"(addr), "g"(len), "g"(prot), "g"(flags), "g"(mmap_fd), "g"(mmap_off));
        asm __volatile__ ("mov %%rax, %0" : "=r"(ret));              
        return (void *)ret;
}


