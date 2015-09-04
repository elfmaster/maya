#define _GNU_SOURCE
#include <linux/fcntl.h>
#include <asm/unistd_64.h>
#include <asm/stat.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <elf.h>
#include <sys/mman.h>
#include <linux/sched.h>
#include <linux/unistd.h>
#include <sys/wait.h>
#include <linux/prctl.h>
#include <asm/ldt.h>

#define MODIFY_LDT_CONTENTS_DATA        0
#define MODIFY_LDT_CONTENTS_STACK       1
#define MODIFY_LDT_CONTENTS_CODE        2

#define RESIDENT_SECTION_NAME ".mayas_veil"

#define STACK_SIZE 0x4000000
/*
 * We pass these to sys_clone
 * for our create_thread() function
 */
#define SIGCHLD         17
#define CLONE_VM        0x00000100      /* set if VM shared between processes */
#define CLONE_FS        0x00000200      /* set if fs info shared between processes */
#define CLONE_FILES     0x00000400      /* set if open files shared between processes */
#define CLONE_SIGHAND   0x00000800      /* set if signal handlers shared */

struct modify_ldt_ldt_s {
        unsigned int  entry_number;
        unsigned long base_addr;
        unsigned int  limit;
        unsigned int  seg_32bit:1;
        unsigned int  contents:2;
        unsigned int  read_exec_only:1;
        unsigned int  limit_in_pages:1;
        unsigned int  seg_not_present:1;
        unsigned int  useable:1;
};
