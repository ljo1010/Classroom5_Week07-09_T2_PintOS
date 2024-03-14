#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// ********************************************** //
	// [MOD; SYSTEM CALL IMPL]
	// case SYS_EXEC:
	// 	f->R.rax = exec(f->R.rdi);
	// 	break;
	// ********************************************** //
	printf ("system call!\n");
	thread_exit ();
}

int
exec(const char *cmd) {
	check_address(cmd);

	char *cmd_temp = palloc_get_page(0);

	if(cmd_temp == NULL)
		exit(-1);
	strlcpy(cmd_temp, cmd, PGSIZE);

	if(process_exec(cmd_temp) == -1)
		exit(-1);
}

int
fork(const char *thread_name, struct intr_frame *i_frame) {
	return process_fork(thread_name, i_frame);
}

tid_t
process_fork(const char *thread_name, struct intr_frame *i_frame) {
	return thread_create(thread_name, PRI_DEFAULT, __do_fork, thread_current());
}