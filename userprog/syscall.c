#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "threads/palloc.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

bool 
check_address(const char *file) 
{
	struct thread *t = thread_current();
	if (is_user_vaddr(file) && pml4_get_page(t->pml4, file) && file != NULL){
		return true;
	}
		
	else 
		exit(-1);
}

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
	switch (f->R.rax)
	{
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(f->R.rdi);
		break;
	case SYS_CREATE:
		f->R.rax = create(f->R.rdi, f->R.rsi);
		break;
	case SYS_OPEN:
		f->R.rax = open(f->R.rdi);
		break;
	case SYS_CLOSE:
		close(f->R.rdi);
		break;
	case SYS_FILESIZE:
		f->R.rax = filesize(f->R.rdi);
		break;
	case SYS_REMOVE:
		remove(f->R.rdi);
		break;
	case SYS_EXEC:
		exec(f->R.rdi);
		break;
	// case SYS_READ:
	// 	read(f->R.rdi, f->R.rsi, f->R.rdx);
	// 	break;
	case SYS_WRITE:
		write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	}
}


void
halt (void) {
	power_off();
}

void
exit (int status) {
	struct thread *t = thread_current();
	t->exit_status = status;
	printf("%s: exit(%d)\n", t->name, status);
	thread_exit();
}

// pid_t
// fork (const char *thread_name){
// 	return (pid_t) syscall1 (SYS_FORK, thread_name);
// }

int
exec (const char *file) {
	check_address(file);

	char *fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		exit(-1);
	strlcpy (fn_copy, file, PGSIZE);

	if (process_exec (fn_copy) == -1)
		exit(-1);
}

// int
// wait (pid_t pid) {
// 	return syscall1 (SYS_WAIT, pid);
// }

bool
create (const char *file, unsigned initial_size) {
	if(check_address(file)) 
		return filesys_create(file, initial_size);
}

bool
remove (const char *file) {
	check_address(file);
	return filesys_remove(file);
}

int
open (const char *file) {
	check_address(file);
	struct thread *t = thread_current();
	struct file *open_file = filesys_open(file);
	
	if (file == NULL)
		return -1;
	if(open_file){
		t->file_list[t->fd++] = open_file;
		return t->fd-1;
	}
	else
		return -1;
}

int
filesize (int fd) {
	check_address(fd);
	struct thread *t = thread_current();
	struct file *_file = t->file_list[fd];
	return file_length(_file);
}

// int
// read (int fd, void *buffer, unsigned size) {
// 	check_address(fd);
// 	file_read()
// }

int
write (int fd, const void *buffer, unsigned size) {
	if (fd == STDOUT_FILENO)
	{
		putbuf(buffer, size);
		return size;
	}
}

// void
// seek (int fd, unsigned position) {
// 	syscall2 (SYS_SEEK, fd, position);
// }

// unsigned
// tell (int fd) {
// 	return syscall1 (SYS_TELL, fd);
// }

void
close (int fd) {
	struct thread *t = thread_current();
	if (t->fd < fd) return -1;
	
	struct file *close_file = t->file_list[fd];

	if (close_file == NULL) exit(-1);

	close_file = NULL;
	file_close(close_file);
}