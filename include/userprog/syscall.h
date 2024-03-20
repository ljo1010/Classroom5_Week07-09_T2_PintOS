#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

#endif /* userprog/syscall.h */


typedef int pid_t;
#include <stdbool.h>
#include <debug.h>
#include <stddef.h>

void halt (void);
void exit (int status);
pid_t fork (const char *thread_name);
int exec (const char *file);
int wait (pid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned length);
int write (int fd, const void *buffer, unsigned length);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);