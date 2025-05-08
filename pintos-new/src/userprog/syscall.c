#include "devices/shutdown.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);

static int32_t get_user (const uint8_t *uaddr);
static int memread_user (void *src, void *des, size_t bytes);

typedef uint32_t pid_t;

void sys_halt (void);
void sys_exit (int);
pid_t sys_exec (const char *cmdline);
bool sys_write(int fd, const void *buffer, unsigned size, int* ret);


void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

// in case of invalid memory access, fail and exit.
static int fail_invalid_access(void) {
  sys_exit (-1);
  NOT_REACHED();
}

static void
syscall_handler (struct intr_frame *f)
{
  int syscall_number;

  ASSERT( sizeof(syscall_number) == 4 ); // assuming x86

  // The system call number is in the 32-bit word at the caller's stack pointer.
  if (memread_user(f->esp, &syscall_number, sizeof(syscall_number)) == -1)
    fail_invalid_access();

  // Dispatch w.r.t system call number
  // SYS_*** constants are defined in syscall-nr.h
  switch (syscall_number) {
  case SYS_HALT:
    {
      sys_halt();
      NOT_REACHED();
      break;
    }

  case SYS_EXIT:
    {
      int exitcode;
      if (memread_user(f->esp + 4, &exitcode, sizeof(exitcode)) == -1)
        fail_invalid_access();

      sys_exit(exitcode);
      NOT_REACHED();
      break;
    }

  case SYS_EXEC:
    {
      void* cmdline;
      if (memread_user(f->esp + 4, &cmdline, sizeof(cmdline)) == -1)
        fail_invalid_access();

      int return_code = sys_exec((const char*) cmdline);
      f->eax = (uint32_t) return_code;
      break;
    }

  case SYS_WAIT:
  case SYS_CREATE:
  case SYS_REMOVE:
  case SYS_OPEN:
  case SYS_FILESIZE:
  case SYS_READ:
    goto unhandled;

  case SYS_WRITE:
    {
      int fd, return_code;
      const void *buffer;
      unsigned size;

      if(-1 == memread_user(f->esp + 4, &fd, 4)) fail_invalid_access();
      if(-1 == memread_user(f->esp + 8, &buffer, 4)) fail_invalid_access();
      if(-1 == memread_user(f->esp + 12, &size, 4)) fail_invalid_access();

      if(!sys_write(fd, buffer, size, &return_code))
        thread_exit(); // TODO
      f->eax = (uint32_t) return_code;
      break;
    }

  case SYS_SEEK:
  case SYS_TELL:
  case SYS_CLOSE:

  /* unhandled case */
unhandled:
  default:
    printf("[ERROR] system call %d is unimplemented!\n", syscall_number);
    thread_exit();
    break;
  }

}

void sys_halt(void) {
  shutdown_power_off();
}

void sys_exit(int status) {
  printf("%s: exit(%d)\n", thread_current()->name, status);

  // set return code : status
  // TODO pass status into the kernel
  thread_exit();
}

pid_t sys_exec(const char *cmdline) {
  // cmdline is an address to the character buffer, on user memory
  // so a validation check is required
  if (get_user((const uint8_t*) cmdline) == -1) {
    // invalid memory access
    thread_exit();
    return -1;
  }

  tid_t child_tid = process_execute(cmdline);
  return child_tid;
}

bool sys_write(int fd, const void *buffer, unsigned size, int* ret) {
  // memory validation
  if (get_user((const uint8_t*) buffer) == -1) {
    // invalid
    thread_exit();
    return false;
  }

  // First, as of now, only implement fd=1 (stdout)
  // in order to display the messages from the test sets correctly.
  if(fd == 1) {
    putbuf(buffer, size);
    *ret = size;
    return true;
  }
  else {
    printf("[ERROR] sys_write unimplemented\n");
  }
  return false;
}

/****************** Helper Functions on Memory Access ********************/

static int32_t
get_user (const uint8_t *uaddr) {
  // check that a user pointer `uaddr` points below PHYS_BASE
  if (! ((void*)uaddr < PHYS_BASE)) {
    // TODO distinguish with result -1 (convert into another handler)
    return -1; // invalid memory access
  }

  // as suggested in the reference manual, see (3.1.5)
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
      : "=&a" (result) : "m" (*uaddr));
  return result;
}

/**
 * Reads a consecutive `bytes` bytes of user memory with the
 * starting address `src` (uaddr), and writes to dst.
 * Returns the number of bytes read, or -1 on page fault (invalid memory access)
 */
static int
memread_user (void *src, void *dst, size_t bytes)
{
  int32_t value;
  size_t i;
  for(i=0; i<bytes; i++) {
    value = get_user(src + i);
    if(value < 0) return -1; // invalid memory access.
    *(char*)(dst + i) = value & 0xff;
  }
  return (int)bytes;
}
