#include "devices/shutdown.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"

static void syscall_handler (struct intr_frame *);

static int32_t get_user (const uint8_t *uaddr);
//static int memread_user (void *src, void *des, size_t bytes);
bool is_valid_ptr(const void *usr_ptr);

typedef uint32_t pid_t;

void halt (void);
void exit (int);
pid_t exec (const char *cmdline);
bool write(int fd, const void *buffer, unsigned size, int* ret);


void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

// in case of invalid memory access, fail and exit.
static int fail_invalid_access(void) {
  exit (-1);
  NOT_REACHED();
}

static void
syscall_handler (struct intr_frame *f)
{
  int syscall_number;

  ASSERT(sizeof(syscall_number) == 4 ); // assuming x86

  // The system call number is in the 32-bit word at the caller's stack pointer.
  if (!is_valid_ptr(f->esp))
    fail_invalid_access();
  syscall_number = *(int *)(f->esp);

  // Dispatch w.r.t system call number
  // SYS_*** constants are defined in syscall-nr.h
  switch (syscall_number) {
  case SYS_HALT:
    {
      halt();
      NOT_REACHED();
      break;
    }

  case SYS_EXIT:
    {
      int exitcode;
      if (!is_valid_ptr(f->esp + 4))
        fail_invalid_access();

      exitcode = *(int *)(f->esp + 4);
      exit(exitcode);
      NOT_REACHED();
      break;
    }

  case SYS_EXEC:
    {
      void* cmdline;
      if (!is_valid_ptr(f->esp + 4))
        fail_invalid_access();

      cmdline = *(void **)(f->esp + 4);
      int return_code = exec((const char*) cmdline);
      f->eax = (uint32_t) return_code;
      break;
    }

  case SYS_WAIT:
    {
      pid_t pid;
      if (!is_valid_ptr(f->esp + 4))
        fail_invalid_access();

      pid = *(pid_t *)(f->esp + 4);
      int ret = wait(pid);
      f->eax = (uint32_t) ret;
      break;
    }
  
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

      if (!is_valid_ptr(f->esp + 4)) fail_invalid_access();
      if (!is_valid_ptr(f->esp + 8)) fail_invalid_access();
      if (!is_valid_ptr(f->esp + 12)) fail_invalid_access();

      fd = *(int *)(f->esp + 4);
      buffer = *(void **)(f->esp + 8);
      size = *(unsigned *)(f->esp + 12);

      if(!write(fd, buffer, size, &return_code))
        thread_exit();
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

void halt(void) {
  shutdown_power_off();
}

void exit(int status) {
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
}

pid_t exec(const char *cmdline) {
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

int wait(pid_t pid) {
  return process_wait(pid);
}

bool write(int fd, const void *buffer, unsigned size, int* ret) {
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
    printf("[ERROR] write unimplemented\n");
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
/*
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
  */
  
bool
is_valid_ptr(const void *usr_ptr)
{
  struct thread *cur = thread_current();

  // 1. NULL 포인터 검사
  if (usr_ptr == NULL)
    return false;

  // 2. 사용자 공간에 속한 주소인지 검사
  if (!is_user_vaddr(usr_ptr))
    return false;

  // 3. 해당 주소가 실제로 매핑된 유효한 페이지인지 확인
  if (pagedir_get_page(cur->pagedir, usr_ptr) == NULL)
    return false;

  return true;
}
  