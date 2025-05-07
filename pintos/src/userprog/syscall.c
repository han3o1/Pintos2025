#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "threads/init.h"
#include "userprog/process.h"

static void syscall_handler (struct intr_frame *);
static bool is_valid_ptr (const void *usr_ptr);
static void halt (void);
static void exit (int status);
static int wait (pid_t pid);


void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static bool
is_valid_ptr (const void *usr_ptr) 
{
  struct thread *cur = thread_current();

  // 1. NULL 체크
  if (usr_ptr == NULL)
    return false;

  // 2. 사용자 영역 주소인지 확인
  if (!is_user_vaddr(usr_ptr))
    return false;

  // 3. 페이지 디렉토리에서 매핑 확인
  if (pagedir_get_page(cur->pagedir, usr_ptr) == NULL)
    return false;

  return true;
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  // 1. Validate stack pointer
  if (!is_valid_ptr(f->esp)) {
    exit(-1);
  }

  // 2. Extract syscall number
  int syscall_num = *(int *)f->esp;

  // 3. Dispatch system call
  switch (syscall_num) {
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      if (!is_valid_ptr((int *)f->esp + 1)) exit(-1);
      exit(*((int *)f->esp + 1));
      break;
    case SYS_WAIT:
      if (!is_valid_ptr((int *)f->esp + 1)) exit(-1);
      f->eax = wait(*((pid_t *)f->esp + 1));
      break;
    default:
      exit(-1);
      break;
  }
}

void
halt (void) 
{
  shutdown_power_off();
}

void
exit (int status) 
{
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_current()->exit_status = status;
  thread_exit();
}

int
wait (pid_t pid) 
{
  return process_wait(pid);
}
