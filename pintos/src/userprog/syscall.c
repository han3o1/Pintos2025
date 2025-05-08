#include "devices/shutdown.h"
#include "userprog/process.h"
#include "filesys/filesys.h"  
#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h" 
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "filesys/file.h"
#include "lib/kernel/console.h"

#define STDOUT_FILENO 1
#define STDIN_FILENO 0

typedef uint32_t pid_t;
static void syscall_handler (struct intr_frame *);
void sys_halt (void);
void sys_exit (int);
pid_t sys_wait (pid_t pid);
bool is_valid_ptr (const void *ptr);
static struct file *get_open_file(int fd);
int sys_write(int fd, const void *buffer, unsigned size);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  // Read system call number from user stack (esp)
  if (!is_valid_ptr(f->esp))
    thread_exit();  // invalid esp -> terminate

  int syscall_number = *(int *)(f->esp);
  // printf ("system call number: %d\n", syscall_number);

  switch (syscall_number) 
  {
    case SYS_HALT:
    {
      sys_halt();
      NOT_REACHED();
      break;
    }

    case SYS_EXIT:
    {
      // Argument: int status (f->esp + 4)
      int status;

      if (!is_valid_ptr(f->esp + 4))
        thread_exit();

      status = *(int *)(f->esp + 4);
      sys_exit(status);
      NOT_REACHED();
      break;
    }

    case SYS_WAIT:
    {
      // Argument: pid_t pid (f->esp + 4)
      pid_t pid;

      if (!is_valid_ptr(f->esp + 4))
        thread_exit();

      pid = *(pid_t *)(f->esp + 4);
      f->eax = sys_wait(pid);
      break;
    }

    /* Unimplemented system calls
    case SYS_EXEC:
    case SYS_CREATE:
    case SYS_REMOVE:
    case SYS_OPEN:
    case SYS_FILESIZE:
    case SYS_READ: */
    case SYS_WRITE:
    {
      int fd = *(int *)(f->esp + 4);
      const void *buffer = *(const void **)(f->esp + 8);
      unsigned size = *(unsigned *)(f->esp + 12);

      printf("[DEBUG] SYS_WRITE: esp=%p, fd=%d, buffer=%p, size=%u\n", f->esp, fd, buffer, size);

      if (!is_valid_ptr(buffer))
        sys_exit(-1);
  
      f->eax = sys_write(fd, buffer, size);
      break;
    }
    /*
    case SYS_SEEK:
    case SYS_TELL:
    case SYS_CLOSE: */

    default:
    {
      printf("[ERROR] system call %d is unimplemented!\n", syscall_number);
      thread_exit();
      break;
    }
  }
}

/* halt syscall -> shutdown Pintos */
void sys_halt(void) 
{
  shutdown_power_off();
}

/* exit syscall -> terminate current process */
void sys_exit(int status) 
{
  struct thread *cur = thread_current();
  cur->exit_status = status;

  printf("%s: exit(%d)\n", cur->name, status);
  
  thread_exit();
}

/* wait syscall -> call process_wait */
pid_t sys_wait(pid_t pid)
{
  return process_wait(pid);
}

/* Pointer validation function -> check user virtual address */
bool is_valid_ptr(const void *ptr) 
{
  // Check if the pointer is in user virtual address range and is not NULL
  return (ptr != NULL && is_user_vaddr(ptr));
}

/* Get the file pointer from the current thread's fd_table */
static struct file *get_open_file(int fd) {
  // 현재 쓰레드 가져오기
  struct thread *cur = thread_current();

  // 유효한 fd인지 체크 (0 이상 FD_MAX 미만이어야 함)
  if (fd < 0 || fd >= FD_MAX) {
    return NULL;
  }

  // fd_table에서 해당 fd에 해당하는 파일 포인터 가져오기
  return cur->fd_table[fd];
}

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  uint8_t value;

  asm volatile ("movb %1, %0"
                : "=r" (value)
                : "m" (*uaddr));

  result = value;
  return result;
}

int sys_write(int fd, const void *buffer, unsigned size) {
  // 1. 유저 포인터가 유효한지 확인
  if (!is_user_vaddr(buffer))
    sys_exit(-1);
  
  printf("[DEBUG] sys_write called with fd=%d, size=%u\n", fd, size);

  int bytes_written = -1;
  lock_acquire(&fs_lock);

  // 2. fd가 STDOUT일 때 -> putbuf 사용
  if (fd == STDOUT_FILENO) {
    printf("[DEBUG] Writing to STDOUT: size=%u\n", size);

    putbuf(buffer, size);
    bytes_written = size;
  }

  // 3. 일반 파일일 때
  else {
    struct file *file_obj = get_open_file(fd);
    if (file_obj != NULL) {
      bytes_written = file_write(file_obj, buffer, size);
    }
  }

  lock_release(&fs_lock);
  return bytes_written;
}