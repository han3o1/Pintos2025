#include "devices/shutdown.h"
#include "devices/input.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/palloc.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "lib/kernel/list.h"

static void syscall_handler (struct intr_frame *);

static int32_t get_user (const uint8_t *uaddr);
bool is_valid_ptr(const void *usr_ptr);

struct
file_descriptor 
{
  int fd_num;                 // File descriptor number
  tid_t owner;                // 소유자
  struct file *file_struct;   // 실제 파일 객체 포인터
  struct list_elem elem;      // 리스트 연결용 엘리먼트
};

static struct file_descriptor* get_open_file(int fd_num);
int allocate_fd(void);
void close_open_file(int fd_num);

void halt (void);
void exit (int);
//pid_t exec (const char *cmdline);
int wait (pid_t pid);

bool create(const char* file_name, unsigned size);
bool remove(const char* file_name);
int open(const char* file_name);
int filesize(int fd);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);

struct lock filesys_lock;

void
syscall_init (void)
{
  lock_init(&filesys_lock);

  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

// in case of invalid memory access, fail and exit.
static void fail_invalid_access(void) 
{
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
  case SYS_HALT: // 0
    {
      halt();
      NOT_REACHED();
      break;
    }

  case SYS_EXIT: // 1
    {
      int exitcode;
      if (!is_valid_ptr(f->esp + 4))
        fail_invalid_access();

      exitcode = *(int *)(f->esp + 4);
      exit(exitcode);
      NOT_REACHED();
      break;
    }

  case SYS_EXEC: // 2
    {
      /*void* cmdline;
      if (!is_valid_ptr(f->esp + 4))
        fail_invalid_access();

      cmdline = *(void **)(f->esp + 4);
      int return_code = exec((const char*) cmdline);
      f->eax = (uint32_t) return_code;
      break;*/
    }

  case SYS_WAIT: // 3
    {
      pid_t pid;
      if (!is_valid_ptr(f->esp + 4))
        fail_invalid_access();

      pid = *(pid_t *)(f->esp + 4);
      f->eax = (uint32_t) wait(pid);
      break;
    }
  
  case SYS_CREATE: // 4
    {
      const char* file_name;
      unsigned size;
      bool return_code;

      if (!is_valid_ptr(f->esp + 4))
        fail_invalid_access();
      if (!is_valid_ptr(f->esp + 8))
        fail_invalid_access();

      file_name = *(const char **)(f->esp + 4);
      size = *(unsigned *)(f->esp + 8);
      return_code = create(file_name, size);
      f->eax = return_code;
      break;
    }
  
  case SYS_REMOVE: // 5
    {
      const char* file_name;
      bool return_code;

      if (!is_valid_ptr(f->esp + 4))
        fail_invalid_access();

      file_name = *(const char **)(f->esp + 4);
      return_code = remove(file_name);
      f->eax = return_code;
      break;
    }  
  
  case SYS_OPEN: // 6
    {
      const char* file_name;
      int return_code;

      if (!is_valid_ptr(f->esp + 4))
        fail_invalid_access();
      
      file_name = *(const char **)(f->esp + 4);
      return_code = open(file_name);
      f->eax = return_code;
      break;
    }
  
  case SYS_FILESIZE: // 7
    {
      int fd, return_code;

      if (!is_valid_ptr(f->esp + 4))
        fail_invalid_access();

      fd = *(int *)(f->esp + 4);
      return_code = filesize(fd);
      f->eax = return_code;
      break;
    }
  
  case SYS_READ: // 8
    {
      int fd, return_code;
      void *buffer;
      unsigned size;

      if (!is_valid_ptr(f->esp + 4)) fail_invalid_access();
      if (!is_valid_ptr(f->esp + 8)) fail_invalid_access();
      if (!is_valid_ptr(f->esp + 12)) fail_invalid_access();

      fd = *(int *)(f->esp + 4);
      buffer = *(void **)(f->esp + 8);
      size = *(unsigned *)(f->esp + 12);
      return_code = read(fd, buffer, size);
      f->eax = (uint32_t) return_code;
      break;
    }
  
  case SYS_WRITE: // 9
    {
      int fd;
      const void *buffer;
      unsigned size;

      if (!is_valid_ptr(f->esp + 4)) fail_invalid_access();
      if (!is_valid_ptr(f->esp + 8)) fail_invalid_access();
      if (!is_valid_ptr(f->esp + 12)) fail_invalid_access();

      fd = *(int *)(f->esp + 4);
      buffer = *(void **)(f->esp + 8);
      size = *(unsigned *)(f->esp + 12);

      int return_code = write(fd, buffer, size);
      f->eax = (uint32_t) return_code;
      break;
    }

  case SYS_SEEK: // 10
    {
      int fd;
      unsigned position;

      if (!is_valid_ptr(f->esp + 4)) fail_invalid_access();
      if (!is_valid_ptr(f->esp + 8)) fail_invalid_access();

      fd = *(int *)(f->esp + 4);
      position = *(unsigned *)(f->esp + 8);
      seek(fd, position);
      break;
    }
  
  case SYS_TELL: // 11
    {
      int fd;
      unsigned return_code;

      if (!is_valid_ptr(f->esp + 4))
        fail_invalid_access();
      
      fd = *(int *)(f->esp + 4);
      return_code = tell(fd);
      f->eax = (uint32_t) return_code;
      break;
    }

  case SYS_CLOSE: // 12
    {
      int fd;

      if (!is_valid_ptr(f->esp + 4))
        fail_invalid_access();

      fd = *(int *)(f->esp + 4);
      close(fd);
      break;
    }

  default:
    exit (-1);
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

/*pid_t exec(const char *cmdline) {
  if (get_user((const uint8_t*) cmdline) == -1) {
    fail_invalid_access();
    tid_t child_tid = process_execute(cmdline);
    return child_tid;
  }

  tid_t child_tid = process_execute(cmdline);
  return child_tid;
}*/

int wait(pid_t pid) {
  return process_wait(pid);
}

bool create(const char* file_name, unsigned size) {  
  if (!is_valid_ptr((const void *)file_name))
    fail_invalid_access();

  lock_acquire(&filesys_lock);
  bool return_code = filesys_create(file_name, size);
  lock_release(&filesys_lock);
  return return_code;
}

bool remove(const char* file_name) {
  if (!is_valid_ptr((const void *)file_name))
    fail_invalid_access();

  lock_acquire(&filesys_lock);
  bool return_code = filesys_remove(file_name);
  lock_release(&filesys_lock);
  return return_code;
}

int open(const char* file_name) {
  if (!is_valid_ptr(file_name))
    fail_invalid_access();

  lock_acquire(&filesys_lock);
  struct file* file_opened = filesys_open(file_name);
  if (!file_opened) {
    lock_release(&filesys_lock);
    return -1;
  }

  struct file_descriptor* fd = palloc_get_page(0);
  if (!fd) {
    file_close(file_opened);
    lock_release(&filesys_lock);
    return -1;
  }

  fd->file_struct = file_opened;
  fd->fd_num = allocate_fd();
  fd->owner = thread_current()->tid;

  list_push_back(&thread_current()->file_descriptors, &fd->elem);
  lock_release(&filesys_lock);
  return fd->fd_num;
}

int filesize(int fd) {
  lock_acquire(&filesys_lock);

  struct file_descriptor* file_d = get_open_file(fd);
  if(file_d == NULL) {
    lock_release(&filesys_lock);
    return -1;
  }

  int length = file_length(file_d->file_struct);
  lock_release(&filesys_lock);
  return length;
}

int read(int fd, void *buffer, unsigned size) {
  if (!is_valid_ptr(buffer) || !is_valid_ptr((uint8_t *)buffer + size - 1)) {
    fail_invalid_access();
  }

  lock_acquire(&filesys_lock);

  if (fd == 1) {
    // stdout은 읽기 불가능
    lock_release(&filesys_lock);
    return -1;
  }

  if(fd == 0) { // stdin
    unsigned i;
    for(i = 0; i < size; ++i) {
      ((uint8_t *)buffer)[i] = input_getc();
    }
    lock_release(&filesys_lock);
    return size;
  }
  
  struct file_descriptor* file_d = get_open_file(fd);
  if(file_d && file_d->file_struct) {
    int bytes_read = file_read(file_d->file_struct, buffer, size);
    lock_release(&filesys_lock);
    return bytes_read;
  }

  lock_release(&filesys_lock);
  return -1;
}

int write(int fd, const void *buffer, unsigned size) {
  unsigned i;
  for (i = 0; i < size; i++) {
    if (!is_valid_ptr((const uint8_t *)buffer + i))
      fail_invalid_access();
  }

  lock_acquire(&filesys_lock);

  if (fd == 0) {
    lock_release(&filesys_lock);
    return -1;
  }

  if(fd == 1) {
    putbuf(buffer, size);
    lock_release(&filesys_lock);
    return size;
  }
  
  struct file_descriptor* file_d = get_open_file(fd);
  int result = -1;
  if (file_d && file_d->file_struct)
    result = file_write(file_d->file_struct, buffer, size);
    
  lock_release(&filesys_lock);
  return result;
}

void seek(int fd, unsigned position) {
  lock_acquire(&filesys_lock);

  struct file_descriptor* file_d = get_open_file(fd);
  if(file_d && file_d->file_struct)
    file_seek(file_d->file_struct, position);
  
  lock_release(&filesys_lock);
}

unsigned tell(int fd) {
  unsigned result = 0;

  lock_acquire(&filesys_lock);

  struct file_descriptor* file_d = get_open_file(fd);
  if(file_d && file_d->file_struct)
    return file_tell(file_d->file_struct);

  lock_release(&filesys_lock);
  return result;
}

void close(int fd) {
  lock_acquire(&filesys_lock);
  close_open_file(fd);
  lock_release(&filesys_lock);
}


/****************** Helper Functions on Memory Access ********************/

static int32_t
get_user (const uint8_t *uaddr) {
  // check that a user pointer `uaddr` points below PHYS_BASE
  if (! ((void*)uaddr < PHYS_BASE)) {
    return -1; // invalid memory access
  }

  // as suggested in the reference manual, see (3.1.5)
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
      : "=&a" (result) : "m" (*uaddr));
  return result;
}
  
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

static struct file_descriptor*
get_open_file(int fd_num)
{
  struct thread *t = thread_current();
  ASSERT(t != NULL);

  if (fd_num < 3) {
    return NULL; // 0, 1, 2는 stdin, stdout, stderr
  }

  struct list_elem *e;
  for (e = list_begin(&t->file_descriptors);
       e != list_end(&t->file_descriptors);
       e = list_next(e))
  {
    struct file_descriptor *desc = list_entry(e, struct file_descriptor, elem);
    if (desc->fd_num == fd_num) {
      return desc;
    }
  }

  return NULL;
}

int
allocate_fd(void) 
{
  struct thread *cur = thread_current();
  return cur->next_fd++;
}

void
close_open_file(int fd_num) 
{
  struct list *fd_list = &thread_current()->file_descriptors;
  struct list_elem *e;

  for (e = list_begin(fd_list); e != list_end(fd_list); e = list_next(e)) {
    struct file_descriptor *desc = list_entry(e, struct file_descriptor, elem);
    if (desc->fd_num == fd_num) {
      file_close(desc->file_struct);
      list_remove(e);
      palloc_free_page(desc);
      return;
    }
  }
}