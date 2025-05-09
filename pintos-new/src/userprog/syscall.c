#include "devices/shutdown.h"
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
//static int memread_user (void *src, void *des, size_t bytes);
bool is_valid_ptr(const void *usr_ptr);
static struct file_desc* find_file_desc(struct thread *, int fd);

void halt (void);
void exit (int);
pid_t exec (const char *cmdline);
int wait (pid_t pid);

bool create(const char* filename, unsigned initial_size);
bool remove(const char* filename);
int open(const char* file);
void close(int fd);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

// in case of invalid memory access, fail and exit.
static void fail_invalid_access(void) {
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
      void* cmdline;
      if (!is_valid_ptr(f->esp + 4))
        fail_invalid_access();

      cmdline = *(void **)(f->esp + 4);
      int return_code = exec((const char*) cmdline);
      f->eax = (uint32_t) return_code;
      break;
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
      const char* filename;
      unsigned initial_size;
      bool return_code;

      if (!is_valid_ptr(f->esp + 4))
        fail_invalid_access();
      if (!is_valid_ptr(f->esp + 8))
        fail_invalid_access();

      filename = *(const char **)(f->esp + 4);
      initial_size = *(unsigned *)(f->esp + 8);
      return_code = create(filename, initial_size);
      f->eax = return_code;
      break;
    }
  
  case SYS_REMOVE: // 5
    {
      const char* filename;
      bool return_code;

      if (!is_valid_ptr(f->esp + 4))
        fail_invalid_access(); // invalid memory access

      filename = *(const char **)(f->esp + 4);
      return_code = remove(filename);
      f->eax = return_code;
      break;
    }  
  
  case SYS_OPEN: // 6
    {
      const char* filename;
      int return_code;

      if (!is_valid_ptr(f->esp + 4))
        fail_invalid_access();
      
      filename = *(const char **)(f->esp + 4);
      return_code = open(filename);
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
      //if (return_code == -1)
      //  thread_exit();
      f->eax = (uint32_t) return_code;
      break;
    }

  case SYS_SEEK: // 10
  case SYS_TELL: // 11
  case SYS_CLOSE: // 12

  /* unhandled case */
unhandled:
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

pid_t exec(const char *cmdline) {
  // cmdline is an address to the character buffer, on user memory
  // so a validation check is required
  if (get_user((const uint8_t*) cmdline) == -1) {
    fail_invalid_access();
    tid_t child_tid = process_execute(cmdline);
    return child_tid;
  }

  tid_t child_tid = process_execute(cmdline);
  return child_tid;
}

int wait(pid_t pid) {
  return process_wait(pid);
}

bool create(const char* filename, unsigned initial_size) {
  bool return_code;
  
  // memory validation
  if (get_user((const uint8_t*) filename) == -1) {
    fail_invalid_access();
  }

  return_code = filesys_create(filename, initial_size);
  return return_code;
}

bool remove(const char* filename) {
  bool return_code;

  // memory validation
  if (get_user((const uint8_t*) filename) == -1) {
    fail_invalid_access();
  }

  return_code = filesys_remove(filename);
  return return_code;
}

int open(const char* file) {
  struct file* file_opened;
  struct file_desc* fd = palloc_get_page(0);

  // memory validation
  if (get_user((const uint8_t*) file) == -1) {
    fail_invalid_access();
  }

  file_opened = filesys_open(file);
  if (!file_opened) {
    return -1;
  }

  fd->file = file_opened; //file save

  struct list* fd_list = &thread_current()->file_descriptors;
  if (list_empty(fd_list)) {
    // 0, 1, 2 are reserved for stdin, stdout, stderr
    fd->id = 3;
  }
  else {
    fd->id = (list_entry(list_back(fd_list), struct file_desc, elem)->id) + 1;
  }
  list_push_back(fd_list, &(fd->elem));

  return fd->id;
}

int filesize(int fd) {
  struct file_desc* file_d;

  // memory validation
  if (get_user((const uint8_t*) fd) == -1) {
    fail_invalid_access();
  }

  file_d = find_file_desc(thread_current(), fd);

  if(file_d == NULL) {
    return -1;
  }

  return file_length(file_d->file);
}

void close(int fd) {
  struct file_desc* file_d = find_file_desc(thread_current(), fd);

  // memory validation
  if (get_user((const uint8_t*) fd) == -1) {
     fail_invalid_access();
  }

  if(file_d && file_d->file) {
    file_close(file_d->file);
    list_remove(&(file_d->elem));
    palloc_free_page(file_d);
  }
}

int read(int fd, void *buffer, unsigned size) {
  // memory validation
  if (get_user((const uint8_t*) buffer) == -1) {
    fail_invalid_access();
  }

  if(fd == 0) { // stdin
    unsigned i;
    for(i = 0; i < size; ++i) {
      ((uint8_t *)buffer)[i] = input_getc();
    }
    return size;
  }
  else {
    // read from file
    struct file_desc* file_d = find_file_desc(thread_current(), fd);

    if(file_d && file_d->file) {
      return file_read(file_d->file, buffer, size);
    }
    else // no such file or can't open
      return -1;
  }
}

int write(int fd, const void *buffer, unsigned size) {
  // memory validation
  if (get_user((const uint8_t*) buffer) == -1) {
    // invalid
    fail_invalid_access();
  }

  // First, as of now, only implement fd=1 (stdout)
  // in order to display the messages from the test sets correctly.
  if(fd == 1) {
    putbuf(buffer, size);
    return size;
  }
  else {
    printf("[ERROR] write unimplemented\n");
    // write into file
    struct file_desc* file_d = find_file_desc(thread_current(), fd);

    if(file_d && file_d->file) {
      return file_write(file_d->file, buffer, size);
    }
    else // no such file or can't open
      return -1;
  }
  return -1;
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
  
static struct file_desc*
find_file_desc(struct thread *t, int fd)
{
  ASSERT (t != NULL);

  if (fd < 3) {
    return NULL;
  }

  struct list_elem *e;

  if (! list_empty(&t->file_descriptors)) {
    for(e = list_begin(&t->file_descriptors);
        e != list_end(&t->file_descriptors); e = list_next(e))
    {
      struct file_desc *desc = list_entry(e, struct file_desc, elem);
      if(desc->id == fd) {
        return desc;
      }
    }
  }

  return NULL; // not found
}