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
  tid_t owner;                // Owner thread ID
  struct file *file_struct;   // Pointer to the actual file object
  struct list_elem elem;      // List element for linking in descriptor list
};

static struct file_descriptor* get_open_file(int fd_num);
int allocate_fd(void);
void close_open_file(int fd_num);

void halt (void);
void exit (int);

pid_t exec (const char *cmd_line);

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
  lock_init(&filesys_lock); // Initialize the file system lock to ensure thread-safe access to files

  // Register system call interrupt handler (interrupt number 0x30)
  // Priority = 3, Interrupts enabled, Handler = syscall_handler, Name = "syscall"
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

  ASSERT(sizeof(syscall_number) == 4 ); // Assume 32-bit system (x86)

  /*
   * [1] Stack pointer validation
   * - Check if the user stack pointer is valid
   * - It must point to a valid user address
   */
  if (!is_valid_ptr(f->esp))
    fail_invalid_access();

  /*
   * [2] Extract system call number
   * - The system call number is located at the top of the stack (at f->esp)
   */  
  syscall_number = *(int *)(f->esp);

   /*
   * [3] System call processing
   * - Dispatch system call by number using a switch-case
   * - For each case, validate the pointer to arguments (f->esp + 4, etc.)
   * - Extract arguments and call the corresponding system call function
   */
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
      void* cmd_line;

      // Validate the user pointer to prevent invalid memory access
      if (!is_valid_ptr(f->esp + 4))
        fail_invalid_access();

      // Read the argument (pointer to command line string) from user stack  
      cmd_line = *(void **)(f->esp + 4);
      // [3] Execute the command line string as a new process
      int return_code = exec((const char*) cmd_line);
      // Store the return value (TID or -1) in eax to return to user program
      f->eax = (uint32_t) return_code;

      break;
    }

  case SYS_WAIT: // 3
    {
      pid_t pid;
      if (!is_valid_ptr(f->esp + 4))
        fail_invalid_access();

      pid = *(pid_t *)(f->esp + 4);
      /*
       * [4] Return result of the system call
       * - Store the return value of wait() in f->eax
       */
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

/*
 * Shut down the PintOS machine
 * - Calls shutdown_power_off() to power down the machine
 */
void halt(void) {
  shutdown_power_off();
}

/*
 * Terminate the current user program and return status to the kernel
 * 1. Get the current thread's name
 * 2. Print "thread_name: exit(status)"
 * 3. Terminate the current thread using thread_exit()
 */
void exit(int status) {
  struct thread *cur = thread_current();  // Get the current thread
  struct thread *parent = NULL; // Initialize parent pointer to NULL

  cur->exit_status = status;  // Save the exit status to the current thread

  printf("%s: exit(%d)\n", cur->name, status);  // Print the process exit message

  if (cur->parent_id != TID_ERROR) {  // If the current thread has a valid parent
    parent = get_thread_by_id(cur->parent_id);  // Retrieve the parent thread by its ID

    if (parent != NULL) {
      lock_acquire(&parent->lock_child);  // Acquire the lock to access the parent's children list

      struct list_elem *e;
      for (e = list_begin(&parent->children); e != list_end(&parent->children); e = list_next(e)) {
        // Get child status from list
        struct child_status *child = list_entry(e, struct child_status, elem);
         // Match the current thread with its child status entry
        if (child->tid == cur->tid) {
          child->exit_status = status; // Set child's exit status
          child->exited = true; // Mark the child as exited

          // Signal the parent if it's waiting
          cond_signal(&parent->cond_child, &parent->lock_child);
          break;
        }
      }

      lock_release(&parent->lock_child);  // Release the lock after updating
    }
  }

  thread_exit();  // Terminate the current thread and clean up resources
}

pid_t exec(const char *cmd_line) {
  tid_t tid = TID_ERROR;  // Initialize thread ID to error
  struct thread *cur = thread_current();  // Get the current thread

  if (!is_valid_ptr(cmd_line)) {  // Validate the user pointer to command line
    exit(-1);  // If invalid, terminate the process
  }

  cur->child_load_status = 0;  // Initialize child load status to 0 (not yet loaded)

  lock_acquire(&cur->lock_child);  // Acquire lock to synchronize with child loading

  tid = process_execute(cmd_line);  // Create a new process with the given command line

  while (cur->child_load_status == 0)  // Wait while child is still loading
    cond_wait(&cur->cond_child, &cur->lock_child);  // Wait for condition signal from child

  if (cur->child_load_status == -1)  // If loading failed
    tid = TID_ERROR;  // Set return value to error

  lock_release(&cur->lock_child);  // Release the lock after child finished loading

  return tid;  // Return the child's thread ID or error
}

/*
 * Wait for a child process to terminate and return its exit status
 * - Calls process_wait() with the given pid
 */
int wait(pid_t pid) {
  return process_wait(pid);
}

bool create(const char* file_name, unsigned size) {  
  // Check if the file_name pointer is valid
  if (!is_valid_ptr((const void *)file_name))
    fail_invalid_access();  // Exit if pointer is invalid

  lock_acquire(&filesys_lock); // Acquire file system lock to prevent concurrent access  
  bool return_code = filesys_create(file_name, size); // Create a new file with the given name and size
  lock_release(&filesys_lock); // Release the file system lock
  return return_code; // Return whether creation was successful
}

bool remove(const char* file_name) {
  // Check if the file_name pointer is valid
  if (!is_valid_ptr((const void *)file_name))
    fail_invalid_access();  // Exit if invalid

  lock_acquire(&filesys_lock); // Acquire file system lock before modifying filesystem
  bool return_code = filesys_remove(file_name); // Delete the file using file system API
  lock_release(&filesys_lock); // Release the file system lock
  return return_code; // Return whether the file was successfully removed
}

int open(const char* file_name) {
  // Check if file_name pointer is valid (non-null, user address, mapped)
  if (!is_valid_ptr(file_name))
    fail_invalid_access();

  // Acquire the global file system lock to ensure thread-safe access    
  lock_acquire(&filesys_lock);

  // Try to open the file using file_name
  struct file* file_opened = filesys_open(file_name); 
  if (!file_opened) {
    lock_release(&filesys_lock);
    return -1;
  }

  // Allocate memory for a new file descriptor
  struct file_descriptor* fd = palloc_get_page(0);
  if (!fd) {
    file_close(file_opened);
    lock_release(&filesys_lock);
    return -1;
  }

  // Initialize file descriptor fields: file pointer, fd number, owner
  fd->file_struct = file_opened;
  fd->fd_num = allocate_fd();  // assign unique fd number
  fd->owner = thread_current()->tid;  // track thread that opened the file

  // Add file descriptor to current thread's open file list
  list_push_back(&thread_current()->file_descriptors, &fd->elem);

  // Release the file system lock and return the file descriptor number
  lock_release(&filesys_lock);
  return fd->fd_num;
}

int filesize(int fd) {
  // Acquire file system lock for thread-safe access
  lock_acquire(&filesys_lock);

  // Search for the open file descriptor matching fd
  struct file_descriptor* file_d = get_open_file(fd);
  if(file_d == NULL) {
    // If not found, release lock and return -1
    lock_release(&filesys_lock);
    return -1;
  }
  
  int length = file_length(file_d->file_struct); // Retrieve file size using file_length()
  lock_release(&filesys_lock); // Release file system lock
  return length; // Return the size of the file
}

int read(int fd, void *buffer, unsigned size) {
  // Check if the entire buffer range is valid in user space
  if (!is_valid_ptr(buffer) || !is_valid_ptr((uint8_t *)buffer + size - 1)) {
    fail_invalid_access();
  }

  // Acquire file system lock to prevent concurrent access
  lock_acquire(&filesys_lock);

  // Check if fd is STDOUT (1), which is invalid for reading
  if (fd == 1) {
    lock_release(&filesys_lock);
    return -1;
  }

  // If fd is STDIN (0), read input from keyboard one byte at a time
  if(fd == 0) { // stdin
    unsigned i;
    for(i = 0; i < size; ++i) {
      ((uint8_t *)buffer)[i] = input_getc();  // Read character into buffer
    }
    lock_release(&filesys_lock);
    return size;  // Return number of bytes read from stdin
  }
  
   // If not STDIN or STDOUT, read from a regular file
  struct file_descriptor* file_d = get_open_file(fd);
  if(file_d && file_d->file_struct) {
    int bytes_read = file_read(file_d->file_struct, buffer, size);
    lock_release(&filesys_lock);
    return bytes_read;  // Return number of bytes read or -1 if invalid
  }

  lock_release(&filesys_lock);
  return -1;
}

int write(int fd, const void *buffer, unsigned size) {
  unsigned i;

  // [1] Validate each byte in the buffer to ensure it's in user address space
  for (i = 0; i < size; i++) {
    if (!is_valid_ptr((const uint8_t *)buffer + i))
      fail_invalid_access();
  }

  // [2] Acquire file system lock to ensure thread-safe access
  lock_acquire(&filesys_lock);

  // [3] If fd refers to STDIN (0), writing is not allowed
  if (fd == 0) {
    lock_release(&filesys_lock);
    return -1;
  }

  // [4] If fd refers to STDOUT (1), write using putbuf and return size
  if(fd == 1) {
    putbuf(buffer, size);
    lock_release(&filesys_lock);
    return size;
  }

  // [5] For regular files: get the file descriptor entry
  struct file_descriptor* file_d = get_open_file(fd);
  int result = -1;

  // If the file is valid, perform write operation
  if (file_d && file_d->file_struct)
    result = file_write(file_d->file_struct, buffer, size);
  
  // [6] Release the file system lock and return result  
  lock_release(&filesys_lock);
  return result;
}

void seek(int fd, unsigned position) {
  // Acquire file system lock to ensure thread-safe file operations
  lock_acquire(&filesys_lock);

  // Get the file descriptor structure corresponding to fd
  struct file_descriptor* file_d = get_open_file(fd);
  // If the file descriptor and its associated file object are valid, move the file pointer
  if(file_d && file_d->file_struct)
    file_seek(file_d->file_struct, position); // move pointer to specified position
  
  lock_release(&filesys_lock); // Release the file system lock
}

unsigned tell(int fd) {
  unsigned result = 0;

  // Acquire file system lock to ensure mutual exclusion
  lock_acquire(&filesys_lock);

  // Retrieve file descriptor corresponding to fd
  struct file_descriptor* file_d = get_open_file(fd);
  // If the descriptor and file are valid, return the current position in file
  if(file_d && file_d->file_struct) 
    return file_tell(file_d->file_struct);

  lock_release(&filesys_lock); // Release lock if file is invalid or not open
  return result; // Return default result (0) if tell fails
}

void close(int fd) {
  lock_acquire(&filesys_lock); // Acquire file system lock to prevent race conditions while accessing file table
  close_open_file(fd); // Close the file corresponding to the given file descriptor
  lock_release(&filesys_lock); // Release the file system lock to allow other threads to access the file system
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
  /*
   * [1] Obtain current thread
   * - Get the currently running thread using thread_current()
   */
  struct thread *cur = thread_current();

  /*
   * [2] Validate the pointer
   * - Return false if usr_ptr is NULL (NULL is not a valid memory reference)
   */
  if (usr_ptr == NULL)
    return false;

  /*
   * - Check if the address is in user virtual address space
   * - is_user_vaddr() ensures it's in user-accessible range
   */
  if (!is_user_vaddr(usr_ptr))
    return false;

  /*
   * [3] Check page directory
   * - pagedir_get_page() verifies that usr_ptr points to a valid physical page
   * - Returns NULL if the page is not mapped (i.e., not allocated)
   */
  if (pagedir_get_page(cur->pagedir, usr_ptr) == NULL)
    return false;

  /*
   * - If all checks pass, the pointer is valid
   */  
  return true;
}

static struct file_descriptor*
get_open_file(int fd_num)
{
  struct thread *t = thread_current();  // Get the current thread
  ASSERT(t != NULL);

  if (fd_num < 3) {  // Skip STDIN, STDOUT, STDERR
    return NULL; // 0, 1, 2: stdin, stdout, stderr
  }

  struct list_elem *e;
  for (e = list_begin(&t->file_descriptors);
       e != list_end(&t->file_descriptors);
       e = list_next(e))
  {
    struct file_descriptor *desc = list_entry(e, struct file_descriptor, elem);
    if (desc->fd_num == fd_num) {  // Match found → return pointer
      return desc;  // No match found → return NULL
    }
  }

  return NULL;
}

int
allocate_fd(void) 
{
  struct thread *cur = thread_current(); // Get the current running thread
  return cur->next_fd++; // Return the current value of next_fd and increment it for the next allocation
}

void
close_open_file(int fd_num) 
{
  // Get the current thread's file descriptor list
  struct list *fd_list = &thread_current()->file_descriptors; 
  struct list_elem *e;

  // Iterate through the file descriptor list
  for (e = list_begin(fd_list); e != list_end(fd_list); e = list_next(e)) {
    // Retrieve the file_descriptor struct from the list element
    struct file_descriptor *desc = list_entry(e, struct file_descriptor, elem);
    // Check if this descriptor matches the given fd number
    if (desc->fd_num == fd_num) {
      file_close(desc->file_struct); // Close the associated file object
      list_remove(e); // Remove the file descriptor from the list
      palloc_free_page(desc); // Free the allocated memory for the descriptor
      return; // Exit after closing
    }
  }
}