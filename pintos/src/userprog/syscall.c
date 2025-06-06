#include "devices/shutdown.h"
#include "devices/input.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "lib/kernel/list.h"
#ifdef VM
#include "vm/page.h"
#endif

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
  struct file* file;
};

static struct file_descriptor* get_open_file(int fd_num);
int allocate_fd(void);
void close_open_file(int fd_num);

void halt (void);
void exit (int);
pid_t exec (const char *cmd_line);
int wait (pid_t pid);

bool create(const char* file_name, unsigned initial_size);
bool remove(const char* file_name);
int open(const char* file_name);
int filesize(int fd);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);

#ifdef VM
mmapid_t sys_mmap(int fd, void *);
bool sys_munmap(mmapid_t);

static struct mmap_desc* find_mmap_desc(struct thread *, mmapid_t fd);

void preload_and_pin_pages(const void *, size_t);
void unpin_preloaded_pages(const void *, size_t);
#endif

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
  if (lock_held_by_current_thread(&filesys_lock))
  lock_release (&filesys_lock);

  exit (-1);
  NOT_REACHED();
}

static void
syscall_handler (struct intr_frame *f)
{
  int syscall_number;

  ASSERT(sizeof(syscall_number) == 4 ); // assuming x86

  /*
   * 1. Stack pointer validation
   * - Check if the user stack pointer is valid
   * - It must point to a valid user address
   */
  if (!is_valid_ptr(f->esp))
    fail_invalid_access();
  
  /*
   * 2. Extract system call number
   * - The system call number is located at the top of the stack (at f->esp)
   */
  syscall_number = *(int *)(f->esp);

  /*
   * 3. System call processing
   * - Dispatch system call by number using a switch-case
   * - For each case, validate the pointer to arguments (f->esp + 4, etc.)
   * - Extract arguments and call the corresponding system call function
   */
  switch (syscall_number) {
    case SYS_HALT: // 0
      {
        halt();                     // Terminates the OS
        NOT_REACHED();              // Should never reach here after halt
        break;
      }

    case SYS_EXIT: // 1
      {
        int exitcode;
        // Validate the user pointer to prevent invalid memory access
        if (!is_valid_ptr(f->esp + 4))
          fail_invalid_access();

        exitcode = *(int *)(f->esp + 4);  // Get exit status from user stack
        exit(exitcode);                   // Terminate the current process
        NOT_REACHED();
        break;
      }

    case SYS_EXEC: // 2
      {
        void* cmd_line;
        if (!is_valid_ptr(f->esp + 4))
          fail_invalid_access();
        
        cmd_line = *(void **)(f->esp + 4);               // Read the command line string address from user stack
        int return_code = exec((const char*) cmd_line);  // Execute the command line and return the new process's TID
        f->eax = (uint32_t) return_code;                 // Return TID (or -1) to user program
        break;
      }

    case SYS_WAIT: // 3
      {
        pid_t pid;
        if (!is_valid_ptr(f->esp + 4))
          fail_invalid_access();

        pid = *(pid_t *)(f->esp + 4);      // Get PID to wait on
        f->eax = (uint32_t) wait(pid);     // Return child's exit status
        break;
      }
    
    case SYS_CREATE: // 4
      {
        const char* file_name;
        unsigned initial_size;
        bool return_code;

        if (!is_valid_ptr(f->esp + 4))
          fail_invalid_access();
        if (!is_valid_ptr(f->esp + 8))
          fail_invalid_access();

        file_name = *(const char **)(f->esp + 4);  // Get file name
        initial_size = *(unsigned *)(f->esp + 8);          // Get initial size
        return_code = create(file_name, initial_size);     // Create the file
        f->eax = return_code;                      // Return true/false
        break;
      }
    
    case SYS_REMOVE: // 5
      {
        const char* file_name;
        bool return_code;

        if (!is_valid_ptr(f->esp + 4))
          fail_invalid_access();

        file_name = *(const char **)(f->esp + 4);  // Get file name
        return_code = remove(file_name);          // Attempt to remove file
        f->eax = return_code;                     // Return true/false
        break;
      }  
    
    case SYS_OPEN: // 6
      {
        const char* file_name;
        int return_code;

        if (!is_valid_ptr(f->esp + 4))
          fail_invalid_access();
        
        file_name = *(const char **)(f->esp + 4);  // Get file name
        return_code = open(file_name);            // Open the file
        f->eax = return_code;                     // Return file descriptor or -1
        break;
      }
    
    case SYS_FILESIZE: // 7
      {
        int fd, return_code;

        if (!is_valid_ptr(f->esp + 4))
          fail_invalid_access();

        fd = *(int *)(f->esp + 4);           // Get file descriptor
        return_code = filesize(fd);          // Get file size
        f->eax = return_code;                // Return size
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

        fd = *(int *)(f->esp + 4);              // Get file descriptor
        buffer = *(void **)(f->esp + 8);        // Get buffer pointer
        size = *(unsigned *)(f->esp + 12);      // Get size to read
        return_code = read(fd, buffer, size);   // Read from file
        f->eax = (uint32_t) return_code;        // Return number of bytes read
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

        fd = *(int *)(f->esp + 4);              // Get file descriptor
        buffer = *(void **)(f->esp + 8);        // Get buffer pointer
        size = *(unsigned *)(f->esp + 12);      // Get size to write

        int return_code = write(fd, buffer, size);  // Write to file
        f->eax = (uint32_t) return_code;            // Return number of bytes written
        break;
      }

    case SYS_SEEK: // 10
      {
        int fd;
        unsigned position;

        if (!is_valid_ptr(f->esp + 4)) fail_invalid_access();
        if (!is_valid_ptr(f->esp + 8)) fail_invalid_access();

        fd = *(int *)(f->esp + 4);          // Get file descriptor
        position = *(unsigned *)(f->esp + 8);  // Get new position
        seek(fd, position);                 // Set file position
        break;
      }
    
    case SYS_TELL: // 11
      {
        int fd;
        unsigned return_code;

        if (!is_valid_ptr(f->esp + 4))
          fail_invalid_access();
        
        fd = *(int *)(f->esp + 4);         // Get file descriptor
        return_code = tell(fd);           // Get current file position
        f->eax = (uint32_t) return_code;  // Return position
        break;
      }

    case SYS_CLOSE: // 12
      {
        int fd;

        if (!is_valid_ptr(f->esp + 4))
          fail_invalid_access();

        fd = *(int *)(f->esp + 4);   // Get file descriptor
        close(fd);                  // Close the file
        break;
      }

#ifdef VM
    case SYS_MMAP: // 13
      {
        int fd;
        void *addr;

        if (!is_valid_ptr(f->esp + 4)) fail_invalid_access();
        if (!is_valid_ptr(f->esp + 8)) fail_invalid_access();

        fd = *(int *)(f->esp + 4);
        addr = *(void **)(f->esp + 8);

        mmapid_t ret = sys_mmap(fd, addr);
        f->eax = ret;
        break;
      }

    case SYS_MUNMAP: // 14
      {
        mmapid_t mid;

        if (!is_valid_ptr(f->esp + 4)) fail_invalid_access();

        mid = *(mmapid_t *)(f->esp + 4);

        sys_munmap(mid);
        break;
      }
#endif

    default:
      exit (-1); // If unknown syscall number, terminate process
      break;
  }
}

/*
 * Halts the entire operating system by powering off the machine.
 * This function does not return.
 */
void halt(void) {
  shutdown_power_off();  // Powers off the machine immediately
}

/*
 * Terminates the current user program and returns status to the kernel.
 * Also updates the parent's record of this process if applicable.
 */
void exit(int status) {
  struct thread *cur = thread_current();        // Get the currently running thread
  struct thread *parent = NULL;                 // Initialize parent pointer

  cur->exit_status = status;                    // Save exit status to current thread

  printf("%s: exit(%d)\n", cur->name, status);  // Print thread name and exit code to console

  // If the thread has a parent (not an initial process)
  if (cur->parent_id != TID_ERROR) {
    parent = get_thread_by_id(cur->parent_id);  // Look up the parent thread using its ID

    if (parent != NULL) {
      lock_acquire(&parent->lock_child);        // Acquire lock to safely access parent's children list

      // Iterate over the parent's children list
      struct list_elem *e;
      for (e = list_begin(&parent->children); 
           e != list_end(&parent->children); 
           e = list_next(e)) {

        struct child_status *child = list_entry(e, struct child_status, elem);  // Access child_status struct

        if (child->tid == cur->tid) {           // If the entry matches this thread
          child->exit_status = status;          // Store the exit status
          child->exited = true;                 // Mark the child as exited
          cond_signal(&parent->cond_child, &parent->lock_child);  // Wake up parent if it's waiting
          break;                                // Done updating this child
        }
      }

      lock_release(&parent->lock_child);        // Release lock after modifying shared data
    }
  }

  thread_exit();                                // Terminate the current thread and clean up resources
}

/*
 * Executes a new user process from the given command line.
 * Synchronizes with the child to ensure it loads correctly.
 * Returns the child thread ID (TID), or TID_ERROR if execution fails.
 */
pid_t exec(const char *cmd_line) {
  tid_t tid = TID_ERROR;                     // Initialize return value to error
  struct thread *cur = thread_current();     // Get the currently running thread

  // 1. Validate the user-provided pointer to avoid illegal memory access
  if (!is_valid_ptr(cmd_line)) {
    exit(-1);                                // Terminate if the pointer is invalid
  }

  // 2. Reset the load status before launching the child
  cur->child_load_status = 0;                // 0 means "not yet loaded"

  // 3. Acquire the lock to synchronize with the child during loading
  lock_acquire(&cur->lock_child);

  // 4. Create a new thread (child process) with the given command line
  tid = process_execute(cmd_line);           // This also triggers start_process()

  // 5. Wait until the child process either loads successfully or fails
  while (cur->child_load_status == 0)
    cond_wait(&cur->cond_child, &cur->lock_child);  // Sleep until the child signals

  // 6. Check the load status. If -1, child failed to load.
  if (cur->child_load_status == -1)
    tid = TID_ERROR;                         // Return error if child load failed

  // 7. Release the lock now that loading has finished
  lock_release(&cur->lock_child);

  return tid;                                // Return child TID or error
}

/*
 * Waits for the child process with the given PID to exit.
 * Returns the exit status of the child, or -1 on failure.
 */
int wait(pid_t pid) {
  return process_wait(pid);  // Delegate to process_wait() implementation
}

/*
 * Creates a new file with the given name and initial size.
 * Returns true if the file was created successfully, false otherwise.
 */
bool create(const char* file_name, unsigned initial_size) {  
  // 1. Validate the file name pointer to ensure it's in user space
  if (!is_valid_ptr((const void *)file_name))
    fail_invalid_access();   // Kill the process if the pointer is invalid

  // 2. Acquire the file system lock before modifying shared resources
  lock_acquire(&filesys_lock);

  // 3. Attempt to create the file
  bool return_code = filesys_create(file_name, initial_size);

  // 4. Release the file system lock after the operation
  lock_release(&filesys_lock);

  return return_code;   // Return the result of the creation operation
}

/*
 * Removes a file with the given name from the file system.
 * Returns true if the file was removed successfully, false otherwise.
 */
bool remove(const char* file_name) {
  // 1. Validate the file name pointer
  if (!is_valid_ptr((const void *)file_name))
    fail_invalid_access();   // Kill the process on invalid access

  // 2. Acquire lock to ensure mutual exclusion
  lock_acquire(&filesys_lock);

  // 3. Attempt to remove the file
  bool return_code = filesys_remove(file_name);

  // 4. Release the lock after operation
  lock_release(&filesys_lock);

  return return_code;  // Return the result of the remove operation
}

/*
 * Opens a file with the given name and returns its file descriptor.
 * Returns -1 if the file cannot be opened or allocation fails.
 */
int open(const char* file_name) {
  // 1. Validate the user-provided file name pointer
  if (!is_valid_ptr(file_name))
    fail_invalid_access();   // Exit the process on invalid pointer

  // 2. Acquire file system lock to access shared file table
  lock_acquire(&filesys_lock);

  // 3. Try to open the file using the file system
  struct file* file_opened = filesys_open(file_name);
  if (!file_opened) {                    // If open failed
    lock_release(&filesys_lock);
    return -1;
  }

  // 4. Allocate a page for file descriptor structure
  struct file_descriptor* fd = palloc_get_page(0);
  if (!fd) {
    file_close(file_opened);            // Free the opened file if allocation failed
    lock_release(&filesys_lock);
    return -1;
  }

  // 5. Fill the file descriptor structure
  fd->file_struct = file_opened;                 // Store the file pointer
  fd->fd_num = allocate_fd();                    // Assign a new file descriptor number
  fd->owner = thread_current()->tid;             // Set the owner thread

  // 6. Add the file descriptor to the current thread's list
  list_push_back(&thread_current()->file_descriptors, &fd->elem);

  // 7. Release the file system lock
  lock_release(&filesys_lock);

  return fd->fd_num;    // Return the assigned file descriptor number
}

/*
 * Returns the size of the file associated with the given file descriptor.
 * Returns -1 if the file descriptor is invalid.
 */
int filesize(int fd) {
  // 1. Acquire the file system lock to access shared file table
  lock_acquire(&filesys_lock);

  // 2. Get the file descriptor structure associated with fd
  struct file_descriptor* file_d = get_open_file(fd);
  if(file_d == NULL) {                  // If the fd is invalid or not open
    lock_release(&filesys_lock);
    return -1;
  }

  // 3. Get the file length using the file system API
  int length = file_length(file_d->file_struct);

  // 4. Release the lock after reading
  lock_release(&filesys_lock);

  return length;                        // Return the file size in bytes
}

/*
 * Reads data from the given file descriptor into the provided buffer.
 * Returns the number of bytes read, or -1 on failure.
 * Supports reading from stdin (fd == 0).
 */
int read(int fd, void *buffer, unsigned size) {
  // 1. Validate the buffer pointer and its last byte
  if (!is_valid_ptr(buffer) || !is_valid_ptr((uint8_t *)buffer + size - 1)) {
    fail_invalid_access();             // Terminate on invalid memory access
  }

  // 2. Acquire file system lock
  lock_acquire(&filesys_lock);

  // 3. Deny reading from stdout
  if (fd == 1) {
    lock_release(&filesys_lock);
    return -1;
  }

  // 4. If reading from stdin, get characters from keyboard input
  if(fd == 0) {
    unsigned i;
    for(i = 0; i < size; ++i) {
      ((uint8_t *)buffer)[i] = input_getc();   // Read one character at a time
    }
    lock_release(&filesys_lock);
    return size;                               // Return number of bytes read
  }

  int bytes_read;
  // 5. For regular files, retrieve the open file
  struct file_descriptor* file_d = get_open_file(fd);
  if(file_d && file_d->file_struct) {
#ifdef VM
      preload_and_pin_pages(buffer, size);
#endif
    bytes_read = file_read(file_d->file_struct, buffer, size); // Read from file
#ifdef VM
      unpin_preloaded_pages(buffer, size);
#endif
  } else {
    return -1;
  }

  // 6. If file not found or invalid
  lock_release(&filesys_lock);
  return bytes_read;
}

/*
 * Writes data from the given buffer to the file or stdout.
 * Returns the number of bytes written, or -1 on failure.
 * Denies writing to stdin (fd == 0).
 */
int write(int fd, const void *buffer, unsigned size) {
  unsigned i;

  // 1. Validate every byte in the buffer to ensure safe access
  for (i = 0; i < size; i++) {
    if (!is_valid_ptr((const uint8_t *)buffer + i))
      fail_invalid_access();           // Abort on invalid memory
  }

  // 2. Acquire file system lock
  lock_acquire(&filesys_lock);

  // 3. Writing to stdin is not allowed
  if (fd == 0) {
    lock_release(&filesys_lock);
    return -1;
  }

  // 4. Writing to stdout: use putbuf
  if(fd == 1) {
    putbuf(buffer, size);             // Output directly to screen
    lock_release(&filesys_lock);
    return size;
  }

  // 5. For regular files, retrieve file descriptor and write
  struct file_descriptor* file_d = get_open_file(fd);
  int result = -1;
  if (file_d && file_d->file_struct) {
#ifdef VM
      preload_and_pin_pages(buffer, size);
#endif
    result = file_write(file_d->file_struct, buffer, size);  // Write to file
#ifdef VM
      unpin_preloaded_pages(buffer, size);
#endif
  } else {
    result = -1;
  }

  // 6. Release lock and return result
  lock_release(&filesys_lock);
  return result;
}

#ifdef VM
mmapid_t sys_mmap(int fd, void *upage) {
  if (upage == NULL || pg_ofs(upage) != 0) return -1;
  if (fd <= 1) return -1;
  struct thread *curr = thread_current();

  lock_acquire (&filesys_lock);

  struct file *f = NULL;
  struct file_descriptor* file_d = get_open_file(fd);
  if(file_d && file_d->file_struct) {
    f = file_reopen (file_d->file_struct);
  }
  if(f == NULL) goto MMAP_FAIL;

  size_t file_size = file_length(f);
  if(file_size == 0) goto MMAP_FAIL;

  size_t offset;
  for (offset = 0; offset < file_size; offset += PGSIZE) {
    void *addr = upage + offset;
    if (vm_spt_has_entry(curr->spt, addr)) goto MMAP_FAIL;
  }

  for (offset = 0; offset < file_size; offset += PGSIZE) {
    void *addr = upage + offset;

    size_t read_bytes = (offset + PGSIZE < file_size ? PGSIZE : file_size - offset);
    size_t zero_bytes = PGSIZE - read_bytes;

    vm_spt_install_filesys(curr->spt, addr,
        f, offset, read_bytes, zero_bytes, true);
  }

  mmapid_t mid;
  if (! list_empty(&curr->mmap_list)) {
    mid = list_entry(list_back(&curr->mmap_list), struct mmap_desc, elem)->id + 1;
  }
  else mid = 1;

  struct mmap_desc *mmap_d = (struct mmap_desc*) malloc(sizeof(struct mmap_desc));
  mmap_d->id = mid;
  mmap_d->file = f;
  mmap_d->addr = upage;
  mmap_d->size = file_size;
  list_push_back (&curr->mmap_list, &mmap_d->elem);

  lock_release (&filesys_lock);
  return mid;

MMAP_FAIL:
  lock_release (&filesys_lock);
  return -1;
}

bool sys_munmap(mmapid_t mid)
{
  struct thread *curr = thread_current();
  struct mmap_desc *mmap_d = find_mmap_desc(curr, mid);

  if(mmap_d == NULL) {
    return false;
  }

  lock_acquire (&filesys_lock);
  {
    size_t offset, file_size = mmap_d->size;
    for(offset = 0; offset < file_size; offset += PGSIZE) {
      void *addr = mmap_d->addr + offset;
      vm_spt_mm_unmap (curr->spt, curr->pagedir, addr, mmap_d->file, offset, mmap_d->size);
    }

    list_remove(& mmap_d->elem);
    file_close(mmap_d->file);
    free(mmap_d);
  }
  lock_release (&filesys_lock);

  return true;
}
#endif

/*
 * Moves the file pointer of the file descriptor to a specified position.
 */
void seek(int fd, unsigned position) {
  // 1. Acquire the file system lock for thread-safe access
  lock_acquire(&filesys_lock);

  // 2. Retrieve the file descriptor structure associated with fd
  struct file_descriptor* file_d = get_open_file(fd);

  // 3. If the file is valid, move the file pointer
  if(file_d && file_d->file_struct)
    file_seek(file_d->file_struct, position);  // Update the file's current position

  // 4. Release the lock
  lock_release(&filesys_lock);
}

/*
 * Returns the current file pointer position for the given file descriptor.
 * Returns 0 if the file is invalid.
 */
unsigned tell(int fd) {
  unsigned result = 0;  // Default return value if file is invalid

  // 1. Acquire file system lock
  lock_acquire(&filesys_lock);

  // 2. Get the file descriptor structure for fd
  struct file_descriptor* file_d = get_open_file(fd);

  // 3. If the file is valid, retrieve current file position
  if(file_d && file_d->file_struct)
    return file_tell(file_d->file_struct);  // Return without releasing lock (intentional in PintOS)

  // 4. Release lock if file was invalid
  lock_release(&filesys_lock);

  return result;  // Return default value (0)
}

/*
 * Closes the open file associated with the given file descriptor.
 * Removes the file descriptor from the thread’s list and releases resources.
 */
void close(int fd) {
  // 1. Acquire file system lock
  lock_acquire(&filesys_lock);

  // 2. Close and clean up the open file descriptor
  close_open_file(fd);

  // 3. Release the lock after cleanup
  lock_release(&filesys_lock);
}


/****************** Helper Functions on Memory Access ********************/

/*
 * Safely reads a byte from the user virtual address `uaddr`.
 * Returns the byte value (0–255) if successful, or -1 if the address is invalid.
 */
static int32_t get_user (const uint8_t *uaddr) {
  // Check if the user address is below PHYS_BASE (i.e., in user space)
  if (! ((void*)uaddr < PHYS_BASE)) {
    return -1;  // Address is outside user space → invalid access
  }

  int result;

  // Inline assembly to safely read from user memory
  // If memory access fails, jump to label `1` and return value is unchanged
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result)   // Output: result in register EAX
       : "m" (*uaddr));   // Input: memory at user address

  return result;  // Return the loaded byte value or error
}
  
/*
 * Checks whether a given user pointer is valid.
 * Returns true if the pointer is non-null, in user address space,
 * and mapped to a valid physical page.
 */
bool is_valid_ptr(const void *usr_ptr)
{
  struct thread *cur = thread_current();  // Get current thread

  // 1. Check for NULL pointer
  if (usr_ptr == NULL)
    return false;

  // 2. Check if the address is within user virtual address space
  if (!is_user_vaddr(usr_ptr))
    return false;

  // 3. Check if the virtual address is mapped to a physical page
  if (pagedir_get_page(cur->pagedir, usr_ptr) == NULL)
    return false;

  return true;  // All checks passed
}

/*
 * Retrieves the open file descriptor structure for a given file descriptor number.
 * Returns NULL if the descriptor is not found or refers to stdin/stdout/stderr.
 */
static struct file_descriptor* get_open_file(int fd_num)
{
  struct thread *t = thread_current();  // Get current thread
  ASSERT(t != NULL);                    // Sanity check

  // Standard input/output/error are not managed with file_descriptor
  if (fd_num < 3) {
    return NULL;
  }

  // Search the thread's file_descriptors list
  struct list_elem *e;
  for (e = list_begin(&t->file_descriptors);
       e != list_end(&t->file_descriptors);
       e = list_next(e))
  {
    struct file_descriptor *desc = list_entry(e, struct file_descriptor, elem); // Get current descriptor
    if (desc->fd_num == fd_num) {
      return desc;  // Match found
    }
  }

  return NULL;  // Not found
}

/*
 * Allocates and returns the next available file descriptor number
 * for the current thread.
 */
int allocate_fd(void) 
{
  struct thread *cur = thread_current();  // Get current thread
  return cur->next_fd++;                  // Return and increment next available fd
}

/*
 * Closes and deallocates the file descriptor with the given number.
 * Also removes it from the current thread's file descriptor list.
 */
void close_open_file(int fd_num) 
{
  struct list *fd_list = &thread_current()->file_descriptors;  // Get current thread's fd list
  struct list_elem *e;

  // Iterate through the list of open file descriptors
  for (e = list_begin(fd_list); e != list_end(fd_list); e = list_next(e)) {
    struct file_descriptor *desc = list_entry(e, struct file_descriptor, elem);  // Access file descriptor
    if (desc->fd_num == fd_num) {
      file_close(desc->file_struct);   // Close the associated file
      list_remove(e);                  // Remove the descriptor from the list
      palloc_free_page(desc);         // Free the memory used for descriptor
      return;
    }
  }
}

#ifdef VM
static struct mmap_desc*
find_mmap_desc(struct thread *t, mmapid_t mid)
{
  ASSERT (t != NULL);

  struct list_elem *e;

  if (! list_empty(&t->mmap_list)) {
    for(e = list_begin(&t->mmap_list);
        e != list_end(&t->mmap_list); e = list_next(e))
    {
      struct mmap_desc *desc = list_entry(e, struct mmap_desc, elem);
      if(desc->id == mid) {
        return desc;
      }
    }
  }

  return NULL; // not found
}

void preload_and_pin_pages(const void *buffer, size_t size)
{
  struct supplemental_page_table *spt = thread_current()->spt;
  uint32_t *pagedir = thread_current()->pagedir;

  void *upage;
  for(upage = pg_round_down(buffer); upage < buffer + size; upage += PGSIZE)
  {
    vm_load_page (spt, pagedir, upage);
    vm_pin_page (spt, upage);
  }
}

void unpin_preloaded_pages(const void *buffer, size_t size)
{
  struct supplemental_page_table *spt = thread_current()->spt;

  void *upage;
  for(upage = pg_round_down(buffer); upage < buffer + size; upage += PGSIZE)
  {
    vm_unpin_page (spt, upage);
  }
}
#endif