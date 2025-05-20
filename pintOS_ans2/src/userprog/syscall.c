#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "list.h"
#include "process.h"

#define VALIDATE_PTR(ptr)  \
if (!is_valid_ptr(ptr)) exit(-1);

static void syscall_handler (struct intr_frame *);
bool is_valid_ptr(const void*);
struct file_descriptor *get_open_file(int fd);

void acquire_filesys_lock(void);
void release_filesys_lock(void);

void halt(void);
void exit(int status);
int exec(char *file_name);
int wait(tid_t tid);
bool create(const char *file_name, unsigned initial_size);
bool remove(const char *file_name);
int open(const char *file_name);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);

struct lock fs_lock;
struct list open_files;

extern bool running;

struct file_descriptor {
	int fd_num;
	tid_t owner;
	struct file* file_struct;
	struct list_elem elem;
};

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&fs_lock);
  list_init(&open_files);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	int * p = f->esp;
	VALIDATE_PTR(p);
	int system_call = * p;
	
	switch (system_call)
	{
		case SYS_HALT:
		halt();
		break;

		case SYS_EXIT:
		VALIDATE_PTR(p+1);
		exit(*(p+1));
		break;

		case SYS_EXEC:
		VALIDATE_PTR(p+1);
		VALIDATE_PTR(*(p+1));
		f->eax = exec(*(p+1));
		break;

		case SYS_WAIT:
		VALIDATE_PTR(p+1);
		tid_t tid = *(p + 1);
		f->eax = wait(tid);
		break;

		case SYS_CREATE:
		VALIDATE_PTR(p+5);
		VALIDATE_PTR(*(p+4));
		f->eax = create(*(p+4), *(p+5));
		break;

		case SYS_REMOVE:
		VALIDATE_PTR(p+1);
		VALIDATE_PTR(*(p+1));
		f->eax = remove(*(p+1));
		break;

		case SYS_OPEN:
		VALIDATE_PTR(p+1);
		VALIDATE_PTR(*(p+1));
		f->eax = open(*(p + 1));
		break;

		case SYS_FILESIZE:
		VALIDATE_PTR(p+1);
		f->eax = filesize(*(p+1));
		break;

		case SYS_READ:
		VALIDATE_PTR(p+7);
		VALIDATE_PTR(*(p+6));
		f->eax = read(*(p+5), *(p+6), *(p+7));
		break;

		case SYS_WRITE:
		VALIDATE_PTR(p+7);
		VALIDATE_PTR(*(p+6));

		int fd = *(p+5);
		const void *buffer = *(p+6);
		unsigned size = *(p+7);
	
		f->eax = write(fd, buffer, size);
		break;

		case SYS_SEEK:
		VALIDATE_PTR(p+5);
		seek(*(p+4), *(p+5));
		break;
		
		case SYS_TELL:
		VALIDATE_PTR(p+1);
		f->eax = tell(*(p+1));
		break;
		
		case SYS_CLOSE:
		VALIDATE_PTR(p+1);
		close(*(p+1));
		break;
		
		
		default:
		printf("Default %d\n",*p);
	}
}

void
halt(void)
{
	shutdown_power_off();
}

void
exit(int status)
{
	//printf("Exit : %s %d %d\n",thread_current()->name, thread_current()->tid, status);
	struct list_elem *e;
	
	for (e = list_begin (&thread_current()->parent->child_proc); e != list_end (&thread_current()->parent->child_proc);
	e = list_next (e))
	{
		struct child *f = list_entry (e, struct child, elem);
		if(f->tid == thread_current()->tid)
		{
			f->has_been_waited = true;
			f->exit_error = status;
		}
	}
	
	
	thread_current()->exit_error = status;
	
	if(thread_current()->parent->waitingon == thread_current()->tid)
	sema_up(&thread_current()->parent->child_lock);
	
	thread_exit();
}

int
exec(char *file_name)
{
	acquire_filesys_lock();
	char * fn_cp = malloc (strlen(file_name)+1);
	strlcpy(fn_cp, file_name, strlen(file_name)+1);
	
	char * save_ptr;
	fn_cp = strtok_r(fn_cp," ",&save_ptr);
	
	struct file* f = filesys_open (fn_cp);
	
	if(f==NULL)
	{
		release_filesys_lock();
		return -1;
	}
	else
	{
		file_close(f);
		release_filesys_lock();
		return process_execute(file_name);
	}
}

int
wait(tid_t tid)
{
	return process_wait(tid);
}

bool
create(const char *file_name, unsigned initial_size)
{
	if (!is_valid_ptr(file_name)) {
		exit(-1);
	}

	acquire_filesys_lock();
	bool success = filesys_create(file_name, initial_size);
	release_filesys_lock();

	return success;
}

bool
remove(const char *file_name)
{
	if (!is_valid_ptr(file_name)) {
		exit(-1);
	}
  
	acquire_filesys_lock();
	bool success = filesys_remove(file_name);
	release_filesys_lock();
  
	return success;
}

static int
allocate_fd(void)
{
	return thread_current()->fd_count++;
}

int
open(const char *file_name)
{
    if (!is_valid_ptr(file_name)) {
        exit(-1);
    }

    acquire_filesys_lock();
    struct file* fptr = filesys_open(file_name);
    release_filesys_lock();

    if (fptr == NULL)
        return -1;

    struct file_descriptor *pfile = malloc(sizeof(*pfile));
    if (!pfile)
        return -1;

    pfile->file_struct = fptr;
    pfile->fd_num = allocate_fd();
    pfile->owner = thread_current()->tid;
    list_push_back(&thread_current()->files, &pfile->elem);

    return pfile->fd_num;
}

int
filesize(int fd)
{
	struct file_descriptor *fdesc = get_open_file(fd);
	if (fdesc == NULL) {
		return -1;
	}
  
	acquire_filesys_lock();
	int size = file_length(fdesc->file_struct);
	release_filesys_lock();
	
	return size;
}

int
read(int fd, void *buffer, unsigned size)
{
	if (!is_valid_ptr(buffer)) {
		exit(-1);
	}
  
	if (fd == 0) {  // STDIN
		uint8_t *buf = buffer;
		unsigned i;
		for (i = 0; i < size; i++) {
		buf[i] = input_getc();
		}
		return size;
	}
  
	struct file_descriptor *fdesc = get_open_file(fd);
	if (fdesc == NULL) {
		return -1;
	}
  
	acquire_filesys_lock();
	int bytes_read = file_read(fdesc->file_struct, buffer, size);
	release_filesys_lock();
  
	return bytes_read;
}

int
write (int fd, const void *buffer, unsigned size) 
{
	int status = -1;

	if (!is_valid_ptr(buffer)) {
		exit(-1);
	}

	acquire_filesys_lock();

	if (fd == STDIN_FILENO) {
		lock_release(&fs_lock);
		return -1;
	}

	if (fd == STDOUT_FILENO) {
		putbuf(buffer, size);
		status = size;
	} else {
		struct file_descriptor *fd_struct = get_open_file(fd);
		if (fd_struct != NULL) {
			status = file_write(fd_struct->file_struct, buffer, size);
		} else {
			status = -1;
		}
	}

	release_filesys_lock();
	return status;
}

void
seek(int fd, unsigned position)
{
	struct file_descriptor *fdesc = get_open_file(fd);
	if (fdesc == NULL) {
		return;
	}

	acquire_filesys_lock();
	file_seek(fdesc->file_struct, position);
	release_filesys_lock();
}

unsigned
tell(int fd)
{
	struct file_descriptor *fdesc = get_open_file(fd);
	if (fdesc == NULL) {
		return -1;
	}

	acquire_filesys_lock();
	unsigned pos = file_tell(fdesc->file_struct);
	release_filesys_lock();

	return pos;
}

void
close_open_file(int fd)
{
	struct list_elem *e;
	for (e = list_begin(&thread_current()->files); e != list_end(&thread_current()->files); e = list_next(e)) {
		struct file_descriptor *fd_struct = list_entry(e, struct file_descriptor, elem);
		if (fd_struct->fd_num == fd) {
			list_remove(e);
			file_close(fd_struct->file_struct);
			free(fd_struct);
			return;
		}
	}
}

void
close(int fd)
{
    acquire_filesys_lock();
    struct file_descriptor *fd_struct = get_open_file(fd);
    if (fd_struct != NULL && fd_struct->owner == thread_current()->tid) {
        close_open_file(fd);
    }
    release_filesys_lock();
}

void
close_all_files(struct list* files)
{
	struct list_elem *e;
	while(!list_empty(files))
	{
		e = list_pop_front(files);

		struct file_descriptor *f = list_entry (e, struct file_descriptor, elem);
		file_close(f->file_struct);
		list_remove(e);
		free(f);
	}
}

bool
is_valid_ptr(const void *usr_ptr)
{
	if (!is_user_vaddr(usr_ptr))
	{
		return false;
	}
	void *ptr = pagedir_get_page(thread_current()->pagedir, usr_ptr);
	if (!ptr)
	{
		return false;
	}
	return true;
}

struct file_descriptor *
get_open_file(int fd)
{
    struct list_elem *e;
    struct list *files = &thread_current()->files;

    for (e = list_begin(files); e != list_end(files); e = list_next(e)) {
        struct file_descriptor *fd_struct = list_entry(e, struct file_descriptor, elem);

        if (fd_struct->fd_num == fd) {
            return fd_struct;
        }
    }

    return NULL;
}

void
acquire_filesys_lock(void)
{
    lock_acquire(&fs_lock);
}

void
release_filesys_lock(void)
{
    lock_release(&fs_lock);
}
