#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/synch.h"

/* States in a thread's life cycle. */
enum thread_status
  {
    THREAD_RUNNING,     /* Running thread. */
    THREAD_READY,       /* Not running but ready to run. */
    THREAD_BLOCKED,     /* Waiting for an event to trigger. */
    THREAD_DYING        /* About to be destroyed. */
  };

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */
/* Maximum number of file descriptors per process. */
#define FD_MAX 128
/* A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */
struct thread
  {
    /* Owned by thread.c. */
    tid_t tid;                          /* Thread identifier. */
    enum thread_status status;          /* Thread state. */
    char name[16];                      /* Name (for debugging purposes). */
    uint8_t *stack;                     /* Saved stack pointer. */
    int priority;                       /* Priority. */
    int original_priority;              /* Priority, before donation */
    struct list_elem allelem;           /* List element for all threads list. */
    struct list_elem waitelem;          /* List element, stored in the wait_list queue */
    int64_t sleep_endtick;              /* The tick after which the thread should awake (if the thread is in sleep) */

    /* Shared between thread.c and synch.c. */
    struct list_elem elem;              /* List element, stored in the ready_list queue */

    // needed for priority donations
    struct lock *waiting_lock;          /* The lock object on which this thread is waiting (or NULL if not locked) */
    struct list locks;                  /* List of locks the thread holds (for multiple donations) */

#ifdef USERPROG
    /* Owned by userprog/process.c. */
    uint32_t *pagedir;                  /* Page directory. */
    struct list file_descriptors;       /* List of file_descriptors the thread contains */
    struct file *executing_file;        /* The executable file of associated process. */
    int next_fd;

    /* Process hierarchy support */
    tid_t parent_id;                   /* Parent thread id */
    int child_load_status;             /* -1: load failed, 0: not yet loaded, 1: load success */
    
    struct lock lock_child;            /* Lock for child-related sync */
    struct condition cond_child;       /* Condition variable for child loading and waiting */
    
    struct list children;              /* List of child processes (struct child_status) */
    
    struct file *exec_file;            /* The executable file (can be same as executing_file or used differently) */

    int exit_status;  // Used to store process's exit status for process_exit
#endif

    /* Owned by thread.c. */
    unsigned magic;                     /* Detects stack overflow. */
    struct file *fd_table[FD_MAX];
  };

#ifdef USERPROG
/* Child status structure for process_wait/exit. */
struct child_status
{
  tid_t tid;                       /* Child TID */
  int exit_status;                 /* Exit status of the child */
  bool exited;                     /* Whether the child has exited */
  bool has_been_waited;            /* Whether parent has already waited */
  struct list_elem elem;           /* Element for parent's children list */
};

// Optional helper function to find thread by tid.
struct thread *get_thread_by_id(tid_t tid);

// Request a context switch after returning from the current function or interrupt
void thread_yield_on_return(void);
#endif

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (int64_t tick);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

void thread_sleep_until (int64_t wake_tick);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

/* Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func (struct thread *t, void *aux);
void thread_foreach (thread_action_func *, void *);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

#endif /* threads/thread.h */
