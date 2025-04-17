#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* alarm clock - List of sleeping threads that are blocked until a specific tick. */ 
static struct list sleep_list;

/* MLFQ - Type alias for fixed-point arithmetic used in MLFQ scheduling.*/
typedef int fixed_point_t;
/* MLFQ - System load average, updated every second as part of MLFQ. */
static fixed_point_t load_avg;

/* List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

/* Idle thread. */
/* MLFQ - Pointer to the idle thread (now non-static for external access). */
struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame 
  {
    void *eip;                  /* Return address. */
    thread_func *function;      /* Function to call. */
    void *aux;                  /* Auxiliary data for function. */
  };

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *running_thread (void);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static bool is_thread (struct thread *) UNUSED;
static void *alloc_frame (struct thread *, size_t size);
static void schedule (void);
void thread_schedule_tail (struct thread *prev);
static tid_t allocate_tid (void);

/* MLFQ - Fixed-point conversion functions */
int int_to_fp (int); // Convert int to fixed-point
int fp_to_int_zero (int); // Convert fixed-point to int (truncate)
int fp_to_int_nearest (int); // Convert fixed-point to int (round)
/* MLFQ - Fixed-point arithmetic operations */
int add_fp (int, int); // Add two fixed-point numbers
int sub_fp (int, int); // Subtract two fixed-point numbers
int add_mixed (int, int); // Add fixed-point and int
int sub_mixed (int, int); // Subtract int from fixed-point
int mult_fp (int, int); // Multiply two fixed-point numbers
int mult_mixed (int, int); // Multiply fixed-point and int
int div_fp (int, int); // Divide two fixed-point numbers
int div_mixed (int, int); // Divide fixed-point by int

/* MLFQ - Recalculate and update the priority of the given thread based on recent_cpu and nice. */
void mlfqs_update_priority (struct thread *t, void *aux UNUSED);
/* MLFQ - Update the recent_cpu value of the given thread based on load_avg and nice. */
void mlfqs_update_recent_cpu (struct thread *t, void *aux UNUSED);
/* MLFQ - Update recent_cpu for all threads (called once per second). */
void mlfqs_update_recent_cpu_all (void);
/* MLFQ - Recalculate priorities for all threads (called every 4 ticks). */
void mlfqs_update_priority_all (void);
/* MLFQ - Recalculate system load average (called once per second). */
void mlfqs_update_load_avg (void);

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) 
{
  ASSERT (intr_get_level () == INTR_OFF);

  lock_init (&tid_lock);
  list_init (&ready_list);
  list_init (&all_list);
  /* alarm clock - Initialize the list of sleeping threads. */ 
  list_init (&sleep_list);

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread ();
  init_thread (initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid ();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) 
{
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init (&idle_started, 0);
  thread_create ("idle", PRI_MIN, idle, &idle_started);

  /* Start preemptive thread scheduling. */
  intr_enable ();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down (&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) 
{
  struct thread *t = thread_current ();

  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE)
    intr_yield_on_return ();
}

/* Prints thread statistics. */
void
thread_print_stats (void) 
{
  printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
          idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
               thread_func *function, void *aux) 
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;
  enum intr_level old_level;

  ASSERT (function != NULL);

  /* Allocate thread. */
  t = palloc_get_page (PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  init_thread (t, name, priority);
  tid = t->tid = allocate_tid ();

  /* Prepare thread for first run by initializing its stack.
     Do this atomically so intermediate values for the 'stack' 
     member cannot be observed. */
  old_level = intr_disable ();

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame (t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame (t, sizeof *ef);
  ef->eip = (void (*) (void)) kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame (t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;

  intr_set_level (old_level);

  /* Add to run queue. */
  thread_unblock (t);

  /* MLFQ - If using MLFQ, calculate and assign the initial priority for the new thread. */
  if (thread_mlfqs)
    mlfqs_update_priority(t, NULL);

  /* priority scheduling - If the unblocked thread has higher priority than the current thread, yield the CPU to allow preemption. */
  if (t->priority > thread_current ()->priority)
    thread_yield (); // CPU yield (preemptive) if the newly added thread has a higher priority

  return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) 
{
  ASSERT (!intr_context ());
  ASSERT (intr_get_level () == INTR_OFF);

  thread_current ()->status = THREAD_BLOCKED;
  schedule ();
}

/* alarm clock - Comparison function used to sort sleeping threads by wakeup_tick. Returns true if thread a's wakeup_tick is earlier than thread b's. */
static bool
wakeup_tick_less (const struct list_elem *a, const struct list_elem *b, void *aux UNUSED)
{
  struct thread *t1 = list_entry (a, struct thread, elem);
  struct thread *t2 = list_entry (b, struct thread, elem);
  return t1->wakeup_tick < t2->wakeup_tick;
}
 
/* alarm clock - Puts the current thread to sleep until the given wakeup_tick. The thread is added to the sleep_list and will be unblocked later. */
void 
thread_sleep (int64_t wakeup_tick) 
{
  struct thread *cur = thread_current ();
  enum intr_level old_level = intr_disable ();
 
  cur->wakeup_tick = wakeup_tick;
  /* priority scheduling - Insert alignment into sleep_list based on wakeup_tick */
  list_insert_ordered (&sleep_list, &cur->elem, wakeup_tick_less, NULL);
  thread_block ();
 
  intr_set_level (old_level);
}
 
/* alarm clock - Wakes up all threads whose wakeup_tick is less than or equal to current_tick. These threads are removed from the sleep_list and unblocked. */
void 
thread_wakeup (int64_t current_tick) 
{
  struct list_elem *e = list_begin (&sleep_list);
 
  while (e != list_end (&sleep_list)) {
    struct thread *t = list_entry (e, struct thread, elem);
    if (t->wakeup_tick <= current_tick) {
      e = list_remove (e);
      thread_unblock (t);
    } else {
      break;
    }
  }
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) 
{
  enum intr_level old_level;

  ASSERT (is_thread (t));

  old_level = intr_disable ();
  ASSERT (t->status == THREAD_BLOCKED);
  /* MLFQ - Do not add the idle thread to the ready_list. Insert thread into ready_list in order of priority, unless it's the idle thread. */
  if (t != idle_thread)
    /* priority scheduling - Insert the thread into the ready list in descending priority order. */
    list_insert_ordered (&ready_list, &t->elem, thread_priority_cmp, NULL);
  t->status = THREAD_READY;
  intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) 
{
  return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) 
{
  struct thread *t = running_thread ();
  
  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT (is_thread (t));
  ASSERT (t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) 
{
  return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) 
{
  ASSERT (!intr_context ());

#ifdef USERPROG
  process_exit ();
#endif

  /* Remove thread from all threads list, set our status to dying,
     and schedule another process.  That process will destroy us
     when it calls thread_schedule_tail(). */
  intr_disable ();
  list_remove (&thread_current()->allelem);
  thread_current ()->status = THREAD_DYING;
  schedule ();
  NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) 
{
  struct thread *cur = thread_current ();
  enum intr_level old_level;
  
  ASSERT (!intr_context ());

  old_level = intr_disable ();
  if (cur != idle_thread) 
    /* priority scheduling - Yielding thread is re-inserted into the ready list based on its priority. */
    list_insert_ordered (&ready_list, &cur->elem, thread_priority_cmp, NULL);
  cur->status = THREAD_READY;
  schedule ();
  intr_set_level (old_level);
}

/* Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void
thread_foreach (thread_action_func *func, void *aux)
{
  struct list_elem *e;

  ASSERT (intr_get_level () == INTR_OFF);

  for (e = list_begin (&all_list); e != list_end (&all_list);
       e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);
      func (t, aux);
    }
}

/* priority scheduling - Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) 
{
  /* priority scheduling - Update the thread's initial priority and refresh its effective priority, considering any current donations. */
  struct thread *cur = thread_current ();
  cur->init_priority = new_priority;
  refresh_priority ();
 
  /* priority scheduling - If there is a thread in the ready list with higher priority than the current thread, yield the CPU to allow preemption. */
  if (!list_empty (&ready_list)) 
    {
      struct thread *top = list_entry (list_front (&ready_list), 
                                       struct thread, elem);
      if (cur->priority < top->priority)
        {
          thread_yield ();
        }
    }
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) 
{
  return thread_current ()->priority;
}

/* MLFQ - Sets the current thread's nice value and updates its priority. If the thread's new priority is lower than the highest-priority ready thread, it yields the CPU. */
void
thread_set_nice (int nice) 
{
  /* Disable interrupts to safely update scheduling-related values. */
  struct thread *cur = thread_current ();
  enum intr_level old_level = intr_disable ();

  /* Set the thread's nice value. */
  cur->nice = nice;
  /* Recalculate recent_cpu and priority based on the new nice value. */
  mlfqs_update_recent_cpu (cur, NULL);
  mlfqs_update_priority (cur, NULL);

  /* If there's a higher-priority thread in the ready list, yield the CPU. */
  if (!list_empty (&ready_list)) 
    {
      struct thread *top = list_entry (list_front (&ready_list), 
                                       struct thread, elem);
      if (cur->priority < top->priority)
        thread_yield ();
    }

  /* Restore the previous interrupt level. */
  intr_set_level (old_level);
}

/* MLFQ - Returns the current thread's nice value. */
int
thread_get_nice (void) 
{
  return thread_current ()->nice;
}

/* MLFQ - Returns system load average multiplied by 100, rounded to nearest int. */
int
thread_get_load_avg (void) 
{
  return fp_to_int_nearest (load_avg * 100);
}

/* MLFQ - Returns the current thread's recent_cpu multiplied by 100, rounded to nearest int. */
int
thread_get_recent_cpu (void) 
{
  return fp_to_int_nearest (thread_current ()->recent_cpu * 100);
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) 
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current ();
  sema_up (idle_started);

  for (;;) 
    {
      /* Let someone else run. */
      intr_disable ();
      thread_block ();

      /* Re-enable interrupts and wait for the next one.

         The `sti' instruction disables interrupts until the
         completion of the next instruction, so these two
         instructions are executed atomically.  This atomicity is
         important; otherwise, an interrupt could be handled
         between re-enabling interrupts and waiting for the next
         one to occur, wasting as much as one clock tick worth of
         time.

         See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
         7.11.1 "HLT Instruction". */
      asm volatile ("sti; hlt" : : : "memory");
    }
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) 
{
  ASSERT (function != NULL);

  intr_enable ();       /* The scheduler runs with interrupts off. */
  function (aux);       /* Execute the thread function. */
  thread_exit ();       /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread *
running_thread (void) 
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Because `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm ("mov %%esp, %0" : "=g" (esp));
  return pg_round_down (esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool
is_thread (struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority)
{
  ASSERT (t != NULL);
  ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT (name != NULL);

  memset (t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy (t->name, name, sizeof t->name);
  t->stack = (uint8_t *) t + PGSIZE;
  t->priority = priority; // - priority: effective priority (can be donated)
  /* MLFQ scheduling fields */
  /* t->priority is calculated later based on nice and recent_cpu */
  t->nice = 0; // Initialize nice value to 0 (default).
  t->recent_cpu = 0; // Initialize recent_cpu to 0 (default).
  t->init_priority = priority; // init_priority: original base priority (used for donation recovery)
  t->wait_on_lock = NULL; // wait_on_lock: the lock this thread is waiting on (for nested donations)
  list_init (&t->donations); // donations: list of threads that have donated priority to this thread
  t->magic = THREAD_MAGIC;
  list_push_back (&all_list, &t->allelem);
}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *
alloc_frame (struct thread *t, size_t size) 
{
  /* Stack data is always allocated in word-size units. */
  ASSERT (is_thread (t));
  ASSERT (size % sizeof (uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) 
{
  if (list_empty (&ready_list))
    return idle_thread;
  else
    return list_entry (list_pop_front (&ready_list), struct thread, elem);
}

/* Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void
thread_schedule_tail (struct thread *prev)
{
  struct thread *cur = running_thread ();
  
  ASSERT (intr_get_level () == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate ();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread) 
    {
      ASSERT (prev != cur);
      palloc_free_page (prev);
    }
}

/* Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until thread_schedule_tail()
   has completed. */
static void
schedule (void) 
{
  struct thread *cur = running_thread ();
  struct thread *next = next_thread_to_run ();
  struct thread *prev = NULL;

  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (cur->status != THREAD_RUNNING);
  ASSERT (is_thread (next));

  if (cur != next)
    prev = switch_threads (cur, next);
  thread_schedule_tail (prev);
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) 
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire (&tid_lock);
  tid = next_tid++;
  lock_release (&tid_lock);

  return tid;
}

/* priority scheduling - Comparison function used to sort threads by priority in descending order. Returns true if thread a has higher priority than thread b. */
bool 
thread_priority_cmp (const struct list_elem *a, 
                     const struct list_elem *b, 
                     void *aux UNUSED) 
{
  const struct thread *t_a = list_entry (a, struct thread, elem);
  const struct thread *t_b = list_entry (b, struct thread, elem);
  return t_a->priority > t_b->priority;
}

/* priority scheduling - Propagates priority donation through the chain of locks. If a thread is waiting on a lock held by a lower-priority thread, it donates its priority to the holder. This is repeated up to 8 levels deep to prevent infinite donation chains. */
/* Functions that follow the lock that the thread is currently waiting for and donate its priorities */
void 
donate_priority (void) 
{
  struct thread *cur = thread_current (); // current thread
  int depth = 0;
  struct lock *lock = cur->wait_on_lock; // Lock that the current thread is waiting for

  while (lock && depth < 8) // Allow nested donation up to 8 levels
    {
      if (!lock->holder) break; // Suspended if no threads hold a lock

      struct thread *holder = lock->holder;
      if (holder->priority < cur->priority) // Priority donation
        {
          holder->priority = cur->priority; // Move to the next step
        }

      cur = holder;
      lock = holder->wait_on_lock;
      depth++;
    }
}

/* priority scheduling - Restore priorities to initial values and reflect the highest value of donated priorities */
void 
refresh_priority (void) 
{
  struct thread *cur = thread_current (); // current thread
  cur->priority = cur->init_priority; // Restore to Initial Priority

  /* If the donated thread is still waiting for me */
  if (!list_empty (&cur->donations)) 
    {
      struct list_elem *e;
      for (e = list_begin (&cur->donations); 
           e != list_end (&cur->donations); 
           e = list_next (e))
        {
          struct thread *t = list_entry (e, struct thread, donation_elem);
          if (t->wait_on_lock && t->wait_on_lock->holder == cur) 
            {
              if (t->priority > cur->priority)
                cur->priority = t->priority; // Reflects the highest value of donated priorities
            }
        }
    }
}

/* MLFQ */
#define F (1 << 14)

// Converts integer to fixed-point.
int int_to_fp (int n) {
  return n * F;
}

// Converts integer to fixed-point.
int fp_to_int_zero (int x) {
  return x / F;
}

// Converts fixed-point to int (round to nearest).
int fp_to_int_nearest (int x) {
  if (x >= 0)
    return (x + F / 2) / F;
  else
    return (x - F / 2) / F;
}

// Converts fixed-point to int (round to nearest).
int add_fp (int x, int y) {
  return x + y;
}

int sub_fp (int x, int y) {
  return x - y;
}

// Adds/subtracts int to/from fixed-point.
int add_mixed (int x, int n) {
  return x + n * F;
}

int sub_mixed (int x, int n) {
  return x - n * F;
}

// Adds/subtracts int to/from fixed-point.
int mult_fp (int x, int y) {
  return ((int64_t) x) * y / F;
}

// Multiply fixed-point with int
int mult_mixed (int x, int n) {
  return x * n;
}

// Divide two fixed-point
int div_fp (int x, int y) {
  return ((int64_t) x) * F / y;
}

// Divide fixed-point by int
int div_mixed (int x, int n) {
  return x / n;
}

/* MLFQ - Recalculates the priority of thread t based on MLFQ formula: priority = PRI_MAX - (recent_cpu / 4) - (nice * 2). The result is clamped between PRI_MIN and PRI_MAX. */
void
mlfqs_update_priority (struct thread *t, void *aux UNUSED) 
{
  if (t == idle_thread) return; // Skip idle thread
  int new_priority = int_to_fp (PRI_MAX); // Start from PRI_MAX
  new_priority = sub_fp (new_priority, div_mixed (t->recent_cpu, 4)); // Subtract recent_cpu / 4
  new_priority = sub_mixed (new_priority, t->nice * 2); // Subtract nice * 2
  t->priority = fp_to_int_nearest (new_priority); // Convert to int (rounded)

  if (t->priority > PRI_MAX) // Clamp upper bound
    t->priority = PRI_MAX;
  if (t->priority < PRI_MIN) // Clamp upper bound
    t->priority = PRI_MIN;
}

/* MLFQ - Recalculates recent_cpu for thread t using: recent_cpu = (2 * load_avg) / (2 * load_avg + 1) * recent_cpu + nice. */
void
mlfqs_update_recent_cpu (struct thread *t, void *aux UNUSED) 
{
  if (t == idle_thread) return; // Skip idle thread
  /* Calculate coefficient */
  fixed_point_t coef = div_fp (mult_mixed (load_avg, 2), add_mixed (mult_mixed (load_avg, 2), 1));
  /* Apply formula */
  t->recent_cpu = add_mixed (mult_fp (coef, t->recent_cpu), t->nice);
}

/* MLFQ - Updates recent_cpu for all threads using thread_foreach. */
void
mlfqs_update_recent_cpu_all (void) 
{
  ASSERT (intr_get_level () == INTR_OFF); // Must be called with interrupts off
  thread_foreach (mlfqs_update_recent_cpu, NULL); // Apply update to each thread
}

/* MLFQ - Updates priorities for all threads based on their recent_cpu and nice values. */
void
mlfqs_update_priority_all (void) 
{
  ASSERT (intr_get_level () == INTR_OFF); // Must be called with interrupts off
  thread_foreach (mlfqs_update_priority, NULL); // Apply update to each thread
}

/* MLFQ - Updates the system load_avg based on the number of ready threads. Formula: load_avg = (59/60) * load_avg + (1/60) * ready_threads */
void
mlfqs_update_load_avg (void) 
{
  int ready_threads = list_size (&ready_list);
  if (thread_current () != idle_thread)
    ready_threads++; // Include current thread if not idle

  fixed_point_t coeff1 = div_fp (int_to_fp (59), int_to_fp (60));
  fixed_point_t coeff2 = div_fp (int_to_fp (1), int_to_fp (60));

  load_avg = add_fp (
    mult_fp (coeff1, load_avg),
    mult_mixed (coeff2, ready_threads)
  );  
}


/* Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);