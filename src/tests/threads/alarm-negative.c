/* Tests timer_sleep(-100).  Only requirement is that it not crash. */

#include <stdio.h>
#include "tests/threads/tests.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "devices/timer.h"
#include "threads/interrupt.h"  //Added

/* Test for alarm clock */
void test_alarm_clock(void) {
  printf("Test started\n");
  
  /* Sleep for 10 ticks and wake up */
  thread_sleep(10); // 10 틱 동안 잠들게 한다.
  
  /* After 10 ticks, the thread should wake up */
  printf("Woke up after 10 ticks\n");
  thread_yield(); // 기다린 후, 다른 스레드가 실행되도록 양보.
  
  printf("Test finished\n");
}

void run_alarm_clock_test(void) {
  printf("Running alarm clock test...\n");
  test_alarm_clock();
}