#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"

typedef int pid_t;

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

struct file_descriptor {
  int fd_num;                 // File descriptor number
  tid_t owner;                // 소유자
  struct file *file_struct;   // 실제 파일 객체 포인터
  struct list_elem elem;      // 리스트 연결용 엘리먼트
};  

#endif /* userprog/process.h */
