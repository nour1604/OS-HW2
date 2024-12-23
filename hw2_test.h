#ifndef test_hw2_H_
#define test_hw2_H_

#include <sys/types.h>
#include <unistd.h>
#include <sys/syscall.h>

// System call wrappers
long set_sec(int sword, int midnight, int clamp);
long get_sec(char clr);
long check_sec(pid_t pid, char clr);
long set_sec_branch(int height, char clr);

#endif // test_hw2_H_
