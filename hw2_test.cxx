#include "hw2_test.h"

long set_sec(int sword, int midnight, int clamp) {
    long r = syscall(334, sword, midnight, clamp);
    return r;
}

long get_sec(char clr) {
    long r = syscall(335, clr);
    return r;
}

long check_sec(pid_t pid, char clr) {
	long r = syscall(336, pid, clr);
    return r;
}

long set_sec_branch(int height, char clr) {
	long r = syscall(337, height, clr);
    return r;
}
