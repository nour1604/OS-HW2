#include <linux/kernel.h>
#include <linux/sched.h>
#include "hw2_test.h"

long set_sec(int sword, int midnight, int clamp) {
    // Check for root privileges
    if (current->cred->euid != 0) {
        return -EPERM;  // Operation not permitted if not root
    }


    // Validate arguments: Ensure they are non-negative
    if (sword < 0 || midnight < 0 || clamp < 0) {
        return -EINVAL;  // Invalid argument
    }

    // Normalize arguments: Treat values greater than 1 as 1
    sword = sword ? 1 : 0;
    midnight = midnight ? 1 : 0;
    clamp = clamp ? 1 : 0;

    // Set clearance for the current process
    current->clearance = (sword & 1) | ((midnight & 1) << 1) | ((clamp & 1) << 2);

    return 0;  // Success
}

long get_sec(char clr) {
    // Validate the input clearance character
    if (clr != 's' && clr != 'm' && clr != 'c') {
        printf("Invalid clearance character: %c\n", clr);
        return -EINVAL;  // Invalid clearance character
    }

    // Check the clearance based on the character
    switch (clr) {
        case 's':  // Sword clearance
            return (current->clearance & 1) ? 1 : 0;

        case 'm':  // Midnight clearance
            return (current->clearance & (1 << 1)) ? 1 : 0;

        case 'c':  // Clamp clearance
            return (current->clearance & (1 << 2)) ? 1 : 0;

        default:
            return -EINVAL;  // Should not reach here
    }
}


long check_sec(pid_t pid, char clr) {
    struct task_struct *target_task;
    int required_bit;

    // Validate the clearance character
    if (clr != 's' && clr != 'm' && clr != 'c') {
        return -EINVAL;  // Invalid clearance character
    }

    // Check if the calling process has the requested clearance
    switch (clr) {
        case 's':
            required_bit = 1;  // Bit 0 for Sword
            break;
        case 'm':
            required_bit = 1 << 1;  // Bit 1 for Midnight
            break;
        case 'c':
            required_bit = 1 << 2;  // Bit 2 for Clamp
            break;
    }

    if (!(current->clearance & required_bit)) {
        return -EPERM;  // Calling process does not have the clearance
    }

    // Find the task_struct for the target process by PID
    target_task = pid_task(find_vpid(pid), PIDTYPE_PID);

    if (!target_task) {
        return -ESRCH;  // No such process
    }

    // Check the target process's clearance
    if (target_task.clearance & required_bit) {
        return 1;  // Target process has the clearance
    } else {
        return 0;  // Target process does not have the clearance
    }
}


long set_sec_branch(int height, char clr) {
    struct task_struct *parent_task = current->parent;
    int required_bit;
    int updated_count = 0;

    // Validate input arguments
    if (height <= 0 || (clr != 's' && clr != 'm' && clr != 'c')) {
        return -EINVAL;  // Invalid argument
    }

    // Determine the clearance bit based on the `clr` argument
    switch (clr) {
        case 's':
            required_bit = 1;  // Bit 0 for Sword
            break;
        case 'm':
            required_bit = 1 << 1;  // Bit 1 for Midnight
            break;
        case 'c':
            required_bit = 1 << 2;  // Bit 2 for Clamp
            break;
        default:
            return -EINVAL;  // Redundant check for safety
    }

    // Ensure the calling process has the clearance to set
    if (!(current->clearance & required_bit)) {
        return -EPERM;  // Calling process lacks the required clearance
    }

    // Traverse up the parent hierarchy up to `height`
    rcu_read_lock();
    while (parent_task != NULL && height > 0) {
        // Update the parent's clearance if the bit is not already set
        if (!(parent_task->clearance & required_bit)) {
            parent_task->clearance |= required_bit;
            updated_count++;
        }
        // Move to the next parent
        parent_task = parent_task->parent;
        height--;
    }
    rcu_read_unlock();

    return updated_count;  // Return the number of parents updated
}