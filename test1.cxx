#include "hw2_test.h"
#include <stdio.h>
#include <iostream>
#include <cassert>

using namespace std;

int main() {
    long x = get_sec('m');

	cout << "initial 'midnight' clearance: " << x << endl;
	assert(x == 0);
	
    x = set_sec(1,1,0);
	cout << "set_sec returned: " << x;
	if(x == -1) cout << " (did you use sudo?)";
	cout << endl;
	
	assert(x == 0);
    x = get_sec('m');
	cout << "updated 'midnight' clearance: " << x << endl;
	assert(x == 1);
	
	x = set_sec_branch(1000, 's');
	cout << "set_sec_branch returned: " << x << endl;
	assert(x >= 0);
	
	x = check_sec(pid_t(1), 's');
	cout << "init process 'sword' clearance:  " << x << endl;
	assert(x == 1);
	
    cout << "===== SUCCESS =====" << endl;
    return 0;
}

