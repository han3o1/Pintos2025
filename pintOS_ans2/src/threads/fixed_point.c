//modified by me
#include "threads/fixed_point.h"
#include <stdint.h>


int int_to_fp(int n) { return n * F; }
int fp_to_int_zero(int x) { return x / F; }
int fp_to_int_nearest(int x) { return x >= 0 ? (x + F / 2) / F : (x - F / 2) / F; }


int fp_add(int x, int y) { return x + y; }
int fp_sub(int x, int y) { return x - y; }


int fp_add_int(int x, int n) { return x + n * F; }
int fp_sub_int(int x, int n) { return x - n * F; }


int fp_mul(int x, int y) { return ((int64_t)x) * y / F; }
int fp_mul_int(int x, int n) { return x * n; }


int fp_div(int x, int y) { return ((int64_t)x) * F / y; }
int fp_div_int(int x, int n) { return x / n; }


