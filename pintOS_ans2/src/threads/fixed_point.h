//modified by me
#ifndef FIXED_POINT_H
#define FIXED_POINT_H


#define F (1 << 14)  




int fp_to_int_zero(int x);        
int fp_to_int_nearest(int x);    
int int_to_fp(int n);


int fp_add(int x, int y);
int fp_sub(int x, int y);
int fp_add_int(int x, int n);
int fp_sub_int(int x, int n);


int fp_mul(int x, int y);
int fp_mul_int(int x, int n);
int fp_div(int x, int y);
int fp_div_int(int x, int n);


#endif
