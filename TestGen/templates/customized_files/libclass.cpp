// This is only for cust cpp testcases
#include <stdio.h>
#include "class.h"

int C1::f()
{
	puts("C1-VCALL");
	return 0;
}

void B1::f()
{
	puts("B1-VCALL");
}

void A11::f()
{
	puts("A11-VCALL");
}

void A2::f()
{
	puts("A2-VCALL");
}