#include <stdio.h>
#include "allclass.h"

class A1: public A {public:void f(){puts("A1\n");}};

A* create_A1(){
    return new A1;
}