#ifndef BASE_H
#define BASE_H
#include <stdio.h>
class A { public: virtual void f() = 0; };
class B { public: virtual void f() = 0; };
class C { public: virtual int f() = 0; };
class A2: public A {public:void f(){puts("A2\n");}};
class B1: public B {public:void f(){puts("B1\n");}};
class C1: public C {public:int f(){puts("C1\n");return 1;}};
#endif // BASE_H