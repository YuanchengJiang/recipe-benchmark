#include <stdio.h>

class A { public: virtual void f() = 0; };
class B { public: virtual void f() = 0; };
class C { public: virtual int f() = 0; };
class A1: public A {public:void f(){puts("A1-VCALL");}};
class A2: public A {public: virtual void f() = 0;};
class A11: public A1 {public: virtual void f() = 0;};
class B1: public B {public: virtual void f() = 0;};
class C1: public C {public: virtual int f() = 0;};