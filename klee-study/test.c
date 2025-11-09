#include <klee/klee.h>
#include <stdio.h>

int main() {
    int x;
    klee_make_symbolic(&x, sizeof(x), "x");

    if (x > 5)
        printf("x > 5\n");
    else
        printf("x <= 5\n");

    return 0;
}
