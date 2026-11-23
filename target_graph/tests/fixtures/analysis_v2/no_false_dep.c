/* Deliberately does not use its second argument. */
__attribute__((noinline)) int only_first(int a, int ignored) {
    return a + 1;
}

__attribute__((noinline)) int caller(int x, int y) {
    return only_first(x, y);
}

int main(int argc, char **argv) {
    return caller(argc, argc + 7);
}
