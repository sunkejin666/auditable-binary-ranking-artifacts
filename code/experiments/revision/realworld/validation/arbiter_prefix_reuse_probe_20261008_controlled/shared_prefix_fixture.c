#include <stdint.h>
__attribute__((noinline)) int target_sink(int arg) { return arg + 1; }
__attribute__((noinline)) int shared_prefix(int arg) {
    int x = arg + 10;
    int a = target_sink(x);
    int b = target_sink(x + 1);
    int c = target_sink(x + 2);
    return a + b + c;
}
__attribute__((noinline)) int driver(int arg) { return shared_prefix(arg); }
int main(int argc, char **argv) { return driver(argc); }
