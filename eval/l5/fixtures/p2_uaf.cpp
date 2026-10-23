#include <cstdlib>

int main(int argc, char **) {
    int *p = static_cast<int *>(std::malloc(sizeof(int)));
    *p = 1;
    std::free(p);
    volatile int *vp = p;
    int x = *vp;
    return x == argc ? 2 : 0;
}
