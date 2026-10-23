#include <cstdlib>

int main(int argc, char **) {
    int *a = static_cast<int *>(std::malloc(4 * sizeof(int)));
    a[argc + 7] = 42;
    std::free(a);
    return 0;
}
