#include <cstdlib>

int main(int, char **) {
    for (;;) {
        void *p = std::malloc(1024 * 1024);
        if (p == nullptr) return 0;
    }
}
