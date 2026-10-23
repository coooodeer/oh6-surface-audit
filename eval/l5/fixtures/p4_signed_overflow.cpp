#include <climits>

int main(int argc, char **) {
    int x = INT_MAX;
    x += argc;
    return x == 0 ? 1 : 0;
}
