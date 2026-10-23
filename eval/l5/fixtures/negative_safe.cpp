int main(int argc, char **) {
    int a[4] = {0, 1, 2, 3};
    a[argc & 1] = 7;
    return a[0];
}
