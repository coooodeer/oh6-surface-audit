int main(int argc, char **) {
    int *p = nullptr;
    if (argc > 1) {
        p = new int(argc);
    }
    if (p != nullptr) {
        *p = 7;
    }
    delete p;
    return 0;
}
