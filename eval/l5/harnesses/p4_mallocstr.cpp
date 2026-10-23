#include <cstdint>
#include <cstdlib>

static char *MallocStr(uint32_t len)
{
    char *str = (char *)malloc(sizeof(char) * (len + 1));
    if (str != NULL) {
        str[len] = '\0';
    }
    return str;
}

int main()
{
    char *p = MallocStr(4294967295u);
    free(p);
    return 0;
}
