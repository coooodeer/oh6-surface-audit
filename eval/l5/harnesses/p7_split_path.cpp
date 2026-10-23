#include <string>
#include <vector>

static std::vector<std::string> SplitPath(const std::string &path)
{
    std::vector<std::string> segments;
    int start = 0;
    for (size_t i = 0; i < path.size(); i++) {
        if (path[i] == '/') {
            if (i > start) {
                segments.push_back(path.substr(start, i - start));
            }
            start = i + 1;
        }
    }
    if (start < path.size()) {
        segments.push_back(path.substr(start));
    }
    return segments;
}

int main()
{
    std::string path(1000000, 'a');
    volatile size_t total = 0;
    for (int k = 0; k < 20000; k++) {
        auto segments = SplitPath(path);
        total += segments.size();
    }
    return total == 0 ? 1 : 0;
}
