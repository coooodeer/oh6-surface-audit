#include <cstddef>
#include <cstdint>
#include <vector>

struct FakeParcel {
    std::vector<int> data{1};
    size_t idx = 0;

    int *ReadParcelable()
    {
        if (idx >= data.size()) {
            return nullptr;
        }
        return new int(data[idx++]);
    }
};

int main()
{
    int32_t infoSize = 2;
    FakeParcel reply;
    std::vector<int> out;
    for (int32_t i = 0; i < infoSize; i++) {
        int *info = reply.ReadParcelable();
        if (info == nullptr) {
            return 0;
        }
        out.push_back(*info);
        delete info;
    }
    return static_cast<int>(out.size());
}
