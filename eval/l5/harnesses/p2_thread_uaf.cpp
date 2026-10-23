#include <chrono>
#include <memory>
#include <thread>

struct Callback {
    int (*fn)(int);
};

using CallbackPtr = std::shared_ptr<Callback>;

static int Invoke(CallbackPtr cb)
{
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    return cb->fn(1);
}

static int OnResult(int v)
{
    return v + 1;
}

int main()
{
    CallbackPtr cb = std::make_shared<Callback>(Callback{OnResult});
    std::thread waitThread([callback = cb]() { (void)Invoke(callback); });
    waitThread.detach();
    cb.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    return 0;
}
