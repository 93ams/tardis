// A C++ program that knows nothing of TARDIS: the standard library's
// threads, locks, clocks, streams, random device and exceptions, over
// libc++ and libc. `test/cpp.zig` runs it under system-call mode.

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <mutex>
#include <random>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <fcntl.h>
#include <unistd.h>

extern "C" {

// Four threads add to a counter under a mutex, and a fifth waits on a
// condition variable for them to finish.
int cpp_threads() {
    std::mutex m;
    std::condition_variable done;
    long total = 0;
    int finished = 0;
    std::vector<std::thread> workers;
    for (int id = 0; id < 4; id++) {
        workers.emplace_back([&, id] {
            for (int i = 0; i < 50; i++) {
                std::lock_guard<std::mutex> hold(m);
                total += id + 1;
            }
            std::lock_guard<std::mutex> hold(m);
            finished++;
            done.notify_all();
        });
    }
    {
        std::unique_lock<std::mutex> hold(m);
        done.wait(hold, [&] { return finished == 4; });
    }
    for (auto &w : workers) w.join();
    return total == 50 * (1 + 2 + 3 + 4) ? 0 : 1;
}

// An hour's sleep, then a wait that times out after 250 ms: the
// milliseconds the steady clock says went by.
int64_t cpp_time() {
    using namespace std::chrono;
    const auto start = steady_clock::now();
    std::this_thread::sleep_for(hours(1));
    std::mutex m;
    std::condition_variable never;
    std::unique_lock<std::mutex> hold(m);
    if (never.wait_for(hold, milliseconds(250)) != std::cv_status::timeout) return -1;
    return duration_cast<milliseconds>(steady_clock::now() - start).count();
}

// The wall clock, in milliseconds since the epoch.
int64_t cpp_wall_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

// An exception thrown in a thread and caught there, and one thrown
// through two frames on the calling thread.
static int thrower(int depth) {
    if (depth == 0) throw std::runtime_error("down");
    std::string keep(64, 'x');
    return thrower(depth - 1) + static_cast<int>(keep.size());
}

int cpp_exceptions() {
    std::atomic<int> caught{0};
    std::thread t([&] {
        try {
            thrower(3);
        } catch (const std::runtime_error &e) {
            if (std::string(e.what()) == "down") caught++;
        }
    });
    t.join();
    try {
        thrower(2);
    } catch (const std::exception &) {
        caught++;
    }
    return caught == 2 ? 0 : 1;
}

// A file written through a stream, read back through another, then
// written again by descriptor, synced, renamed, and its directory synced.
int cpp_files() {
    {
        std::ofstream out("stream.txt");
        if (!out) return 1;
        out << "line one\n" << 42 << "\n";
        out.flush();
        if (!out) return 2;
    }
    {
        std::ifstream in("stream.txt");
        std::string first;
        int number = 0;
        if (!std::getline(in, first) || !(in >> number)) return 3;
        if (first != "line one" || number != 42) return 4;
    }
    const int fd = open("kept.tmp", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd < 0) return 5;
    const char text[] = "durable";
    size_t done = 0;
    while (done < sizeof(text) - 1) {
        const ssize_t n = write(fd, text + done, sizeof(text) - 1 - done);
        if (n <= 0) return 6;
        done += static_cast<size_t>(n);
    }
    if (fsync(fd) != 0) return 7;
    close(fd);
    if (std::rename("kept.tmp", "kept.txt") != 0) return 8;
    const int dir = open(".", O_RDONLY | O_DIRECTORY);
    if (dir < 0) return 9;
    if (fsync(dir) != 0) return 10;
    close(dir);
    return 0;
}

// After a power loss: the renamed file is there, whole.
int cpp_files_kept() {
    std::ifstream in("kept.txt");
    std::string text;
    if (!std::getline(in, text)) return 1;
    return text == "durable" ? 0 : 2;
}

// What the random device gives: the run's, so it follows the seed.
uint32_t cpp_random() {
    std::random_device device;
    return device();
}

// How many processors the program is told of, asked three ways: the C++
// library's, those online and those configured. Each in two decimal
// digits of the result.
int cpp_processors() {
    const long hardware = std::thread::hardware_concurrency();
    const long online = sysconf(_SC_NPROCESSORS_ONLN);
    const long configured = sysconf(_SC_NPROCESSORS_CONF);
    if (hardware < 0 || hardware > 99 || online < 0 || online > 99 || configured < 0 || configured > 99) return -1;
    return static_cast<int>(hardware * 10000 + online * 100 + configured);
}

}
