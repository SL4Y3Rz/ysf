#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <atomic>
#include <mutex>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <thread>
#include <unordered_map>
#include <chrono>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <mach/vm_types.h>
#include <mach/task_info.h>
#include <mach-o/dyld.h>
#include <dlfcn.h>

static constexpr size_t   SNAP_BYTES  = 8;
static constexpr size_t   MAX_ENTRIES = 4096;
static constexpr uint32_t SCAN_MS     = 800;
static constexpr uint32_t WATCH_MS    = 100;
static constexpr uint32_t FREEZE_MS   = 16;

static task_t             g_self_task = MACH_PORT_NULL;
static std::atomic<bool>  g_running   { false };
static std::mutex         g_mutex;

struct MemEntry {
    vm_address_t   addr;
    vm_size_t      region_size;
    uint8_t        snap[SNAP_BYTES];
    bool           writable;
    bool           valid;
    std::string    label;
};

struct WatchEntry {
    vm_address_t addr;
    uint8_t      last[SNAP_BYTES];
    size_t       sz;
    void(*cb)(vm_address_t, uint64_t, uint64_t);
};

struct FreezeEntry {
    vm_address_t      addr;
    uint64_t          val;
    size_t            sz;
    std::atomic<bool> active { true };
};

static std::vector<MemEntry>                     g_entries;
static std::unordered_map<uint64_t, std::string> g_labels;
static std::vector<WatchEntry>                   g_watches;
static std::vector<std::shared_ptr<FreezeEntry>> g_freezes;

static std::string hex_str(const uint8_t* b, size_t n) {
    std::ostringstream o;
    for (size_t i = 0; i < n; ++i)
        o << std::hex << std::uppercase
          << std::setw(2) << std::setfill('0') << (int)b[i]
          << (i + 1 < n ? " " : "");
    return o.str();
}

static uint64_t to_u64(const uint8_t* b, size_t n) {
    uint64_t v = 0;
    memcpy(&v, b, n < 8 ? n : 8);
    return v;
}

static bool self_read(vm_address_t addr, void* dst, size_t sz) {
    vm_size_t out = sz;
    kern_return_t kr = vm_read_overwrite(
        g_self_task, addr, sz,
        reinterpret_cast<vm_address_t>(dst), &out);
    return kr == KERN_SUCCESS && out == sz;
}

static bool self_write(vm_address_t addr, const void* src, size_t sz) {
    kern_return_t kr = vm_protect(
        g_self_task, addr, sz, FALSE,
        VM_PROT_READ | VM_PROT_WRITE);
    if (kr != KERN_SUCCESS) return false;
    kr = vm_write(
        g_self_task, addr,
        reinterpret_cast<vm_offset_t>(src),
        static_cast<mach_msg_type_number_t>(sz));
    vm_protect(g_self_task, addr, sz, FALSE,
               VM_PROT_READ | VM_PROT_EXECUTE);
    return kr == KERN_SUCCESS;
}

static void do_scan() {
    std::vector<MemEntry> fresh;
    vm_address_t          addr = 0;
    vm_size_t             sz   = 0;

    while (fresh.size() < MAX_ENTRIES) {
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t         cnt  = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t                    obj  = MACH_PORT_NULL;

        kern_return_t kr = vm_region_64(
            g_self_task, &addr, &sz,
            VM_REGION_BASIC_INFO_64,
            reinterpret_cast<vm_region_info_t>(&info),
            &cnt, &obj);

        if (kr != KERN_SUCCESS) break;

        if (info.protection & VM_PROT_READ) {
            MemEntry e {};
            e.addr        = addr;
            e.region_size = sz;
            e.writable    = (info.protection & VM_PROT_WRITE) != 0;
            e.valid       = self_read(addr, e.snap, SNAP_BYTES);
            {
                std::lock_guard<std::mutex> lk(g_mutex);
                auto it = g_labels.find(addr);
                if (it != g_labels.end()) e.label = it->second;
            }
            fresh.push_back(e);
        }
        addr += sz;
    }

    std::lock_guard<std::mutex> lk(g_mutex);
    g_entries = std::move(fresh);
}

static void scan_loop() {
    while (g_running.load()) {
        do_scan();
        std::this_thread::sleep_for(std::chrono::milliseconds(SCAN_MS));
    }
}

static void watch_loop() {
    while (g_running.load()) {
        {
            std::lock_guard<std::mutex> lk(g_mutex);
            for (auto& w : g_watches) {
                uint8_t cur[SNAP_BYTES] = {};
                if (!self_read(w.addr, cur, w.sz)) continue;
                uint64_t ov = to_u64(w.last, w.sz);
                uint64_t nv = to_u64(cur, w.sz);
                if (ov != nv) {
                    if (w.cb) w.cb(w.addr, ov, nv);
                    memcpy(w.last, cur, w.sz);
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(WATCH_MS));
    }
}

extern "C" {

void memdebug_start() {
    if (g_running.exchange(true)) return;
    g_self_task = mach_task_self();
    printf("[memdebug] started\n");
    fflush(stdout);
    std::thread(scan_loop).detach();
    std::thread(watch_loop).detach();
}

void memdebug_stop() {
    g_running.store(false);
    printf("[memdebug] stopped\n");
    fflush(stdout);
}

void memdebug_label(vm_address_t addr, const char* lbl) {
    std::lock_guard<std::mutex> lk(g_mutex);
    g_labels[addr] = lbl;
}

bool memdebug_read(vm_address_t addr, void* dst, size_t sz) {
    return self_read(addr, dst, sz);
}

bool memdebug_write(vm_address_t addr, const void* src, size_t sz) {
    return self_write(addr, src, sz);
}

void memdebug_find_value(uint64_t val) {
    printf("[memdebug] scanning for %llu...\n", (unsigned long long)val);
    fflush(stdout);
    std::lock_guard<std::mutex> lk(g_mutex);
    int hits = 0;
    for (auto& e : g_entries) {
        if (!e.writable) continue;
        for (vm_address_t off = 0; off + 8 <= e.region_size; off += 4) {
            uint64_t v = 0;
            if (!self_read(e.addr + off, &v, 8)) break;
            if (v == val) {
                printf("[memdebug] HIT 0x%016lx = %llu\n",
                    (unsigned long)(e.addr + off),
                    (unsigned long long)v);
                fflush(stdout);
                if (++hits >= 256) return;
            }
        }
    }
    printf("[memdebug] done — %d hits\n", hits);
    fflush(stdout);
}

void memdebug_freeze(vm_address_t addr, uint64_t val, size_t sz) {
    auto fe  = std::make_shared<FreezeEntry>();
    fe->addr = addr;
    fe->val  = val;
    fe->sz   = sz;
    {
        std::lock_guard<std::mutex> lk(g_mutex);
        g_freezes.push_back(fe);
    }
    std::thread([fe](){
        while (g_running.load() && fe->active.load()) {
            self_write(fe->addr, &fe->val, fe->sz);
            std::this_thread::sleep_for(
                std::chrono::milliseconds(FREEZE_MS));
        }
    }).detach();
}

void memdebug_dump(size_t n) {
    std::lock_guard<std::mutex> lk(g_mutex);
    size_t lim = n < g_entries.size() ? n : g_entries.size();
    printf("\n══ Dump [%zu regions] ══\n", g_entries.size());
    for (size_t i = 0; i < lim; ++i) {
        auto& e = g_entries[i];
        printf("  0x%016lx  %s%s\n",
            (unsigned long)e.addr,
            e.valid ? hex_str(e.snap, SNAP_BYTES).c_str() : "[no read]",
            e.writable ? " [RW]" : "");
    }
    fflush(stdout);
}

} // extern "C"

__attribute__((constructor))
static void on_load() {
    printf("[memdebug] injected\n");
    fflush(stdout);
    std::thread([](){
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        memdebug_start();
    }).detach();
}

__attribute__((destructor))
static void on_unload() { memdebug_stop(); }
