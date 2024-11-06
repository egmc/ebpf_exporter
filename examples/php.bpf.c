#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/usdt.bpf.h>
#include "maps.bpf.h"

#define MAX_STR_LEN 256
#define MAX_CLASS_LEN 128

struct call_t {
    char filename[MAX_STR_LEN];
};

struct exception_t {
    char class[MAX_CLASS_LEN];
};

struct php_req_key {
    u32 pid;
    char request_uri[MAX_STR_LEN];
    char request_method[5];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct call_t);
    __type(value, u64);
} php_compile_file_total SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100);
    __type(key, struct exception_t);
    __type(value, u64);
} php_exception_thrown_total SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100);
    __type(key, struct exception_t);
    __type(value, u64);
} php_exception_caught_total SEC(".maps");

// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 10000);
//     __type(key, struct php_req_key);
//     __type(value, u64);
// } php_req SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, u32);
    __type(value, u64);
} php_req SEC(".maps");

int truncate_string(char *str, int max_length) {
    int i;

    // 文字列を後ろからチェック
    for (i = max_length - 1; i >= 0; i--) {
        if (str[i] == '/') {
            return i; 
        } else {
            str[i] = '\0';
        }
    }

    return -1;
}

SEC("usdt//usr/lib/apache2/modules/libphp8.1.so:php:compile__file__entry")
int BPF_USDT(do_count, char *arg0, char *arg1) 
{
    struct call_t call = {};

    bpf_probe_read_user_str(&call.filename, sizeof(call.filename), arg1);

    truncate_string(call.filename, MAX_STR_LEN);

    static const char fmtstr[] = "compile file entry: %s, %s\n"; 
    bpf_trace_printk(fmtstr, sizeof(fmtstr), arg0, arg1);

    increment_map(&php_compile_file_total, &call, 1);

    return 0;
}


SEC("usdt//usr/lib/apache2/modules/libphp8.1.so:php:exception__thrown")
int BPF_USDT(exception_count, char *arg0) 
{
    struct exception_t exception_thrown = {};

    bpf_probe_read_user_str(&exception_thrown.class, sizeof(exception_thrown.class), arg0);

    increment_map(&php_exception_thrown_total, &exception_thrown, 1);

    return 0;
}

SEC("usdt//usr/lib/apache2/modules/libphp8.1.so:php:exception__caught")
int BPF_USDT(exception_count2, char *arg0) 
{
    struct exception_t exception = {};

    bpf_probe_read_user_str(&exception.class, sizeof(exception.class), arg0);

    static const char fmtstr[] = "exception caught: %s\n"; 
    bpf_trace_printk(fmtstr, sizeof(fmtstr), arg0);


    increment_map(&php_exception_caught_total, &exception, 1);

    return 0;
}

SEC("usdt//usr/lib/apache2/modules/libphp8.1.so:php:request__startup")
int BPF_USDT(request_startup, char *arg0, char *arg1, char *arg2)
{
 
    u64 ts = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    static const char fmtstr[] = "request startup: %s, %s, %s\n"; 
    static const char fmtu64[] = "request startup time: %llu\n"; 
    static const char fmtu32[] = "request startup pid: %u\n"; 
    bpf_trace_printk(fmtstr, sizeof(fmtstr), arg0, arg1, arg2);
    bpf_trace_printk(fmtu64, sizeof(fmtu64), ts);
    bpf_trace_printk(fmtu32, sizeof(fmtu32), pid);

    struct php_req_key key;
    key.pid = pid;
    bpf_probe_read_user_str(&key.request_uri, sizeof(key.request_uri), arg1);
    bpf_probe_read_user_str(&key.request_method, sizeof(key.request_method), arg2);
    bpf_map_update_elem(&php_req, &pid, &ts, BPF_ANY);


    return 0;
}

SEC("usdt//usr/lib/apache2/modules/libphp8.1.so:php:request__shutdown")
int BPF_USDT(request_shutdown, char *arg0, char *arg1, char *arg2)
{
 
    u64 *tsp, delta_us, ts = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    static const char fmtstr[] = "request shutdown: %s, %s, %s\n"; 
    static const char fmtu64[] = "request shutdown time: %llu\n";
    static const char fmtu32[] = "request shutdown pid: %u\n"; 
    static const char fmtu64delta[] = "request shutdown elapsed: %llu\n"; 
    bpf_trace_printk(fmtstr, sizeof(fmtstr), arg0, arg1, arg2);
    bpf_trace_printk(fmtu64, sizeof(fmtu64), ts);
    bpf_trace_printk(fmtu32, sizeof(fmtu32), pid);

    struct php_req_key key;
    key.pid = pid;
    bpf_probe_read_user_str(&key.request_uri, sizeof(key.request_uri), arg1);
    bpf_probe_read_user_str(&key.request_method, sizeof(key.request_method), arg2);
    
    tsp = bpf_map_lookup_elem(&php_req, &pid);
    if (!tsp) {
        return 0;
    }

    delta_us = (ts - *tsp) / 1000;

    bpf_trace_printk(fmtu64delta, sizeof(fmtu64delta), delta_us);

    return 0;
}

#define MAX_SLOT 22

struct hist_key_t {
    u64 bucket;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SLOT + 1);
    __type(key, struct hist_key_t);
    __type(value, u64);
} memcached_set_val_length SEC(".maps");

// uprobe: libmemcached.so の memcached_set にフック
SEC("uprobe//usr/lib/x86_64-linux-gnu/libmemcached.so.11:memcached_set")
int uprobe_memcached_set(struct pt_regs *ctx) {

    u64 arg5 = (u64)PT_REGS_PARM5(ctx);
    const char *arg4 = (const char *)PT_REGS_PARM4(ctx);

    struct hist_key_t key = {};

    // 取得した第2引数の値を出力
    static const char fmt[] = "Value: %d\n"; 
    static const char fmtstr[] = "Value: %s\n"; 
    bpf_trace_printk(fmt, sizeof(fmt), arg5);
    bpf_trace_printk(fmtstr, sizeof(fmtstr), arg4);

    increment_exp2_histogram(&memcached_set_val_length, key, arg5, MAX_SLOT);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";