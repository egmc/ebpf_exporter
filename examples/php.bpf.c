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

    increment_map(&php_compile_file_total, &call, 1);

    return 0;
}


SEC("usdt//usr/lib/apache2/modules/libphp8.1.so:php:exception__thrown")
int BPF_USDT(exception_count, char *arg0) 
{
    struct exception_t exception = {};

    bpf_probe_read_user_str(&exception.class, sizeof(exception.class), arg0);

    increment_map(&php_exception_thrown_total, &exception, 1);

    return 0;
}

#define MAX_SLOT 50

struct hist_key_t {
    u64 bucket;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SLOT + 1);
    __type(key, struct hist_key_t);
    __type(value, u64);
} memcached_val_length SEC(".maps");

// uprobe: libmemcached.so の memcached_set にフック
SEC("uprobe//usr/lib/x86_64-linux-gnu/libmemcached.so.11:memcached_set")
int uprobe_memcached_set(struct pt_regs *ctx) {

    uint arg5 = (uint)PT_REGS_PARM5(ctx);
    const char *arg4 = (const char *)PT_REGS_PARM4(ctx);

    // 取得した第2引数の値を出力
    static const char fmt[] = "Value: %d\n"; 
    static const char fmtstr[] = "Value: %s\n"; 
    bpf_trace_printk(fmt, sizeof(fmt), arg5);
    bpf_trace_printk(fmtstr, sizeof(fmtstr), arg4);


    return 0;
}

char LICENSE[] SEC("license") = "GPL";
