#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#define TRACE_CAPACITY (16 * 1024 * 1024)

static uint64_t trace_buffer[TRACE_CAPACITY];
static size_t trace_count = 0;
static int trace_initialized = 0;
static volatile int in_trace = 0;

// Minimal fast integer-to-hex formatting (no libc printf/malloc)
static int format_entry(char *buf, size_t seq, uint64_t bb_id) {
    char num_buf[32];
    int nlen = 0;
    if (seq == 0) {
        num_buf[nlen++] = '0';
    } else {
        size_t temp = seq;
        while (temp > 0) {
            num_buf[nlen++] = (char)('0' + (temp % 10));
            temp /= 10;
        }
    }

    int pos = 0;
    for (int i = nlen - 1; i >= 0; --i) {
        buf[pos++] = num_buf[i];
    }
    buf[pos++] = ':';
    buf[pos++] = ' ';

    static const char hex_digits[] = "0123456789abcdef";
    for (int shift = 60; shift >= 0; shift -= 4) {
        buf[pos++] = hex_digits[(bb_id >> shift) & 0xf];
    }
    buf[pos++] = '\n';
    return pos;
}

__attribute__((no_sanitize("all")))
static void trace_flush(void) {
    if (in_trace || trace_count == 0) return;
    in_trace = 1;

    const char *trace_path = getenv("TARGET_GRAPH_TRACE_FILE");
    if (!trace_path) {
        trace_path = "trace.txt";
    }

    int fd = open(trace_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        char chunk[4096];
        int chunk_pos = 0;

        for (size_t i = 0; i < trace_count; ++i) {
            char entry_str[64];
            int elen = format_entry(entry_str, i, trace_buffer[i]);

            if (chunk_pos + elen >= (int)sizeof(chunk)) {
                write(fd, chunk, (size_t)chunk_pos);
                chunk_pos = 0;
            }
            for (int k = 0; k < elen; ++k) {
                chunk[chunk_pos++] = entry_str[k];
            }
        }
        if (chunk_pos > 0) {
            write(fd, chunk, (size_t)chunk_pos);
        }
        close(fd);
    }

    trace_count = 0;
    in_trace = 0;
}

extern void __sanitizer_set_death_callback(void (*callback)(void)) __attribute__((weak));

__attribute__((no_sanitize("all")))
static void crash_signal_handler(int sig, siginfo_t *info, void *ucontext) {
    (void)info;
    (void)ucontext;
    trace_flush();
    signal(sig, SIG_DFL);
    raise(sig);
}

__attribute__((no_sanitize("all")))
static void install_crash_handlers(void) {
    if (__sanitizer_set_death_callback) {
        __sanitizer_set_death_callback(trace_flush);
        return;
    }
    struct sigaction sa;
    sa.sa_sigaction = crash_signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO | SA_NODEFER | SA_RESETHAND;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
}

__attribute__((constructor))
__attribute__((no_sanitize("all")))
static void trace_ctor(void) {
    if (!trace_initialized) {
        trace_initialized = 1;
        atexit(trace_flush);
        install_crash_handlers();
    }
}

__attribute__((destructor))
__attribute__((no_sanitize("all")))
static void trace_dtor(void) {
    trace_flush();
}

__attribute__((no_sanitize("all")))
void __target_graph_trace_bb(uint64_t bb_id) {
    if (!trace_initialized) {
        trace_ctor();
    }
    if (!trace_initialized || in_trace) return;
    in_trace = 1;

    if (trace_count < TRACE_CAPACITY) {
        trace_buffer[trace_count++] = bb_id;
    }

    in_trace = 0;
}

__attribute__((no_sanitize("all")))
void __asan_on_error(void) {
    trace_flush();
}
