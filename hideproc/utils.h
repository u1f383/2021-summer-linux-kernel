#include <linux/cdev.h>
#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/livepatch.h>
#include <linux/pid.h>

struct ftrace_hook {
    const char *name;
    void *func, *orig;
    unsigned long address;
    struct ftrace_ops ops;
};

unsigned long kallsyms_lookup_name(const char *name);
int init_kallsyms(void);
void hook_remove(struct ftrace_hook *hook);
int hook_install(struct ftrace_hook *hook);