#include "utils.h"

static struct klp_func funcs[] = {
	{
		.old_name = "kallsyms_lookup_name",
		.new_func = kallsyms_lookup_name,
	}, {}
};

static struct klp_func failfuncs[] = {
	{
		.old_name = "___________________",
	}, {}
};

static struct klp_object objs[] = {
	{
		.funcs = funcs,
	},
	{
		.name = "kallsyms_failing_name",
		.funcs = failfuncs,
	}, { }
};

static struct klp_patch patch = {
	.mod = THIS_MODULE,
	.objs = objs,
};

unsigned long kallsyms_lookup_name(const char *name)
{
	return ((unsigned long(*)(const char *))funcs->old_func)(name);
}

int init_kallsyms(void)
{
	int r = klp_enable_patch(&patch);

	if (!r)
		return -1;

	return 0;
}

static int hook_resolve_addr(struct ftrace_hook *hook)
{
    hook->address = kallsyms_lookup_name(hook->name);
    /* lookup address for the symbol */
    if (!hook->address) {
        printk("unresolved symbol: %s\n", hook->name);
        return -ENOENT;
    }
    *((unsigned long *) hook->orig) = hook->address;
    return 0;
}

static void notrace hook_ftrace_thunk(unsigned long ip,
                                      unsigned long parent_ip,
                                      struct ftrace_ops *ops,
                                      struct pt_regs *regs)
{
    /* get struct ftrace_hook from member ops */
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
    if (!within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long) hook->func;
}

int hook_install(struct ftrace_hook *hook)
{
    int err = hook_resolve_addr(hook);
    if (err)
        return err;

    hook->ops.func = hook_ftrace_thunk;
    /**
     * SAVE_REGS: The ftrace_ops wants regs saved at each function called and passed to the callback.
     * RECURSION_SAFE : The ftrace_ops can set this to tell the ftrace infrastructure
     *                  that the call back has its own recursion protection.
     * IPMODIFY - The ops can modify the IP register.
     *            This can only be set with SAVE_REGS.
     **/
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION_SAFE |
                      FTRACE_OPS_FL_IPMODIFY;

    /* set a function to filter on in ftrace by address */
    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (err) {
        printk("ftrace_set_filter_ip() failed: %d\n", err);
        return err;
    }

    /* register a function for profiling */
    err = register_ftrace_function(&hook->ops);
    if (err) {
        printk("register_ftrace_function() failed: %d\n", err);
        /* remove ip from filter */
        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
        return err;
    }
    return 0;
}

void hook_remove(struct ftrace_hook *hook)
{
    int err = unregister_ftrace_function(&hook->ops);
    if (err)
        printk("unregister_ftrace_function() failed: %d\n", err);
    err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    if (err)
        printk("ftrace_set_filter_ip() failed: %d\n", err);
}