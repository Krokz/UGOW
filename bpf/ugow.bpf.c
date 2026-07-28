// SPDX-License-Identifier: GPL-2.0
/*
 * UGOW BPF LSM -- W-bit enforcement via eBPF on the stock WSL2 kernel.
 *
 * Hooks write-class VFS operations and checks a BPF hash map keyed by
 * (inode, device, uid).  Walks the dentry tree upward so a grant on a
 * directory covers all descendants.
 *
 * Only enforces on devices listed in the target_devs map, which the
 * userspace loader populates from the mounts it has been told to manage
 * (recorded in /var/lib/ugow/drives and replayed at boot).  Keying on the
 * device rather than the filesystem type keeps this working across WSL
 * releases, which have shipped /mnt/c as 9p and as virtiofs.
 *
 * Compile:
 *   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
 *         -I/usr/include/bpf -c ugow.bpf.c -o ugow.bpf.o
 */

#include "vmlinux.h"

#ifndef EACCES
#define EACCES 13
#endif

/*
 * struct iattr::ia_valid bits. These are preprocessor defines in <linux/fs.h>,
 * so they carry no BTF and are absent from vmlinux.h -- they have to be
 * restated here. Values are from include/linux/fs.h and are ABI-stable.
 */
#define UGOW_ATTR_MODE		(1 << 0)
#define UGOW_ATTR_UID		(1 << 1)
#define UGOW_ATTR_GID		(1 << 2)
#define UGOW_ATTR_SIZE		(1 << 3)
#define UGOW_ATTR_ATIME		(1 << 4)
#define UGOW_ATTR_MTIME		(1 << 5)
#define UGOW_ATTR_ATIME_SET	(1 << 7)
#define UGOW_ATTR_MTIME_SET	(1 << 8)

#define UGOW_GATED_ATTRS (UGOW_ATTR_MODE | UGOW_ATTR_UID | UGOW_ATTR_GID | \
			  UGOW_ATTR_SIZE | UGOW_ATTR_ATIME | UGOW_ATTR_MTIME | \
			  UGOW_ATTR_ATIME_SET | UGOW_ATTR_MTIME_SET)

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "ugow.h"

char LICENSE[] SEC("license") = "GPL";

/* ------------------------------------------------------------------ */
/* Maps                                                               */
/* ------------------------------------------------------------------ */

/*
 * Grant table: (ino, dev, uid) -> 1.
 * Populated from userspace via bpftool / the loader.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct grant_key);
	__type(value, __u8);
} grants SEC(".maps");

/*
 * Device filter: dev_t -> 1.
 * Only devices present here are subject to W-bit enforcement.
 * The loader adds the dev_t of each 9P mount (e.g. /mnt/c).
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u8);
} target_devs SEC(".maps");

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

/*
 * Check whether the device backing this inode is one we enforce on.
 */
static __always_inline bool is_target_dev_num(__u32 dev)
{
	return bpf_map_lookup_elem(&target_devs, &dev) != NULL;
}

static __always_inline bool is_target_dev(struct inode *inode)
{
	return is_target_dev_num(BPF_CORE_READ(inode, i_sb, s_dev));
}

static __always_inline bool is_target_dentry(struct dentry *dentry)
{
	return is_target_dev_num(BPF_CORE_READ(dentry, d_sb, s_dev));
}

/*
 * Filesystem uid of the current task.
 *
 * bpf_get_current_uid_gid() returns the *real* uid, which diverges from the
 * uid the VFS actually authorizes with whenever a task has called setfsuid()
 * -- notably file servers and some container runtimes.  Read cred->fsuid so
 * the decision matches the one the kernel's own DAC check makes.
 */
static __always_inline __u32 current_fsuid(void)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

	return BPF_CORE_READ(task, cred, fsuid.val);
}

/*
 * Walk from @dentry upward through the tree, checking the grants map
 * at each level.  Returns 0 (allow) if any ancestor has a grant, or
 * -EACCES if none do.
 */
static __always_inline int check_wbit_dentry(struct dentry *dentry, __u32 uid)
{
	struct grant_key key = {};
	struct dentry *parent;

	key.uid = uid;

	for (int i = 0; i < MAX_PATH_DEPTH; i++) {
		struct inode *d_inode = BPF_CORE_READ(dentry, d_inode);
		if (!d_inode)
			break;

		key.ino = BPF_CORE_READ(d_inode, i_ino);
		key.dev = BPF_CORE_READ(d_inode, i_sb, s_dev);

		if (bpf_map_lookup_elem(&grants, &key))
			return 0;

		parent = BPF_CORE_READ(dentry, d_parent);
		if (parent == dentry)
			break;
		dentry = parent;
	}

	return -EACCES;
}

/*
 * Same check but starting from the parent of @dentry (for create-like
 * operations where the entry doesn't exist yet).
 */
static __always_inline int check_parent_wbit(struct dentry *dentry, __u32 uid)
{
	struct dentry *parent = BPF_CORE_READ(dentry, d_parent);
	return check_wbit_dentry(parent, uid);
}

/* ------------------------------------------------------------------ */
/* LSM hooks                                                          */
/* ------------------------------------------------------------------ */

SEC("lsm/file_open")
int BPF_PROG(ugow_file_open, struct file *file)
{
	struct inode *inode = BPF_CORE_READ(file, f_inode);
	unsigned int mode = BPF_CORE_READ(file, f_mode);

	if (!(mode & 2))   /* FMODE_WRITE = 2 */
		return 0;
	if (!is_target_dev(inode))
		return 0;

	__u32 uid = current_fsuid();
	if (uid == 0)
		return 0;
	struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
	return check_wbit_dentry(dentry, uid);
}

SEC("lsm/inode_permission")
int BPF_PROG(ugow_inode_permission, struct inode *inode, int mask)
{
	if (!(mask & 2))   /* MAY_WRITE = 2 */
		return 0;
	if (!is_target_dev(inode))
		return 0;

	__u32 uid = current_fsuid();
	if (uid == 0)
		return 0;

	/*
	 * This hook only gets an inode, so it cannot know which name the caller
	 * used. For a multiply-linked inode any alias we pick may be the wrong
	 * one, and guessing could wrongly allow a write through an ungranted
	 * name. Defer to file_open and the inode_* hooks, which receive the real
	 * dentry -- deferring loses no enforcement, since those still run.
	 */
	if (BPF_CORE_READ(inode, i_nlink) > 1)
		return 0;

	struct hlist_node *first = BPF_CORE_READ(inode, i_dentry.first);
	if (!first)
		return 0;
	struct dentry *dentry = container_of(first, struct dentry, d_u.d_alias);
	return check_wbit_dentry(dentry, uid);
}

/*
 * Metadata writes: chmod, chown, truncate and utimensat all arrive here.
 * Without this hook an unprivileged caller could re-mode any file on an
 * enforced drive, which is a write in every sense that matters.
 */
SEC("lsm/inode_setattr")
int BPF_PROG(ugow_inode_setattr, struct dentry *dentry, struct iattr *attr)
{
	if (!(BPF_CORE_READ(attr, ia_valid) & UGOW_GATED_ATTRS))
		return 0;
	if (!is_target_dentry(dentry))
		return 0;

	__u32 uid = current_fsuid();
	if (uid == 0)
		return 0;
	return check_wbit_dentry(dentry, uid);
}

/* inode_create covers only regular files; this covers FIFOs, sockets and
 * device nodes. */
SEC("lsm/inode_mknod")
int BPF_PROG(ugow_inode_mknod, struct inode *dir, struct dentry *dentry,
	     umode_t mode, dev_t dev)
{
	if (!is_target_dev(dir))
		return 0;
	__u32 uid = current_fsuid();
	if (uid == 0)
		return 0;
	return check_parent_wbit(dentry, uid);
}

SEC("lsm/inode_setxattr")
int BPF_PROG(ugow_inode_setxattr, struct mnt_idmap *idmap,
	     struct dentry *dentry, const char *name, const void *value,
	     __u64 size, int flags)
{
	if (!is_target_dentry(dentry))
		return 0;
	__u32 uid = current_fsuid();
	if (uid == 0)
		return 0;
	return check_wbit_dentry(dentry, uid);
}

SEC("lsm/inode_removexattr")
int BPF_PROG(ugow_inode_removexattr, struct mnt_idmap *idmap,
	     struct dentry *dentry, const char *name)
{
	if (!is_target_dentry(dentry))
		return 0;
	__u32 uid = current_fsuid();
	if (uid == 0)
		return 0;
	return check_wbit_dentry(dentry, uid);
}

SEC("lsm/inode_create")
int BPF_PROG(ugow_inode_create, struct inode *dir, struct dentry *dentry,
	     umode_t mode)
{
	if (!is_target_dev(dir))
		return 0;
	__u32 uid = current_fsuid();
	if (uid == 0)
		return 0;
	return check_parent_wbit(dentry, uid);
}

SEC("lsm/inode_link")
int BPF_PROG(ugow_inode_link, struct dentry *old_dentry, struct inode *dir,
	     struct dentry *new_dentry)
{
	if (!is_target_dev(dir))
		return 0;
	__u32 uid = current_fsuid();
	if (uid == 0)
		return 0;

	int ret = check_parent_wbit(new_dentry, uid);
	if (ret)
		return ret;

	/*
	 * The new name must not confer rights the existing one lacks: the
	 * W-bit walk starts from whichever path is used, so a link created
	 * inside a granted directory would otherwise make a protected file
	 * writable through its second name.
	 */
	return check_wbit_dentry(old_dentry, uid);
}

SEC("lsm/inode_unlink")
int BPF_PROG(ugow_inode_unlink, struct inode *dir, struct dentry *dentry)
{
	if (!is_target_dev(dir))
		return 0;
	__u32 uid = current_fsuid();
	if (uid == 0)
		return 0;
	return check_parent_wbit(dentry, uid);
}

SEC("lsm/inode_symlink")
int BPF_PROG(ugow_inode_symlink, struct inode *dir, struct dentry *dentry,
	     const char *old_name)
{
	if (!is_target_dev(dir))
		return 0;
	__u32 uid = current_fsuid();
	if (uid == 0)
		return 0;
	return check_parent_wbit(dentry, uid);
}

SEC("lsm/inode_mkdir")
int BPF_PROG(ugow_inode_mkdir, struct inode *dir, struct dentry *dentry,
	     umode_t mode)
{
	if (!is_target_dev(dir))
		return 0;
	__u32 uid = current_fsuid();
	if (uid == 0)
		return 0;
	return check_parent_wbit(dentry, uid);
}

SEC("lsm/inode_rmdir")
int BPF_PROG(ugow_inode_rmdir, struct inode *dir, struct dentry *dentry)
{
	if (!is_target_dev(dir))
		return 0;
	__u32 uid = current_fsuid();
	if (uid == 0)
		return 0;
	return check_parent_wbit(dentry, uid);
}

SEC("lsm/inode_rename")
int BPF_PROG(ugow_inode_rename, struct inode *old_dir,
	     struct dentry *old_dentry, struct inode *new_dir,
	     struct dentry *new_dentry)
{
	__u32 uid = current_fsuid();
	if (uid == 0)
		return 0;

	if (is_target_dev(old_dir)) {
		int ret = check_parent_wbit(old_dentry, uid);
		if (ret)
			return ret;
	}
	if (is_target_dev(new_dir))
		return check_parent_wbit(new_dentry, uid);
	return 0;
}
