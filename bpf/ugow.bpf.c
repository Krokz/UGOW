// SPDX-License-Identifier: GPL-2.0
/*
 * UGOW BPF LSM -- W-bit enforcement via eBPF on the stock WSL2 kernel.
 *
 * Hooks write-class VFS operations and checks a BPF hash map keyed by
 * (inode, device, uid).  Walks the dentry tree upward so a grant on a
 * directory covers all descendants.
 *
 * Only enforces on devices listed in the target_devs map (populated by
 * the userspace loader with the dev_t of 9P mounts).
 *
 * Compile:
 *   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
 *         -I/usr/include/bpf -c ugow.bpf.c -o ugow.bpf.o
 */

#include "vmlinux.h"

#ifndef EACCES
#define EACCES 13
#endif

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
static __always_inline bool is_target_dev(struct inode *inode)
{
	__u32 dev = BPF_CORE_READ(inode, i_sb, s_dev);
	return bpf_map_lookup_elem(&target_devs, &dev) != NULL;
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

	__u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
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

	__u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	if (uid == 0)
		return 0;
	struct hlist_node *first = BPF_CORE_READ(inode, i_dentry.first);
	if (!first)
		return -EACCES;
	struct dentry *dentry = container_of(first, struct dentry, d_u.d_alias);
	return check_wbit_dentry(dentry, uid);
}

SEC("lsm/inode_create")
int BPF_PROG(ugow_inode_create, struct inode *dir, struct dentry *dentry,
	     umode_t mode)
{
	if (!is_target_dev(dir))
		return 0;
	__u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
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
	__u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	if (uid == 0)
		return 0;
	return check_parent_wbit(new_dentry, uid);
}

SEC("lsm/inode_unlink")
int BPF_PROG(ugow_inode_unlink, struct inode *dir, struct dentry *dentry)
{
	if (!is_target_dev(dir))
		return 0;
	__u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
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
	__u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
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
	__u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	if (uid == 0)
		return 0;
	return check_parent_wbit(dentry, uid);
}

SEC("lsm/inode_rmdir")
int BPF_PROG(ugow_inode_rmdir, struct inode *dir, struct dentry *dentry)
{
	if (!is_target_dev(dir))
		return 0;
	__u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	if (uid == 0)
		return 0;
	return check_parent_wbit(dentry, uid);
}

SEC("lsm/inode_rename")
int BPF_PROG(ugow_inode_rename, struct inode *old_dir,
	     struct dentry *old_dentry, struct inode *new_dir,
	     struct dentry *new_dentry)
{
	bool old_target = is_target_dev(old_dir);
	bool new_target = is_target_dev(new_dir);
	if (!old_target && !new_target)
		return 0;

	__u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	if (uid == 0)
		return 0;

	if (old_target) {
		int ret = check_parent_wbit(old_dentry, uid);
		if (ret)
			return ret;
	}
	if (new_target)
		return check_parent_wbit(new_dentry, uid);
	return 0;
}
