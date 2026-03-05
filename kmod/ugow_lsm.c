// SPDX-License-Identifier: GPL-2.0
/*
 * UGOW LSM -- W-bit permission enforcement for WSL2 mounted filesystems.
 *
 * Adds a per-path, per-UID "write bit" that gates all write-class VFS
 * operations on 9P (drvfs) superblocks.  Grants are managed from userspace
 * via a securityfs control interface.
 *
 * Build: compile into a custom WSL2-Linux-Kernel with CONFIG_SECURITY_UGOW=y.
 */

#include <linux/lsm_hooks.h>
#include <linux/security.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/cred.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

#define UGOW_NAME	"ugow"
#define UGOW_HT_BITS	10		/* 1024 buckets */
#define UGOW_PATH_MAX	4096

/* ------------------------------------------------------------------ */
/* Grant table: hash(path, uid) -> entry                              */
/* ------------------------------------------------------------------ */

struct ugow_grant {
	struct hlist_node	node;
	struct rcu_head		rcu;
	kuid_t			uid;
	char			path[];		/* flexible array */
};

static DEFINE_HASHTABLE(ugow_grants, UGOW_HT_BITS);
static DEFINE_SPINLOCK(ugow_lock);

static u32 grant_hash(const char *path, kuid_t uid)
{
	u32 h = full_name_hash(NULL, path, strlen(path));
	return hash_32(h ^ __kuid_val(uid), UGOW_HT_BITS);
}

/* Read-side lookup -- caller must hold rcu_read_lock(). */
static bool ugow_has_grant_rcu(const char *path, kuid_t uid)
{
	struct ugow_grant *g;
	u32 bucket = grant_hash(path, uid);

	hlist_for_each_entry_rcu(g, &ugow_grants[bucket], node) {
		if (uid_eq(g->uid, uid) && strcmp(g->path, path) == 0)
			return true;
	}
	return false;
}

/* Write-side lookup -- caller must hold ugow_lock. */
static bool ugow_has_grant_locked(const char *path, kuid_t uid)
{
	struct ugow_grant *g;
	u32 bucket = grant_hash(path, uid);

	hlist_for_each_entry(g, &ugow_grants[bucket], node) {
		if (uid_eq(g->uid, uid) && strcmp(g->path, path) == 0)
			return true;
	}
	return false;
}

/*
 * Walk from @path up to "/" checking for a grant.  Mirrors the
 * inheritance semantics of the userspace shim: a grant on a directory
 * covers all descendants.
 */
static bool ugow_check_wbit(char *path, kuid_t uid)
{
	char *slash;
	bool found;

	rcu_read_lock();
	for (;;) {
		found = ugow_has_grant_rcu(path, uid);
		if (found)
			break;
		slash = strrchr(path, '/');
		if (!slash || slash == path) {
			found = ugow_has_grant_rcu("/", uid);
			break;
		}
		*slash = '\0';
	}
	rcu_read_unlock();
	return found;
}

/* ------------------------------------------------------------------ */
/* Grant management (called from securityfs write handler)            */
/* ------------------------------------------------------------------ */

static int ugow_add_grant(const char *path, kuid_t uid)
{
	struct ugow_grant *g;
	size_t plen = strlen(path) + 1;

	g = kmalloc(sizeof(*g) + plen, GFP_KERNEL);
	if (!g)
		return -ENOMEM;
	g->uid = uid;
	memcpy(g->path, path, plen);

	spin_lock(&ugow_lock);
	if (ugow_has_grant_locked(path, uid)) {
		spin_unlock(&ugow_lock);
		kfree(g);
		return 0;
	}
	hash_add_rcu(ugow_grants, &g->node, grant_hash(path, uid));
	spin_unlock(&ugow_lock);
	return 0;
}

static int ugow_remove_grant(const char *path, kuid_t uid)
{
	struct ugow_grant *g;
	u32 bucket = grant_hash(path, uid);

	spin_lock(&ugow_lock);
	hlist_for_each_entry(g, &ugow_grants[bucket], node) {
		if (uid_eq(g->uid, uid) && strcmp(g->path, path) == 0) {
			hash_del_rcu(&g->node);
			spin_unlock(&ugow_lock);
			kfree_rcu(g, rcu);
			return 0;
		}
	}
	spin_unlock(&ugow_lock);
	return -ENOENT;
}

/* ------------------------------------------------------------------ */
/* Helper: resolve a dentry to an absolute path string                */
/* ------------------------------------------------------------------ */

static int ugow_dentry_path(struct dentry *dentry, char *buf, int buflen)
{
	char *p = dentry_path_raw(dentry, buf, buflen);
	if (IS_ERR(p))
		return PTR_ERR(p);
	if (p != buf)
		memmove(buf, p, strlen(p) + 1);
	return 0;
}

/* ------------------------------------------------------------------ */
/* Predicate: is this superblock a 9P (drvfs) mount we should gate?   */
/* ------------------------------------------------------------------ */

static bool ugow_is_target_sb(struct super_block *sb)
{
	/*
	 * WSL2 mounts Windows drives via 9P.  The filesystem type name
	 * is "9p" in the kernel.  We only enforce on these mounts.
	 */
	return sb->s_type && strcmp(sb->s_type->name, "9p") == 0;
}

/* ------------------------------------------------------------------ */
/* LSM hooks                                                          */
/* ------------------------------------------------------------------ */

static int ugow_inode_permission(struct inode *inode, int mask)
{
	struct dentry *dentry;
	char *pathbuf;
	kuid_t uid;
	int err, ret = -EACCES;

	if (!(mask & MAY_WRITE))
		return 0;
	if (!ugow_is_target_sb(inode->i_sb))
		return 0;

	pathbuf = kmalloc(UGOW_PATH_MAX, GFP_KERNEL);
	if (!pathbuf)
		return -ENOMEM;

	uid = current_fsuid();

	dentry = d_find_any_alias(inode);
	if (!dentry)
		goto out;

	err = ugow_dentry_path(dentry, pathbuf, UGOW_PATH_MAX);
	dput(dentry);
	if (err)
		goto out;

	if (ugow_check_wbit(pathbuf, uid))
		ret = 0;
out:
	kfree(pathbuf);
	return ret;
}

static int ugow_file_open(struct file *file)
{
	struct dentry *dentry;
	char *pathbuf;
	kuid_t uid;
	int err, ret = -EACCES;

	if (!(file->f_mode & FMODE_WRITE))
		return 0;
	if (!ugow_is_target_sb(file_inode(file)->i_sb))
		return 0;

	pathbuf = kmalloc(UGOW_PATH_MAX, GFP_KERNEL);
	if (!pathbuf)
		return -ENOMEM;

	uid = current_fsuid();
	dentry = file->f_path.dentry;

	err = ugow_dentry_path(dentry, pathbuf, UGOW_PATH_MAX);
	if (err)
		goto out;

	if (ugow_check_wbit(pathbuf, uid))
		ret = 0;
out:
	kfree(pathbuf);
	return ret;
}

static int ugow_check_parent_wbit(struct dentry *parent)
{
	char *pathbuf;
	kuid_t uid = current_fsuid();
	int err, ret = -EACCES;

	if (!ugow_is_target_sb(parent->d_sb))
		return 0;

	pathbuf = kmalloc(UGOW_PATH_MAX, GFP_KERNEL);
	if (!pathbuf)
		return -ENOMEM;

	err = ugow_dentry_path(parent, pathbuf, UGOW_PATH_MAX);
	if (err)
		goto out;

	if (ugow_check_wbit(pathbuf, uid))
		ret = 0;
out:
	kfree(pathbuf);
	return ret;
}

static int ugow_inode_create(struct inode *dir, struct dentry *dentry,
			     umode_t mode)
{
	return ugow_check_parent_wbit(dentry->d_parent);
}

static int ugow_inode_link(struct dentry *old_dentry, struct inode *dir,
			   struct dentry *new_dentry)
{
	return ugow_check_parent_wbit(new_dentry->d_parent);
}

static int ugow_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	return ugow_check_parent_wbit(dentry->d_parent);
}

static int ugow_inode_symlink(struct inode *dir, struct dentry *dentry,
			      const char *old_name)
{
	return ugow_check_parent_wbit(dentry->d_parent);
}

static int ugow_inode_mkdir(struct inode *dir, struct dentry *dentry,
			    umode_t mode)
{
	return ugow_check_parent_wbit(dentry->d_parent);
}

static int ugow_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
	return ugow_inode_unlink(dir, dentry);
}

static int ugow_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
			     struct inode *new_dir, struct dentry *new_dentry)
{
	int err;

	if (!ugow_is_target_sb(old_dentry->d_sb))
		return 0;

	/* Source parent must have W-bit */
	err = ugow_check_parent_wbit(old_dentry->d_parent);
	if (err)
		return err;

	/* Destination parent must have W-bit */
	return ugow_check_parent_wbit(new_dentry->d_parent);
}

/* ------------------------------------------------------------------ */
/* securityfs interface: /sys/kernel/security/ugow/                   */
/*                                                                    */
/*   grant   -- write "uid path\n" to grant                           */
/*   revoke  -- write "uid path\n" to revoke                          */
/*   grants  -- read to list all current grants                       */
/* ------------------------------------------------------------------ */

static struct dentry *ugow_dir;
static struct dentry *ugow_grant_file;
static struct dentry *ugow_revoke_file;
static struct dentry *ugow_list_file;

static int parse_uid_path(const char __user *buf, size_t count,
			  kuid_t *uid_out, char *path_out, size_t path_max)
{
	char *kbuf;
	char *space;
	unsigned long uid_val;
	int err;

	if (count >= UGOW_PATH_MAX + 32)
		return -EINVAL;

	kbuf = kmalloc(count + 1, GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	if (copy_from_user(kbuf, buf, count)) {
		err = -EFAULT;
		goto out;
	}
	kbuf[count] = '\0';
	if (count > 0 && kbuf[count - 1] == '\n')
		kbuf[count - 1] = '\0';

	space = strchr(kbuf, ' ');
	if (!space) {
		err = -EINVAL;
		goto out;
	}
	*space = '\0';

	err = kstrtoul(kbuf, 10, &uid_val);
	if (err)
		goto out;
	*uid_out = make_kuid(current_user_ns(), (uid_t)uid_val);
	if (!uid_valid(*uid_out)) {
		err = -EINVAL;
		goto out;
	}

	if (strlen(space + 1) >= path_max) {
		err = -ENAMETOOLONG;
		goto out;
	}
	strscpy(path_out, space + 1, path_max);
	err = 0;
out:
	kfree(kbuf);
	return err;
}

static ssize_t ugow_grant_write(struct file *file, const char __user *buf,
				size_t count, loff_t *ppos)
{
	char *path;
	kuid_t uid;
	int err;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	path = kmalloc(UGOW_PATH_MAX, GFP_KERNEL);
	if (!path)
		return -ENOMEM;

	err = parse_uid_path(buf, count, &uid, path, UGOW_PATH_MAX);
	if (err)
		goto out;

	err = ugow_add_grant(path, uid);
	if (!err)
		err = count;
out:
	kfree(path);
	return err;
}

static ssize_t ugow_revoke_write(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	char *path;
	kuid_t uid;
	int err;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	path = kmalloc(UGOW_PATH_MAX, GFP_KERNEL);
	if (!path)
		return -ENOMEM;

	err = parse_uid_path(buf, count, &uid, path, UGOW_PATH_MAX);
	if (err)
		goto out;

	err = ugow_remove_grant(path, uid);
	if (!err)
		err = count;
out:
	kfree(path);
	return err;
}

static void *ugow_list_start(struct seq_file *s, loff_t *pos)
{
	return (*pos == 0) ? (void *)1 : NULL;
}

static void *ugow_list_next(struct seq_file *s, void *v, loff_t *pos)
{
	++(*pos);
	return NULL;
}

static void ugow_list_stop(struct seq_file *s, void *v) { }

static int ugow_list_show(struct seq_file *s, void *v)
{
	struct ugow_grant *g;
	int bkt;

	rcu_read_lock();
	hash_for_each_rcu(ugow_grants, bkt, g, node)
		seq_printf(s, "%u\t%s\n", __kuid_val(g->uid), g->path);
	rcu_read_unlock();
	return 0;
}

static const struct seq_operations ugow_list_sops = {
	.start = ugow_list_start,
	.next  = ugow_list_next,
	.stop  = ugow_list_stop,
	.show  = ugow_list_show,
};

static int ugow_list_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &ugow_list_sops);
}

static const struct file_operations ugow_grant_fops = {
	.write = ugow_grant_write,
	.llseek = noop_llseek,
};

static const struct file_operations ugow_revoke_fops = {
	.write = ugow_revoke_write,
	.llseek = noop_llseek,
};

static const struct file_operations ugow_list_fops = {
	.open    = ugow_list_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};

/* ------------------------------------------------------------------ */
/* LSM init                                                           */
/* ------------------------------------------------------------------ */

static struct security_hook_list ugow_hooks[] __ro_after_init = {
	LSM_HOOK_INIT(inode_permission, ugow_inode_permission),
	LSM_HOOK_INIT(file_open,       ugow_file_open),
	LSM_HOOK_INIT(inode_create,    ugow_inode_create),
	LSM_HOOK_INIT(inode_link,      ugow_inode_link),
	LSM_HOOK_INIT(inode_unlink,    ugow_inode_unlink),
	LSM_HOOK_INIT(inode_symlink,   ugow_inode_symlink),
	LSM_HOOK_INIT(inode_mkdir,     ugow_inode_mkdir),
	LSM_HOOK_INIT(inode_rmdir,     ugow_inode_rmdir),
	LSM_HOOK_INIT(inode_rename,    ugow_inode_rename),
};

static int __init ugow_init(void)
{
	security_add_hooks(ugow_hooks, ARRAY_SIZE(ugow_hooks), UGOW_NAME);

	/* Create securityfs control interface */
	ugow_dir = securityfs_create_dir(UGOW_NAME, NULL);
	if (IS_ERR(ugow_dir))
		return PTR_ERR(ugow_dir);

	ugow_grant_file = securityfs_create_file("grant", 0200,
						 ugow_dir, NULL,
						 &ugow_grant_fops);
	if (IS_ERR(ugow_grant_file)) {
		securityfs_remove(ugow_dir);
		return PTR_ERR(ugow_grant_file);
	}

	ugow_revoke_file = securityfs_create_file("revoke", 0200,
						  ugow_dir, NULL,
						  &ugow_revoke_fops);
	if (IS_ERR(ugow_revoke_file)) {
		securityfs_remove(ugow_grant_file);
		securityfs_remove(ugow_dir);
		return PTR_ERR(ugow_revoke_file);
	}

	ugow_list_file = securityfs_create_file("grants", 0400,
						ugow_dir, NULL,
						&ugow_list_fops);
	if (IS_ERR(ugow_list_file)) {
		securityfs_remove(ugow_revoke_file);
		securityfs_remove(ugow_grant_file);
		securityfs_remove(ugow_dir);
		return PTR_ERR(ugow_list_file);
	}

	pr_info("ugow: W-bit LSM initialized (9P enforcement active)\n");
	return 0;
}

DEFINE_LSM(ugow) = {
	.name  = UGOW_NAME,
	.init  = ugow_init,
};
