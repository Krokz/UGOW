// SPDX-License-Identifier: GPL-2.0
/*
 * UGOW LSM -- W-bit permission enforcement for WSL2 mounted filesystems.
 *
 * Adds a per-path, per-UID "write bit" that gates write-class VFS operations
 * on filesystems userspace has registered for enforcement.  Grants are managed
 * from userspace via a securityfs control interface.
 *
 * Grant identity
 * --------------
 * A grant is (device, superblock-relative path, uid).  The kernel can only
 * cheaply derive a *superblock*-relative path for a dentry -- dentry_path_raw()
 * stops at the filesystem root, so a file the user calls /mnt/c/docker/f is
 * /docker/f here.  Pairing that path with the superblock's device keeps grants
 * unambiguous when several drives are mounted, since /docker on C: and /docker
 * on D: differ in device.  Userspace does the mountpoint arithmetic and sends
 * both halves.
 *
 * Devices are registered explicitly, mirroring the BPF backend's target_devs
 * map: a superblock nobody registered is not enforced at all.  That keeps a
 * freshly booted system usable before grants have been replayed, and avoids
 * guessing at filesystem type names, which have changed across WSL releases
 * (9p, drvfs, virtiofs).
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
#include <linux/kdev_t.h>

#define UGOW_NAME	"ugow"
#define UGOW_HT_BITS	10		/* 1024 buckets */
#define UGOW_PATH_MAX	4096
#define UGOW_MAX_DEVS	64

/* ------------------------------------------------------------------ */
/* Registered devices                                                 */
/*                                                                    */
/* Read on every gated operation and written only from securityfs, so  */
/* reads are lock-free: dev_t is u32, slots are published with a       */
/* single store, and a stale read can only mean "one operation used    */
/* the previous registration state".                                   */
/* ------------------------------------------------------------------ */

static dev_t ugow_devs[UGOW_MAX_DEVS];	/* 0 == empty slot */
static DEFINE_SPINLOCK(ugow_dev_lock);

static bool ugow_dev_enforced(dev_t dev)
{
	int i;

	if (!dev)
		return false;
	for (i = 0; i < UGOW_MAX_DEVS; i++)
		if (READ_ONCE(ugow_devs[i]) == dev)
			return true;
	return false;
}

static int ugow_dev_add(dev_t dev)
{
	int i, free_slot = -1;

	if (!dev)
		return -EINVAL;

	spin_lock(&ugow_dev_lock);
	for (i = 0; i < UGOW_MAX_DEVS; i++) {
		if (ugow_devs[i] == dev) {
			spin_unlock(&ugow_dev_lock);
			return 0;
		}
		if (!ugow_devs[i] && free_slot < 0)
			free_slot = i;
	}
	if (free_slot < 0) {
		spin_unlock(&ugow_dev_lock);
		return -ENOSPC;
	}
	WRITE_ONCE(ugow_devs[free_slot], dev);
	spin_unlock(&ugow_dev_lock);
	return 0;
}

static int ugow_dev_del(dev_t dev)
{
	int i, ret = -ENOENT;

	spin_lock(&ugow_dev_lock);
	for (i = 0; i < UGOW_MAX_DEVS; i++) {
		if (ugow_devs[i] == dev) {
			WRITE_ONCE(ugow_devs[i], 0);
			ret = 0;
			break;
		}
	}
	spin_unlock(&ugow_dev_lock);
	return ret;
}

/* ------------------------------------------------------------------ */
/* Grant table: hash(dev, path, uid) -> entry                         */
/* ------------------------------------------------------------------ */

struct ugow_grant {
	struct hlist_node	node;
	struct rcu_head		rcu;
	kuid_t			uid;
	dev_t			dev;
	char			path[];		/* superblock-relative */
};

static DEFINE_HASHTABLE(ugow_grants, UGOW_HT_BITS);
static DEFINE_SPINLOCK(ugow_lock);

/*
 * Hash of the grant identity.  This is the *key*, not a bucket index --
 * hash_add_rcu() and hash_for_each_possible_rcu() apply hash_min() themselves,
 * so handing them a pre-computed bucket would hash twice and file entries in a
 * bucket lookups never visit.
 */
static u32 grant_key(dev_t dev, const char *path, kuid_t uid)
{
	u32 h = full_name_hash(NULL, path, strlen(path));

	return h ^ __kuid_val(uid) ^ (u32)dev;
}

static bool grant_matches(const struct ugow_grant *g, dev_t dev,
			  const char *path, kuid_t uid)
{
	return g->dev == dev && uid_eq(g->uid, uid) &&
	       strcmp(g->path, path) == 0;
}

/* Read-side lookup -- caller must hold rcu_read_lock(). */
static bool ugow_has_grant_rcu(dev_t dev, const char *path, kuid_t uid)
{
	struct ugow_grant *g;
	u32 key = grant_key(dev, path, uid);

	hash_for_each_possible_rcu(ugow_grants, g, node, key) {
		if (grant_matches(g, dev, path, uid))
			return true;
	}
	return false;
}

/*
 * Walk from @path up to "/" checking for a grant.  Mirrors the inheritance
 * semantics of the userspace shim: a grant on a directory covers all
 * descendants.  @path is modified in place (a private buffer).
 */
static bool ugow_check_wbit(dev_t dev, char *path, kuid_t uid)
{
	char *slash;
	bool found;

	rcu_read_lock();
	for (;;) {
		found = ugow_has_grant_rcu(dev, path, uid);
		if (found)
			break;
		slash = strrchr(path, '/');
		if (!slash || slash == path) {
			found = ugow_has_grant_rcu(dev, "/", uid);
			break;
		}
		*slash = '\0';
	}
	rcu_read_unlock();
	return found;
}

/* ------------------------------------------------------------------ */
/* Grant management (called from securityfs write handlers)           */
/* ------------------------------------------------------------------ */

static int ugow_add_grant(dev_t dev, const char *path, kuid_t uid)
{
	struct ugow_grant *g, *existing;
	size_t plen = strlen(path) + 1;
	u32 key = grant_key(dev, path, uid);

	g = kmalloc(sizeof(*g) + plen, GFP_KERNEL);
	if (!g)
		return -ENOMEM;
	g->uid = uid;
	g->dev = dev;
	memcpy(g->path, path, plen);

	spin_lock(&ugow_lock);
	hash_for_each_possible(ugow_grants, existing, node, key) {
		if (grant_matches(existing, dev, path, uid)) {
			spin_unlock(&ugow_lock);
			kfree(g);
			return 0;
		}
	}
	hash_add_rcu(ugow_grants, &g->node, key);
	spin_unlock(&ugow_lock);
	return 0;
}

static int ugow_remove_grant(dev_t dev, const char *path, kuid_t uid)
{
	struct ugow_grant *g;
	u32 key = grant_key(dev, path, uid);

	spin_lock(&ugow_lock);
	hash_for_each_possible(ugow_grants, g, node, key) {
		if (grant_matches(g, dev, path, uid)) {
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
/* Helper: resolve a dentry to a superblock-relative path string      */
/* ------------------------------------------------------------------ */

static int ugow_dentry_path(struct dentry *dentry, char *buf, int buflen)
{
	char *p;

	/*
	 * An anonymous or disconnected dentry has no parent chain, so
	 * dentry_path_raw() would render it as "/" -- letting an unrelated file
	 * be evaluated as the filesystem root, where a "/" grant applies.
	 */
	if (dentry->d_flags & DCACHE_DISCONNECTED)
		return -ENOENT;

	p = dentry_path_raw(dentry, buf, buflen);
	if (IS_ERR(p))
		return PTR_ERR(p);
	if (p != buf)
		memmove(buf, p, strlen(p) + 1);

	/* Only the superblock root may legitimately render as "/". */
	if (buf[0] == '/' && buf[1] == '\0' && !IS_ROOT(dentry))
		return -ENOENT;
	return 0;
}

/* ------------------------------------------------------------------ */
/* Core check                                                         */
/* ------------------------------------------------------------------ */

static bool ugow_exempt(void)
{
#ifdef CONFIG_SECURITY_UGOW_ROOT_EXEMPT
	if (uid_eq(current_fsuid(), GLOBAL_ROOT_UID))
		return true;
#endif
	return false;
}

/*
 * Gate a write on @dentry, which must live on @sb.  Returns 0 to allow or
 * -EACCES to deny.  Cheap rejections (unenforced device, exempt caller) happen
 * before any allocation.
 */
static int ugow_gate(struct super_block *sb, struct dentry *dentry)
{
	char *pathbuf;
	dev_t dev;
	int err, ret = -EACCES;

	if (!sb || !dentry)
		return 0;
	dev = sb->s_dev;
	if (!ugow_dev_enforced(dev))
		return 0;
	if (ugow_exempt())
		return 0;

	/* names_cachep -- the PATH_MAX slab the VFS itself uses for this. */
	pathbuf = __getname();
	if (!pathbuf)
		return -ENOMEM;

	err = ugow_dentry_path(dentry, pathbuf, UGOW_PATH_MAX);
	if (err) {
		/*
		 * Report why rather than folding every failure into -EACCES: a
		 * path we could not render is not the same as a path the caller
		 * has no grant for, and conflating them makes an out-of-memory
		 * condition look like a permission decision.
		 */
		ret = err;
		goto out;
	}

	if (ugow_check_wbit(dev, pathbuf, current_fsuid()))
		ret = 0;
out:
	__putname(pathbuf);
	return ret;
}

static int ugow_gate_parent(struct dentry *dentry)
{
	if (!dentry)
		return 0;
	return ugow_gate(dentry->d_sb, dentry->d_parent);
}

/* ------------------------------------------------------------------ */
/* LSM hooks                                                          */
/* ------------------------------------------------------------------ */

static int ugow_inode_permission(struct inode *inode, int mask)
{
	struct dentry *dentry;
	int ret;

	if (!(mask & MAY_WRITE))
		return 0;
	/* Nothing here may sleep during an RCU path walk. */
	if (mask & MAY_NOT_BLOCK)
		return -ECHILD;
	if (!ugow_dev_enforced(inode->i_sb->s_dev))
		return 0;
	if (ugow_exempt())
		return 0;

	/*
	 * This hook receives an inode, not a path, so there is no way to learn
	 * which name the caller used.  For a multiply-linked inode any alias we
	 * pick may be the wrong one, and guessing could wrongly *allow* a write
	 * through an ungranted name.  Defer instead: file_open() and the
	 * inode_* hooks all receive the real dentry and make the actual
	 * decision, so returning 0 here loses no enforcement.
	 */
	if (inode->i_nlink > 1)
		return 0;

	dentry = d_find_any_alias(inode);
	if (!dentry)
		return 0;

	ret = ugow_gate(inode->i_sb, dentry);
	dput(dentry);
	/* A name we could not render must not masquerade as a denial. */
	return ret == -ENOENT ? 0 : ret;
}

static int ugow_file_open(struct file *file)
{
	if (!(file->f_mode & FMODE_WRITE))
		return 0;
	return ugow_gate(file_inode(file)->i_sb, file->f_path.dentry);
}

static int ugow_inode_create(struct inode *dir, struct dentry *dentry,
			     umode_t mode)
{
	return ugow_gate_parent(dentry);
}

static int ugow_inode_link(struct dentry *old_dentry, struct inode *dir,
			   struct dentry *new_dentry)
{
	int ret = ugow_gate_parent(new_dentry);

	if (ret)
		return ret;
	/*
	 * The new name must not confer rights the existing one lacks: the
	 * W-bit walk starts from whichever path was used, so a link created
	 * inside a granted directory would otherwise expose a protected file
	 * for writing through its second name.
	 */
	return ugow_gate(old_dentry->d_sb, old_dentry);
}

static int ugow_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	return ugow_gate_parent(dentry);
}

static int ugow_inode_symlink(struct inode *dir, struct dentry *dentry,
			      const char *old_name)
{
	return ugow_gate_parent(dentry);
}

static int ugow_inode_mkdir(struct inode *dir, struct dentry *dentry,
			    umode_t mode)
{
	return ugow_gate_parent(dentry);
}

/* inode_create only covers regular files; without this, FIFOs, sockets and
 * device nodes could be created in a directory the caller has no grant on. */
static int ugow_inode_mknod(struct inode *dir, struct dentry *dentry,
			    umode_t mode, dev_t dev)
{
	return ugow_gate_parent(dentry);
}

static int ugow_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
	return ugow_gate_parent(dentry);
}

static int ugow_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
			     struct inode *new_dir, struct dentry *new_dentry)
{
	int err;

	/* Source parent must have W-bit */
	err = ugow_gate_parent(old_dentry);
	if (err)
		return err;

	/* Destination parent must have W-bit */
	return ugow_gate_parent(new_dentry);
}

/*
 * chmod, ownership, size and timestamp changes are all metadata writes:
 * ungated, they let any caller re-mode or re-stamp files they hold no grant on.
 *
 * ATTR_*TIME covers utimensat with UTIME_NOW; ATTR_*TIME_SET covers explicit
 * timestamps. Both arrive here through notify_change(), so ordinary writes --
 * which update mtime without it -- are unaffected.
 */
#define UGOW_GATED_ATTRS (ATTR_MODE | ATTR_UID | ATTR_GID | ATTR_SIZE | \
			  ATTR_ATIME | ATTR_MTIME | \
			  ATTR_ATIME_SET | ATTR_MTIME_SET)

static int ugow_inode_setattr(struct dentry *dentry, struct iattr *attr)
{
	if (!(attr->ia_valid & UGOW_GATED_ATTRS))
		return 0;
	return ugow_gate(dentry->d_sb, dentry);
}

/* Extended attributes carry ACLs and capabilities, so writing them is a
 * privileged metadata change like chmod. */
static int ugow_inode_setxattr(struct mnt_idmap *idmap, struct dentry *dentry,
			       const char *name, const void *value,
			       size_t size, int flags)
{
	return ugow_gate(dentry->d_sb, dentry);
}

static int ugow_inode_removexattr(struct mnt_idmap *idmap,
				  struct dentry *dentry, const char *name)
{
	return ugow_gate(dentry->d_sb, dentry);
}

/* ------------------------------------------------------------------ */
/* securityfs interface: /sys/kernel/security/ugow/                   */
/*                                                                    */
/*   grant   -- write "uid major:minor path\n" to grant               */
/*   revoke  -- write "uid major:minor path\n" to revoke              */
/*   devices -- write "+major:minor" / "-major:minor"; read to list   */
/*   grants  -- read to list all current grants                       */
/*                                                                    */
/* Paths are superblock-relative (userspace strips the mountpoint).    */
/* Devices are major:minor rather than a packed number so the two      */
/* sides never have to agree on a dev_t encoding.                     */
/* ------------------------------------------------------------------ */

static struct dentry *ugow_dir;
static struct dentry *ugow_grant_file;
static struct dentry *ugow_revoke_file;
static struct dentry *ugow_list_file;
static struct dentry *ugow_devices_file;

static char *ugow_copy_line(const char __user *buf, size_t count)
{
	char *kbuf;

	if (count == 0 || count >= UGOW_PATH_MAX + 64)
		return ERR_PTR(-EINVAL);

	kbuf = kmalloc(count + 1, GFP_KERNEL);
	if (!kbuf)
		return ERR_PTR(-ENOMEM);

	if (copy_from_user(kbuf, buf, count)) {
		kfree(kbuf);
		return ERR_PTR(-EFAULT);
	}
	kbuf[count] = '\0';
	if (kbuf[count - 1] == '\n')
		kbuf[count - 1] = '\0';

	/*
	 * One write is one record.  An embedded newline or tab would be stored
	 * verbatim inside a path and then re-emitted by the `grants` reader,
	 * letting a writer forge extra lines in output that userspace parses.
	 */
	if (strchr(kbuf, '\n') || strchr(kbuf, '\t')) {
		kfree(kbuf);
		return ERR_PTR(-EINVAL);
	}
	return kbuf;
}

/*
 * Accept only the shape dentry_path_raw() can actually produce, so a grant
 * that could never match is refused loudly instead of sitting in the table
 * looking effective.
 */
static bool ugow_path_is_canonical(const char *path)
{
	const char *p;

	if (path[0] != '/')
		return false;
	if (!strcmp(path, "/"))
		return true;
	if (path[strlen(path) - 1] == '/')
		return false;
	if (strstr(path, "//"))
		return false;
	for (p = path; p; p = strchr(p + 1, '/')) {
		const char *seg = (*p == '/') ? p + 1 : p;

		if (seg[0] == '.' &&
		    (seg[1] == '\0' || seg[1] == '/' ||
		     (seg[1] == '.' && (seg[2] == '\0' || seg[2] == '/'))))
			return false;
	}
	return true;
}

static int ugow_parse_dev(const char *s, dev_t *out)
{
	char *colon;
	unsigned int major, minor;
	char tmp[32];

	if (strscpy(tmp, s, sizeof(tmp)) < 0)
		return -EINVAL;
	colon = strchr(tmp, ':');
	if (!colon)
		return -EINVAL;
	*colon = '\0';
	if (kstrtouint(tmp, 10, &major))
		return -EINVAL;
	if (kstrtouint(colon + 1, 10, &minor))
		return -EINVAL;
	*out = MKDEV(major, minor);
	if (!*out)
		return -EINVAL;
	return 0;
}

/* Parse "uid major:minor path" out of a NUL-terminated line. */
static int ugow_parse_grant(char *line, kuid_t *uid_out, dev_t *dev_out,
			    char *path_out, size_t path_max)
{
	char *uid_tok, *dev_tok, *path_tok;
	unsigned int uid_val;
	int err;

	uid_tok = line;
	dev_tok = strchr(uid_tok, ' ');
	if (!dev_tok)
		return -EINVAL;
	*dev_tok++ = '\0';

	path_tok = strchr(dev_tok, ' ');
	if (!path_tok)
		return -EINVAL;
	*path_tok++ = '\0';

	if (kstrtouint(uid_tok, 10, &uid_val))
		return -EINVAL;
	*uid_out = make_kuid(current_user_ns(), (uid_t)uid_val);
	if (!uid_valid(*uid_out))
		return -EINVAL;

	err = ugow_parse_dev(dev_tok, dev_out);
	if (err)
		return err;

	if (!ugow_path_is_canonical(path_tok))
		return -EINVAL;
	if (strlen(path_tok) >= path_max)
		return -ENAMETOOLONG;
	strscpy(path_out, path_tok, path_max);
	return 0;
}

static ssize_t ugow_grant_common(const char __user *buf, size_t count,
				 bool add)
{
	char *line, *path;
	kuid_t uid;
	dev_t dev;
	int err;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	line = ugow_copy_line(buf, count);
	if (IS_ERR(line))
		return PTR_ERR(line);

	path = kmalloc(UGOW_PATH_MAX, GFP_KERNEL);
	if (!path) {
		kfree(line);
		return -ENOMEM;
	}

	err = ugow_parse_grant(line, &uid, &dev, path, UGOW_PATH_MAX);
	if (err)
		goto out;

	err = add ? ugow_add_grant(dev, path, uid)
		  : ugow_remove_grant(dev, path, uid);
	if (!err)
		err = count;
out:
	kfree(path);
	kfree(line);
	return err;
}

static ssize_t ugow_grant_write(struct file *file, const char __user *buf,
				size_t count, loff_t *ppos)
{
	return ugow_grant_common(buf, count, true);
}

static ssize_t ugow_revoke_write(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	return ugow_grant_common(buf, count, false);
}

static ssize_t ugow_devices_write(struct file *file, const char __user *buf,
				  size_t count, loff_t *ppos)
{
	char *line;
	dev_t dev;
	int err;
	bool add;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	line = ugow_copy_line(buf, count);
	if (IS_ERR(line))
		return PTR_ERR(line);

	if (line[0] == '+') {
		add = true;
	} else if (line[0] == '-') {
		add = false;
	} else {
		err = -EINVAL;
		goto out;
	}

	err = ugow_parse_dev(line + 1, &dev);
	if (err)
		goto out;

	err = add ? ugow_dev_add(dev) : ugow_dev_del(dev);
	if (!err)
		err = count;
out:
	kfree(line);
	return err;
}

static int ugow_grants_show(struct seq_file *s, void *v)
{
	struct ugow_grant *g;
	int bkt;

	rcu_read_lock();
	hash_for_each_rcu(ugow_grants, bkt, g, node)
		seq_printf(s, "%u\t%u:%u\t%s\n", __kuid_val(g->uid),
			   MAJOR(g->dev), MINOR(g->dev), g->path);
	rcu_read_unlock();
	return 0;
}

static int ugow_grants_open(struct inode *inode, struct file *file)
{
	return single_open(file, ugow_grants_show, NULL);
}

static int ugow_devices_show(struct seq_file *s, void *v)
{
	int i;

	for (i = 0; i < UGOW_MAX_DEVS; i++) {
		dev_t dev = READ_ONCE(ugow_devs[i]);

		if (dev)
			seq_printf(s, "%u:%u\n", MAJOR(dev), MINOR(dev));
	}
	return 0;
}

static int ugow_devices_open(struct inode *inode, struct file *file)
{
	return single_open(file, ugow_devices_show, NULL);
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
	.open    = ugow_grants_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = single_release,
};

static const struct file_operations ugow_devices_fops = {
	.open    = ugow_devices_open,
	.read    = seq_read,
	.write   = ugow_devices_write,
	.llseek  = seq_lseek,
	.release = single_release,
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
	LSM_HOOK_INIT(inode_mknod,     ugow_inode_mknod),
	LSM_HOOK_INIT(inode_rmdir,     ugow_inode_rmdir),
	LSM_HOOK_INIT(inode_rename,    ugow_inode_rename),
	LSM_HOOK_INIT(inode_setattr,   ugow_inode_setattr),
	LSM_HOOK_INIT(inode_setxattr,  ugow_inode_setxattr),
	LSM_HOOK_INIT(inode_removexattr, ugow_inode_removexattr),
};

static void __init ugow_remove_securityfs(void)
{
	securityfs_remove(ugow_devices_file);
	securityfs_remove(ugow_list_file);
	securityfs_remove(ugow_revoke_file);
	securityfs_remove(ugow_grant_file);
	securityfs_remove(ugow_dir);
}

static int __init ugow_securityfs_init(void)
{
	ugow_dir = securityfs_create_dir(UGOW_NAME, NULL);
	if (IS_ERR(ugow_dir))
		return PTR_ERR(ugow_dir);

	ugow_grant_file = securityfs_create_file("grant", 0200, ugow_dir,
						NULL, &ugow_grant_fops);
	if (IS_ERR(ugow_grant_file))
		return PTR_ERR(ugow_grant_file);

	ugow_revoke_file = securityfs_create_file("revoke", 0200, ugow_dir,
						 NULL, &ugow_revoke_fops);
	if (IS_ERR(ugow_revoke_file))
		return PTR_ERR(ugow_revoke_file);

	ugow_list_file = securityfs_create_file("grants", 0400, ugow_dir,
						NULL, &ugow_list_fops);
	if (IS_ERR(ugow_list_file))
		return PTR_ERR(ugow_list_file);

	ugow_devices_file = securityfs_create_file("devices", 0600, ugow_dir,
						   NULL, &ugow_devices_fops);
	if (IS_ERR(ugow_devices_file))
		return PTR_ERR(ugow_devices_file);

	return 0;
}

static int __init ugow_init(void)
{
	security_add_hooks(ugow_hooks, ARRAY_SIZE(ugow_hooks), UGOW_NAME);
	pr_info("ugow: W-bit LSM initialized (no device enforced until registered)\n");
	return 0;
}

DEFINE_LSM(ugow) = {
	.name  = UGOW_NAME,
	.init  = ugow_init,
};

/*
 * securityfs cannot be touched from the LSM .init callback: security_init()
 * runs before vfs_caches_init() in start_kernel(), so mnt_init() has not
 * happened and securityfs_create_dir() would fault trying to pin its
 * filesystem.  Every in-tree LSM registers its interface from a later
 * initcall for this reason (AppArmor's aa_create_aafs, TOMOYO's
 * tomoyo_initerface_init, SELinux's init_sel_fs).
 *
 * Arming the hooks first is harmless here: no device is enforced until one is
 * registered through this very interface, so an interface that failed to
 * appear leaves the system unchanged rather than read-only.
 */
static int __init ugow_fs_init(void)
{
	int err = ugow_securityfs_init();

	if (err) {
		ugow_remove_securityfs();
		pr_err("ugow: securityfs setup failed (%d); no grants can be "
		       "added, so nothing will be enforced\n", err);
	}
	return err;
}

fs_initcall(ugow_fs_init);
