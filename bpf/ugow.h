/* SPDX-License-Identifier: GPL-2.0 */
#ifndef UGOW_H
#define UGOW_H

/*
 * Shared types between BPF programs and the userspace loader.
 *
 * Grants are keyed by (inode number, device number, uid) so the BPF
 * program never touches path strings -- everything is a fixed-size
 * integer lookup.  The userspace loader resolves paths to (ino, dev)
 * via stat() and populates the maps.
 */

#define MAX_PATH_DEPTH 32

struct grant_key {
	unsigned long	ino;
	unsigned int	dev;
	unsigned int	uid;
};

#endif /* UGOW_H */
