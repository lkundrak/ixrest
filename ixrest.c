/*
 * ixrest -- Restore PC/IX archives
 * Copyright (C) 2021  Lubomir Rintel <lkundrak@v3.sk>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>

#define MAGIC	60011
#define BPW     8

enum {
	FS_VOLUME	= 0,
	FS_FINDEX	= 1,
	FS_CLRI		= 2,
	FS_BITS		= 3,
	FS_OINODE	= 4,
	FS_ONAME	= 5,
	FS_VOLEND	= 6,
	FS_END		= 7,
	FS_INODE	= 8,
	FS_NAME		= 9,
};

struct hdr {
	uint8_t	len;
	uint8_t	type;
	uint16_t magic;
	uint16_t checksum;
} __attribute__ ((packed));

/*
 * The structure is fully described in
 * PC/IX's dumprestor.h
 */

union fs_rec {
	struct hdr h;

	struct {
		struct hdr h;
		uint16_t volnum;
		uint32_t date;
		uint32_t ddate;
		uint32_t numwds;
		char disk[16];
		char fsname[16];
		char user[16];
		short incno;
	} v;

	struct {
		struct hdr h;
		uint16_t nwds;
	} b;

	struct {
		struct hdr h;
		uint16_t ino;
		uint16_t mode;
		uint16_t nlink;
		uint16_t uid;
		uint16_t gid;
		uint32_t size;
		uint32_t atime;
		uint32_t mtime;
		uint32_t ctime;
		uint16_t devmaj;
		uint16_t devmin;
		uint16_t rdevmaj;
		uint16_t rdevmin;
		uint32_t dsize;
		int16_t pad;
	} i;

	struct {
		struct hdr h;
		uint16_t ino;
		uint16_t mode;
		uint16_t nlink;
		uint16_t uid;
		uint16_t gid;
		uint32_t size;
		uint32_t atime;
		uint32_t mtime;
		uint32_t ctime;
		uint16_t devmaj;
		uint16_t devmin;
		uint16_t rdevmaj;
		uint16_t rdevmin;
		uint32_t dsize;
		int32_t pad;
		char name[];
	} n;
} __attribute__ ((packed));

#define UNPRIVED	0x01
#define FSNAME		0x10

/*
 * Reliable read until buffer is filled.
 */

static int
do_read (int fd, void *buf, uint32_t *vol_size, size_t len)
{
	int bytes = 0;
	int ret;

	do {
		ret = read (fd, buf, vol_size && *vol_size < len ? *vol_size : len);
		if (ret == -1)
			return -1;
		if (ret == 0)
			break;
		if (vol_size)
			*vol_size -= ret;
		bytes += ret;
		len -= ret;
	} while (len);

	return bytes;
}

union fs_rec *
readhdr (int fd, uint32_t *vol_size)
{
	union fs_rec *rec;
	int ret;
	int len;

	/*
	 * The common part of the header.
	 */

	len = sizeof (rec->h);

	rec = malloc (len);
	ret = do_read (fd, rec, vol_size, len);

	switch (ret) {
	case sizeof (rec->h):
		break;
	case -1:
		perror ("read");
		return NULL;
	default:
		fprintf (stderr, "short read\n");
		return NULL;
	}

	if (rec->h.magic != MAGIC) {
		fprintf (stderr, "header magic bad\n");
		return NULL;
	}

	/*
	 * The rest of the header.
	 */

	len = rec->h.len * BPW;
	if (len < sizeof (rec->h)) {
		fprintf (stderr, "header too short\n");
		return NULL;
	}
	len -= sizeof (rec->h);

	rec = realloc (rec, len);
	ret = do_read (fd, (void *)rec + sizeof (rec->h), vol_size, len);

	if (ret == len)
		return rec;
	if (ret == -1) {
		perror ("read");
		return NULL;
	}
	fprintf (stderr, "short read\n");
	return NULL;
}

/*
 * Switch to the next volume.
 */

static int
nextfile (const char *name, uint32_t *vol_size)
{
	union fs_rec *rec;
	int fd;

       	*vol_size = sizeof (rec);

	fd = open (name, O_RDONLY);
	if (fd == -1) {
		perror (name);
		return -1;
	}

	rec = readhdr (fd, NULL);
	if (rec == NULL) {
		fprintf (stderr, "FS_VOLUME header missing\n");
		goto error;
	}
	if (rec->h.type != FS_VOLUME) {
		fprintf (stderr, "expected FS_VOLUME\n");
		goto error;
	}

	*vol_size = (rec->v.numwds - rec->h.len) * BPW;

	free (rec);
	return fd;
error:
	free (rec);
	close (fd);
	return -1;
}

/*
 * Reliable read, possibly across volumes.
 */

static int
read_vol (int argc, const char *argv[], int *file, int *fd,
	void *buf, uint32_t *vol_size, size_t len)
{
	int ret;

	while (1) {
		ret = do_read (*fd, buf, vol_size, len);
		if (ret == -1)
			return -1;
		if (ret == len)
			return 0;
		buf += ret;
		len -= ret;

		/*
		 * Next volume.
		 */

		close (*fd);
		if (*file == argc) {
			fprintf (stderr, "Expected another volume\n");
			return -1;
		}
		*fd = nextfile (argv[ (*file)++], vol_size);
		if (*fd == -1)
			return -1;
	}
}

static int
do_write (int fd, void *buf, size_t len)
{
	int bytes = 0;
	int ret;

	while (len) {
		ret = write (fd, buf, len);
		if (len == -1)
			return -1;
		if (ret == 0)
			return -1;
		bytes += ret;
		len -= ret;
	}

	return bytes;
}

static int
copyfd (int argc, const char *argv[], int *file, int *from,
	int to, uint32_t *vol_size, size_t size)
{
	int read_size = (size + 7) & ~0x7;
	uint8_t buf[1024];
	int bytes = 0;
	int to_read;
	int to_write;
	int ret;

	do {
		to_read = read_size < sizeof (buf) ? read_size : sizeof (buf);
		ret = read_vol (argc, argv, file, from, buf, vol_size, to_read);
		if (ret == -1)
			return ret;
		read_size -= to_read;

		to_write = size < to_read ? size : to_read;
		ret = do_write (to, buf, to_write);
		if (ret == -1)
			return ret;

		size -= to_write;
		bytes += to_write;
		if (ret != to_write)
			break;
	} while (read_size);

	return bytes;
}

/*
 * Read a (64-bit) word.
 */

static uint64_t
readwd (int fd, uint32_t *vol_size)
{
	uint64_t word;
	int ret;

	ret = do_read (fd, &word, vol_size, sizeof (word));
	switch (ret) {
	case sizeof (word):
		return word;
	case -1:
		perror ("read");
		return -1;
	default:
		fprintf (stderr, "short read\n");
		return -1;
	}	
}

struct dirent {
	uint16_t parent;
	struct {
		uint16_t ino;
		char name[14];
	} __attribute__ ((packed)) e;
};

static int
inodir (int root, struct dirent *ents, int ne, int ino)
{
	int parent;
	int fd;
	int i;

	/*
	 * Find parent.
	 */

	for (i = 0; i < ne; i++) {
		if (ents[i].e.ino == ino)
			break;
	}

	/*
	 * No parent -- root.
	 */

	if (i == ne)
		return dup (root);

	/*
	 * Recurse
	 */

	parent = inodir (root, ents, ne, ents[i].parent);
	if (parent == -1)
		return -1;
	fd = openat (parent, ents[i].e.name, 0);
	if (fd == -1)
		perror (ents[i].e.name);
	close (parent);
	return fd;
}

/*
 * Ensure the path exists, return the
 * handle to the last element.
 */

static int
namedir (int root, char **fn)
{
	int parent;
	int dir;
	char *p;

	dir = dup (root);
	if (dir == -1) {
		perror ("dup");
		return -1;
	}

	if (**fn == '/')
		(*fn)++;
	for (p = *fn; *p; p++) {
		if (*p == '/') {
			*p++ = '\0';
			mkdirat (dir, *fn, 0777);
			parent = dir;
			dir = openat (parent, *fn, 0);
			close (parent);
			if (!dir) {
				perror (*fn);
				return -1;
			}

			*fn = p;
		}
	}

	return dir;
}

/*
 * Process a FS_FILE or FS_INODE section.
 */

static int
do_file (int flags, int root, struct dirent **ents, int *ne,
	int argc, const char *argv[], int *file, int *fd,
	union fs_rec *rec, uint32_t *vol_size)
{
	char *fn;
	int out;
	int to_read;
	int ret;
	int nino;
	int mode;
	int dir = -1;

	to_read = rec->i.size;
	mode = rec->i.mode;

	if (flags & FSNAME) {
		fn = rec->n.name;
		dir = namedir (root, &fn);
		if (dir == -1)
			return -1;
	} else {
		if (*ne == 0) {
			if ((mode & S_IFMT) != S_IFDIR) {
				fprintf (stderr, "root not a directory\n");
				return -1;
			}
			fn = NULL;
		} else {
			for (nino = 0; nino < *ne; nino++) {
				if ((*ents)[nino].e.ino == rec->i.ino)
					break;
			}
			if (nino == *ne) {
				fprintf (stderr, "inode not found: %d\n", rec->i.ino);
				return -1;
			}
			fn = (*ents)[nino].e.name;

			dir = inodir (root, *ents, *ne, (*ents)[nino].parent);
			if (dir == -1)
				return -1;
		}
	}

	switch (mode & S_IFMT) {
		
	case S_IFCHR:
	case S_IFBLK:
		if (to_read != 0) {
			fprintf (stderr, "non-zero length device file\n");
			ret = -1;
			goto done;
		}

		ret = mknodat (dir, fn, mode, makedev (rec->i.rdevmaj, rec->i.rdevmin));
		if (ret == -1 && !((flags & UNPRIVED) && errno == EPERM)) {
			perror (fn);
			goto done;
		}

		break;


	case S_IFDIR:
		if (to_read && (flags & FSNAME)) {
			fprintf (stderr, "non-empty dir with FS_NAME\n");
			ret = -1;
			goto done;
		}

		/*
		 * Read and remember directory entries.
		 */

		while (to_read) {
			if (*ne % 64 == 0) {
				/*
				 * Allocate more dir entries.
				 */

				*ents = realloc (*ents, (*ne / 64 + 1) * 64 * sizeof (**ents));
				if (fn)
					fn = (*ents)[nino].e.name;
			}

			(*ents)[*ne].parent = rec->i.ino;
			ret = read_vol (argc, argv, file, fd,
					&(*ents)[*ne].e, vol_size, sizeof ((*ents)[0].e));
			if (ret == -1)
				goto done;
			to_read -= sizeof ((*ents)[0].e);

			if (strcmp ((*ents)[*ne].e.name, "..") && strcmp ((*ents)[*ne].e.name, "."))
				(*ne)++;
		}

		if (fn) {
			ret = mkdirat (dir, fn, mode);
			if (ret == -1) {
				perror (fn);
				goto done;
			}
		}

		break;

	default:
		out = openat (dir, fn, O_WRONLY | O_CREAT | O_TRUNC, mode);

		if (out == -1) {
			perror (fn);
			ret = out;
			goto done;
		}

		while (1) {
			/*
			 * Copy out the data bits.
			 */

			ret = copyfd (argc, argv, file, fd, out, vol_size, to_read);
			if (ret == -1)
				goto done;
			to_read -= ret;
			if (!to_read)
				break;
		}
		close (out);
	}

	if (fn) {
		struct timespec times[2] = { 0, };
		times[0].tv_sec = rec->i.atime;
		times[1].tv_sec = rec->i.mtime;

       		ret = utimensat (dir, fn, times, AT_SYMLINK_NOFOLLOW);
		if (ret == -1 && !((flags & UNPRIVED) && errno == ENOENT)) {
			perror (fn);
			goto done;
		}

		ret = fchownat (dir, fn, rec->i.uid, rec->i.gid, AT_SYMLINK_NOFOLLOW);
		if (ret == -1 && !((flags & UNPRIVED) && errno == ENOENT) && !((flags & UNPRIVED) && errno == EPERM)) {
			perror (fn);
			goto done;
		}
	}

	/*
	 * TODO: hard links.
	 */

	ret = 0;
done:
	if (dir != -1)
		close (dir);
	return ret;
}

int
main (int argc, const char *argv[])
{
	struct dirent *ents = NULL;
	int ne = 0;
	union fs_rec *rec;
	uint32_t vol_size;
	int flags = 0;
	int nextarg;
	int root = -1;
	int ret;
	int fd;
	int i;

	for (nextarg = 1; nextarg < argc; nextarg++) {
		if (argv[nextarg][0] != '-')
			break;
		if (strcmp (argv[nextarg], "--") == 0) {
			nextarg++;
			break;
		}
		for (i = 1; argv[nextarg][i]; i++) {
			switch (argv[nextarg][i]) {
			case 'u':
				flags |= UNPRIVED;
				break;
			case 'C':
				i++;
				if (argv[nextarg][i] == '\0') {
					i = 0;
					nextarg++;
				}
				if (nextarg == argc) {
					fprintf (stderr, "-C needs an argument\n");
					return 1;
				}
				if (root != -1) {
					fprintf (stderr, "-C already specified\n");
					return 1;
				}
				root = open (&argv[nextarg][i], 0);
				if (root == -1) {
					perror (&argv[nextarg][i]);
					return 1;
				}
				i = 0;
				break;
			default:
				fprintf (stderr, "Bad argument\n");
				return 1;
			}
			if (i == 0)
				break;
		}
	}

	if (root == -1)
		root = open (".", 0);
	if (root == -1) {
		perror (".");
		return 1;
	}

	if (argc <= nextarg) {
		fprintf (stderr, "Usage: %s [-u] [-C <dir>] <file> [...]\n", argv[0]);
		return 1;
	}

	/*
	 * Open the first file.
	 */

	fd = nextfile (argv[nextarg++], &vol_size);
	if (fd == -1)
		return 1;

	while (1) {
		rec = readhdr (fd, &vol_size);
		if (rec == NULL)
			return 1;

		switch (rec->h.type) {
		case FS_BITS:
			/* Not sure what are these for. */
			for (i = 0; i < rec->b.nwds; i++)
				readwd (fd, &vol_size);
			break;
		case FS_FINDEX:
			/* Not sure what is this for. */
			break;
		case FS_END:
			close (fd);
			return 0;
		case FS_INODE:
			ret = do_file (flags, root, &ents, &ne, argc, argv,
					&nextarg, &fd, rec, &vol_size);
			if (ret == -1)
				return 1;
			break;
		case FS_NAME:
			ret = do_file (flags | FSNAME, root, &ents, &ne, argc, argv,
					&nextarg, &fd, rec, &vol_size);
			if (ret == -1)
				return 1;
			break;
		default:
			fprintf (stderr, "unexpected section %d\n", rec->h.type);
			return 1;
		}
		free (rec);
	}
}
