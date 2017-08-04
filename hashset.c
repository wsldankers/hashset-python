#include <fcntl.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "Python.h"
#include "pythread.h"

typedef struct HashSet {
	PyObject_HEAD
	void *buf;
	char *filename;
	size_t size;
	size_t mapsize;
	size_t hashlen;
} HashSet_t;

typedef struct HashSetIterator {
	PyObject_HEAD
	HashSet_t *hs;
	size_t off;
} HashSetIterator_t;

typedef struct hash_merge_source {
	HashSet_t *hs;
	char *buf;
	size_t off;
	size_t end;
} hash_merge_source_t;
static const hashmerge_source_t hashmerge_source_0;

typedef struct hash_merge_state {
	off_t written;
	hash_merge_source_t *sources;
	hash_merge_source_t **queue;
	char *buf;
	const char *filename;
	size_t fill;
	size_t numsources;
	size_t queuelen;
	size_t hashlen;
	int fd;
} hash_merge_state_t;
static const hashmerge_state_t hashmerge_state_0 = {.fd = -1, .buf = MAP_FAILED};

#define MERGEBUFSIZE (1 << 21)

static uint64_t msb64(const uint8_t *bytes) {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	return *(const uint64_t *)bytes;
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#ifdef __GNUC__
	return __builtin_bswap64(*(const uint64_t *)bytes);
#else
	uint64_t r = *(const uint64_t *)bytes;
	r = ((r & UINT64_C(0x00FF00FF00FF00FF)) << 8) | ((r & UINT64_C(0xFF00FF00FF00FF00)) >> 8);
	r = ((r & UINT64_C(0x0000FFFF0000FFFF)) << 16) | ((r & UINT64_C(0xFFFF0000FFFF0000)) >> 16);
	return (r << 32) | (r >> 32);
#endif
#else
	return ((uint64_t)bytes[0] << 56)
		| ((uint64_t)bytes[1] << 48)
		| ((uint64_t)bytes[2] << 40)
		| ((uint64_t)bytes[3] << 32)
		| ((uint64_t)bytes[4] << 24)
		| ((uint64_t)bytes[5] << 16)
		| ((uint64_t)bytes[6] << 8)
		| ((uint64_t)bytes[7]);
#endif
}

static bool dedup(HashSet_t *hs) {
	size_t hashlen = hs->hashlen;
	uint8_t *buf = hs->buf;
	uint8_t *dst = buf + hashlen;
	const uint8_t *prv = buf;
	const uint8_t *src = buf + hashlen;
	const uint8_t *end = buf + hs->size;

	if(!hashlen)
		return PyErr_BadInternalCall("internal error: hashlen==0 in dedup()"), false;

	if(!hs->size)
		return;

	while(src < end) {
		if(memcmp(prv, src, hashlen)) {
			if(src != dst)
				memcpy(dst, src, hashlen);
			dst += hashlen;
		}
		prv = src;
		src += hashlen;
	}

	hs->size = dst - buf;

	return true;
}

static uint64_t guess(uint64_t lower, uint64_t upper, uint64_t lower_hash, uint64_t upper_hash, uint64_t target) {
#ifdef __SIZEOF_INT128__
	unsigned __int128 res, diff;
	uint64_t num, off, ret;
	num = upper - lower;
	diff = upper_hash - lower_hash;
	diff += 1;
	off = target - lower_hash;
	res = off;
	res *= num;
	res /= diff;
	ret = (uint64_t)res;
	return ret + lower;
#else
	uint64_t ret, num, prec, div, half;
	num = upper - lower;
	prec = UINT64_MAX / num;
	div = UINT64_MAX / prec + 1;
	half = num / prec / 2;
	/* warn("\rdiv=%"PRIu64"\033[K", div); */
	ret = lower + ((target - lower_hash) / div) * num / ((upper_hash - lower_hash) / div + 1) + half;
	if(ret >= upper)
		ret = upper - 1;
	if(ret < lower)
		ret = lower;
	return ret;
#endif
}

static bool exists_ge(const HashSet_t *hs, const void *key, size_t len, uint64_t *retp) {
	const uint8_t *buf, *cur_buf;
	uint64_t lower, upper, cur, lower_hash, upper_hash, target;
	int d;

	if(len != hs->hashlen)
		return PyExc_Format(PyExc_ValueError, "key does not have the configured length (%ld != %ld) ", (long int)len, (long int)hs->hashlen), false;
	if(len < 8)
		return PyExc_Format(PyExc_ValueError, "key too small (%ld < 8) ", (long int)len), false;
	if(hs->size % len)
		return PyExc_Format(PyExc_ValueError, "hashset size (%ld) is not a multiple of key length (%ld)", (long int)hs->size, (long int)len), false;

	upper = hs->size / len;
	if(!upper)
		return *retp = 0, true;

	buf = hs->buf;
	lower = 0;
	lower_hash = 0;
	upper_hash = UINT64_MAX;
	target = msb64(key);

	for(;;) {
		cur = lower_hash == upper_hash
			? lower + (upper - lower) / 2
			: guess(lower, upper, lower_hash, upper_hash, target);
		/* warn("\rguess=%"PRIu64" lower=%"PRIu64" upper=%"PRIu64" lower_hash=0x%016"PRIu64" upper_hash=0x%016"PRIx64" target=%016"PRIx64"\033[K", cur, lower, upper, lower_hash, upper_hash, target); */
		/* if(cur < lower) croak("cur < lower"); */
		/* if(cur >= upper) croak("cur >= upper"); */
		cur_buf = buf + cur * len;
		d = memcmp(cur_buf, key, len);
		if(d == 0) {
			break;
		} else if(d < 0) {
			lower = cur + 1;
			lower_hash = msb64(cur_buf);
		} else {
			upper = cur;
			upper_hash = msb64(cur_buf);
		}
		if(lower == upper)
			break;
	}

	*retp = cur * (uint64_t)len;
	return true;
}

static bool HashSet_exists(const HashSet_t *hs, const void *key, size_t len, bool *retp) {
	uint64_t off;
	if(!hs->size)
		return *retp = false, true;
	if(!exists_ge(hs, key, len, &off))
		return false;
	*retp = !memcmp((const char *)hs->buf + off, key, len);
	return true;
}

static void queue_update_up(hash_merge_state_t *state, size_t i) {
	size_t i1, i2;
	hash_merge_source_t *s, *s1, *s2;
	const char *a, *a1, *a2;
	hash_merge_source_t **queue = state->queue;
	size_t queuelen = state->queuelen;
	size_t hashlen = state->hashlen;

	s = queue[i];
	a = s->buf + s->off;

	/* bubble up */
	for(;;) {
		i1 = i * 2 + 1;
		if(i1 >= queuelen)
			break;
		s1 = queue[i1];
		a1 = s1->buf + s1->off;

		i2 = i1 + 1;
		if(i2 < queuelen) {
			s2 = queue[i2];
			a2 = s2->buf + s2->off;
			if(memcmp(a2, a1, hashlen) < 0) {
				i1 = i2;
				s1 = s2;
				a1 = a2;
			}
		}

		if(memcmp(a1, a, hashlen) < 0) {
			queue[i] = s1;
			queue[i1] = s;
			i = i1;
		} else {
			break;
		}
	}
}

static void queue_init(hash_merge_state_t *state) {
	size_t i = i = state->queuelen / 2;

	do queue_update_up(state, i);
		while(i--);
}

__attribute__((unused))
static void queue_update(hash_merge_state_t *state, size_t i) {
	size_t i1;
	hash_merge_source_t *s, *s1;
	const char *a, *a1;
	hash_merge_source_t **queue = state->queue;
	size_t queuelen = state->queuelen;
	size_t hashlen = state->hashlen;

	s = queue[i];
	a = s->buf + s->off;
	i1 = queuelen;

	/* bubble down */
	while(i) {
		i1 = (i - 1) / 2;
		s1 = queue[i1];
		a1 = s1->buf + s1->off;
		if(memcmp(a, a1, hashlen) < 0) {
			queue[i] = s1;
			queue[i1] = s;
			i = i1;
		} else {
			break;
		}
	}

	if(i != i1)
		queue_update_up(state, i);
}

static bool safewrite(hash_merge_state_t *state) {
	ssize_t r;
	state->written += state->fill;
	const char *buf = state->buf;
	while(state->fill) {
		r = write(state->fd, buf, state->fill);
		switch(r) {
			case -1:
				return PyErr_SetFromErrnoWithFilename(PyExc_OsErr, state->filename), false;
			case 0:
				return PyErr_Format(PyExc_OsErr, "write(%s): Returned 0", state->filename), false;
		}
		buf += (size_t)r;
		state->fill -= (size_t)r;
	}
	return true;
}

static bool merge_do(hash_merge_state_t *state, const char *destination, HashSet_t **sources, size_t numsources) {
	size_t i;
	HashSet_t *hs;
	hash_merge_source_t *src;
	char *last;
	int fd;
	size_t hashlen = 0;

	if(numsources) {
		state->hashlen = hashlen = sources[0]->hashlen;

		if(MERGEBUFSIZE % hashlen)
			return PyErr_Format(PyExc_ValueError, "buffer length (%d) is not a multiple of hash length (%d)", (int)MERGEBUFSIZE, (int)hashlen), false;

#ifdef MAP_HUGETLB
		state->buf = mmap(NULL, MERGEBUFSIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_HUGETLB, -1, 0);
		if(state->buf == MAP_FAILED)
#endif
		state->buf = mmap(NULL, MERGEBUFSIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
		if(state->buf == MAP_FAILED)
			return PyErr_SetFromErrno(Py_OsErr), false;
	}

	fd = state->fd = open(destination, O_WRONLY|O_CREAT|O_NOCTTY|O_LARGEFILE, 0666);
	if(fd == -1)
		return PyErr_SetFromErrnoWithFilename(PyExc_OsErr, destination), false;
	state->filename = destination;

	state->queue = malloc(numsources * sizeof *state->queue);
	if(!state->queue)
		return PyErr_NoMemory();

	state->sources = malloc(numsources * sizeof *state->sources);
	if(!state->sources)
		return PyErr_NoMemory();

	for(i = 0; i < numsources; i++)
		state->sources[i] = hash_merge_source_0;
	state->numsources = numsources;

	for(i = 0; i < numsources; i++) {
		hs = sources[i];
		src = state->sources + i;
		src->hs = hs;
		src->buf = hs->buf;
		src->end = hs->size;
		if(hs->hashlen != hashlen)
			return PyErr_Format(PyExc_ValueError, "input object has a different hash length"), false;
		if(src->end)
			state->queue[state->queuelen++] = src;
	}

	if(state->queuelen) {
		queue_init(state);
		src = state->queue[0];
	}

	while(state->queuelen) {
		last = state->buf + state->fill;
		memcpy(last, src->buf + src->off, hashlen);
		state->fill += hashlen;
		src->off += hashlen;
		if(src->off == src->end) {
			if(!--state->queuelen)
				break;
			state->queue[0] = state->queue[state->queuelen];
		}
		/* skip duplicate hashes */
		for(;;) {
			queue_update_up(state, 0);
			src = state->queue[0];
			if(memcmp(last, src->buf + src->off, hashlen))
				break;
			src->off += hashlen;
			if(src->off == src->end) {
				if(!--state->queuelen)
					break;
				state->queue[0] = state->queue[state->queuelen];
			}
		}
		if(state->fill == MERGEBUFSIZE && !safewrite(state))
			return false;
	}

	if(state->fill && !safewrite(state))
		return false;

	if(ftruncate(fd, state->written) == -1)
		return PyErr_SetFromErrnoWithFilename(PyExc_OsErr, destination), false;

	if(fdatasync(fd) == -1)
		return PyErr_SetFromErrnoWithFilename(PyExc_OsErr, destination), false;

	state->fd = -1;
	if(close(fd) == -1)
		return PyErr_SetFromErrnoWithFilename(PyExc_OsErr, destination), false;

	return true;
}

static void merge_cleanup(hash_merge_state_t *state) {
	free(state->sources);
	free(state->queue);
	if(state->fd != -1)
		close(state->fd);
	if(state->buf != MAP_FAILED)
		munmap(state->buf, MERGEBUFSIZE);
	*state = hash_merge_state_0;
	Safefree(state);
}

static void close_fd_ptr(int *fdp) {
	if(*fdp != -1)
		close(*fdp);
	*fdp = -1;
	Safefree(fdp);
}

static int HashSet_free(pTHX_ SV *sv PERL_UNUSED_DECL, MAGIC *mg) {
	HashSet_t *obj = (void *)SvPV_nolen(mg->mg_obj);
	if(obj) {
		if(obj->buf != MAP_FAILED)
			munmap(obj->buf, obj->mapsize);
		free(obj->filename);
		*obj = HashSet_0;
	}
	SvREFCNT_dec(mg->mg_obj);
	return 0;
}

static int HashSetIterator_free(pTHX_ SV *sv PERL_UNUSED_DECL, MAGIC *mg) {
	HashSetIterator_t *obj = (void *)SvPV_nolen(mg->mg_obj);
	if(obj) {
		if(obj->HashSet)
			SvREFCNT_dec(obj->HashSet);
		*obj = HashSetIterator_0;
	}
	SvREFCNT_dec(mg->mg_obj);
	return 0;
}

MODULE = File::Hashset  PACKAGE = File::Hashset

PROTOTYPES: ENABLE

void
sortfile(const char *class, const char *filename, size_t hashlen)
PREINIT:
	int (*cmp)(const void *, const void *);
	HashSet_t hs = HashSet_0;
	int *fd_ptr;
	int err;
	struct stat st;
PPCODE:
	PERL_UNUSED_ARG(class);

	cmp = hashcmp(hashlen);
	if(!cmp)
		croak("File::Hashset::sortfile: unsupported hash length (%d)", hashlen);

	Newx(fd_ptr, 1, int);
	SAVEDESTRUCTOR(close_fd_ptr, fd_ptr);

	*fd_ptr = open(filename, O_RDWR|O_NOCTTY|O_LARGEFILE);
	if(*fd_ptr == -1)
		croak("open(%s): %s", filename, strerror(errno));

	if(fstat(*fd_ptr, &st) == -1)
		croak("stat(%s): %s", filename, strerror(errno));

	if(st.st_size % hashlen)
		croak("File::Hashset::sortfile(%s): file size (%ld) is not a multiple of the key length (%d)", filename, (long int)st.st_size, hashlen);

	if(st.st_size <= (off_t)hashlen)
		return;

	hs.buf = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, *fd_ptr, 0);
	if(hs.buf == MAP_FAILED)
		croak("mmap(%s): %s", filename, strerror(errno));

	hs.size = hs.mapsize = st.st_size;
	hs.hashlen = hashlen;
	qsort(hs.buf, hs.size / hashlen, hashlen, cmp);
	dedup(&hs);

	if(msync(hs.buf, hs.mapsize, MS_SYNC) == -1) {
		err = errno;
		munmap(hs.buf, hs.mapsize);
		croak("msync(%s, MS_SYNC): %s", filename, strerror(err));
	}

	if(munmap(hs.buf, hs.mapsize) == -1)
		croak("munmap(%s): %s", filename, strerror(errno));

	if(hs.size != hs.mapsize && ftruncate(*fd_ptr, hs.size) == -1)
		croak("ftruncate(%s, %ld): %s", filename, (long int)hs.size, strerror(errno));

	err = close(*fd_ptr);
	*fd_ptr = -1;
	if(err == -1)
		croak("close(%s): %s", filename, strerror(errno));

	XSRETURN_EMPTY;

void
merge(const char *class, const char *destination, ...)
PREINIT:
	int i;
	HashSet_t **sources;
	int numsources;
	hash_merge_state_t *state;
PPCODE:
	PERL_UNUSED_ARG(class);

	numsources = items - 2;

	//warn("merge(%s, %d)", destination, numsources);

	Newx(sources, numsources, HashSet_t *);
	SAVEFREEPV(sources);

	for(i = 0; i < numsources; i++) {
		sources[i] = find_magic(ST(i + 2), &HashSet_vtable);
		if(!sources[i])
			croak("invalid File::Hashset object");
		if(sources[i]->hashlen != sources[0]->hashlen)
			croak("attempt to merge File::Hashset objects with differing hashlen");
	}

	Newx(state, 1, hash_merge_state_t);
	SAVEDESTRUCTOR(merge_cleanup, state);
	*state = hash_merge_state_0;

	merge_do(state, destination, sources, numsources);

	XSRETURN_EMPTY;

SV *
new(const char *class, SV *string_sv, size_t hashlen)
PREINIT:
	HV *hash;
	HashSet_t hs = HashSet_0;
	const char *string;
	STRLEN len;
	int (*cmp)(const void *, const void *);
CODE:
	cmp = hashcmp(hashlen);
	if(!cmp)
		croak("File::Hashset::new: unsupported hash length (%d)", hashlen);

	hs.hashlen = hashlen;

	if(SvUTF8(string_sv))
		croak("attempt to use an UTF-8 string as a hash buffer");
	string = SvPV(string_sv, len);
	if(len % hashlen)
		croak("File::Hashset::new: string size (%ld) is not a multiple of the key length (%d)", (long int)len, hashlen);

	if(len) {
		hs.buf = mmap(NULL, (size_t)len, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
		if(hs.buf == MAP_FAILED)
			croak("mmap(): %s", strerror(errno));
		memcpy(hs.buf, string, len);
		qsort(hs.buf, len / hashlen, hashlen, cmp);
		hs.size = hs.mapsize = len;
		dedup(&hs);
	}

	hash = newHV();
	attach_magic((SV *)hash, &HashSet_vtable, "HashSet", &hs, sizeof hs);
	RETVAL = sv_bless(newRV_noinc((SV *)hash), gv_stashpv(class, 0));
OUTPUT:
	RETVAL

SV *
load(const char *class, const char *filename, size_t hashlen)
PREINIT:
	HV *hash;
	HashSet_t hs = HashSet_0;
	int *fd_ptr;
	int err;
	struct stat st;
CODE:
	//warn("load(%s)", filename);
	if(!hashcmp(hashlen))
		croak("File::Hashset::open: unsupported hash length (%d)", hashlen);
	hs.hashlen = hashlen;

	Newx(fd_ptr, 1, int);
	SAVEDESTRUCTOR(close_fd_ptr, fd_ptr);

	*fd_ptr = open(filename, O_RDONLY|O_NOCTTY|O_LARGEFILE);
	if(*fd_ptr == -1)
		croak("open(%s): %s", filename, strerror(errno));

	if(fstat(*fd_ptr, &st) == -1)
		croak("stat(%s): %s", filename, strerror(errno));

	if(st.st_size % hashlen)
		croak("File::Hashset::load(%s): file size (%ld) is not a multiple of the specified hashlen (%d)", filename, (long int)st.st_size, hashlen);

	if(st.st_size) {
		hs.buf = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, *fd_ptr, 0);
		err = errno;
		if(hs.buf == MAP_FAILED)
			croak("mmap(%s): %s", filename, strerror(err));
	}
	hs.size = hs.mapsize = st.st_size;

	if(st.st_size) {
		madvise(hs.buf, hs.mapsize, MADV_WILLNEED);
#ifdef MADV_UNMERGEABLE
		madvise(hs.buf, hs.mapsize, MADV_UNMERGEABLE);
#endif
	}
	hs.filename = strdup(filename);

	hash = newHV();
	attach_magic((SV *)hash, &HashSet_vtable, "HashSet", &hs, sizeof hs);
	RETVAL = sv_bless(newRV_noinc((SV *)hash), gv_stashpv(class, 0));
OUTPUT:
	RETVAL

void
exists(SV *self, SV *key)
PREINIT:
	HashSet_t *hs;
	const char *k;
	STRLEN len;
PPCODE:
	hs = find_magic(self, &HashSet_vtable);
	if(!hs)
		croak("Invalid File::Hashset object");

	k = SvPV(key, len);
	if(HashSet_exists(hs, k, len))
		XSRETURN_YES;
	else
		XSRETURN_NO;

SV *
iterator(SV *self, SV *key = NULL)
PREINIT:
	HashSet_t *hs;
	HashSetIterator_t c;
	HV *hash;
	const char *k;
	STRLEN len;
CODE:
	hs = find_magic(self, &HashSet_vtable);
	if(!hs)
		croak("Invalid File::Hashset object");

	c.HashSet = SvRV(self);
	c.hs = hs;
	if(key) {
		k = SvPV(key, len);
		c.off = exists_ge(hs, k, len);
	} else {
		c.off = 0;
	}

	hash = newHV();
	attach_magic((SV *)hash, &HashSetIterator_vtable, "HashSetIterator", &c, sizeof c);
	RETVAL = sv_bless(newRV_noinc((SV *)hash), gv_stashpv("File::Hashset::Cursor", 0));
	SvREFCNT_inc(c.HashSet);
OUTPUT:
	RETVAL

MODULE = File::Hashset  PACKAGE = File::Hashset::Cursor

void
fetch(SV *self)
PREINIT:
	HashSet_t *hs;
	HashSetIterator_t *c;
PPCODE:
	c = find_magic(self, &HashSetIterator_vtable);
	if(!c)
		croak("invalid File::Hashset::Cursor object");

	hs = c->hs;
	if(!hs)
		croak("invalid File::Hashset::Cursor object");
	if(c->off >= hs->size) {
		c->off = 0;
		XSRETURN_UNDEF;
	} else {
		mXPUSHp((const char *)hs->buf + c->off, hs->hashlen);
		c->off += hs->hashlen;
		XSRETURN(1);
	}
