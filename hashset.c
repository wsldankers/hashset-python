#include <fcntl.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define PY_SSIZE_T_CLEAN

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
	PyObjects *filename_obj;
	size_t fill;
	size_t numsources;
	size_t queuelen;
	size_t hashlen;
	int fd;
} hash_merge_state_t;
static const hashmerge_state_t hashmerge_state_0 = {.fd = -1, .buf = MAP_FAILED};

#define MERGEBUFSIZE (1 << 21)
#define OK (!PyErr_Occurred())
#define RETURN_IF_OK(x) return PyErr_Occurred() ? NULL : (x)
#define RETURN_NONE_IF_OK RETURN_IF_OK((Py_INCREF(Py_None), Py_None))

static PyObject *hashset_module_filename(PyObject *filename_object) {
	PyObject *decoded_filename;
	if(PyUnicode_Check(filename_object)) {
		if(PyUnicode_FSConverter(filename_object, &decoded_filename))
			return decoded_filename;
		else
			return NULL;
	} else if(PyBytes_Check(filename_object)) {
		Py_IncRef(filename_object);
		return filename_object;
	} else {
		return PyBytes_FromObject(filename_object);
	}
}

static bool hashset_module_object_to_buffer(PyObject *obj, Py_buffer *buffer) {
	Py_ssize_t len;

	if(PyUnicode_Check(obj)) {
		return PyErr_SetString(PyExc_BufferError, "str is not suitable for storing bytes"), false;
	} else {
		if(PyObject_GetBuffer(obj, buffer, PyBUF_SIMPLE) == -1)
			return false;

		if(!PyBuffer_IsContiguous(buffer, 'C')) {
			PyBuffer_Release(buffer);
			return PyErr_SetString(PyExc_BufferError, "buffer not contiguous"), false;
		}
	}

	return true;
}


static uint64_t msb64(const uint8_t *bytes, size_t len) {
	uint8_t buf[8];
	if(len < 8) {
		for(i = 0; i < 8; i++)
			buf[i] = bytes[i % len];
		bytes = buf;
	}
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
	target = msb64(key, len);

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
			lower_hash = msb64(cur_buf, len);
		} else {
			upper = cur;
			upper_hash = msb64(cur_buf, len);
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
		return PyErr_NoMemory(), false;

	state->sources = malloc(numsources * sizeof *state->sources);
	if(!state->sources)
		return PyErr_NoMemory(), false;

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
	Py_DecRef(state->filename_obj);

	*state = hash_merge_state_0;
}

static int HashSet_free(HashSet_t *obj) {
	PyObject *filename;

	if(obj->buf != MAP_FAILED)
		munmap(obj->buf, obj->mapsize);
	obj->buf = MAP_FAILED;

	free(obj->filename);
	*obj->filename = NULL;

	Py_CLEAR(obj->filename_obj);

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

PyObject *HashSet_sortfile(const char *class, const char *filename, size_t hashlen)
	int fd;
	struct stat st;
	HashSet_t hs = HashSet_0;

	if(!OK)
		return false;

	if(!hashlen)
		return PyErr_Format(PyExc_ValueError, "HashSet.sortfile(%s): hash length must not be 0", filename), false;

	fd = open(filename, O_RDWR|O_NOCTTY|O_LARGEFILE);
	if(fd == -1)
		return PyErr_SetFromErrnoWithFilename(PyExc_OsErr, filename), false;

	/* we have an open fd now, so we can't just return wantonly */

	if(fstat(fd, &st) == -1)
		PyErr_SetFromErrnoWithFilename(PyExc_OsErr, filename);

	if(OK && st.st_size % hashlen)
		PyErr_Format(PyExc_ValueError, "HashSet.sortfile(%s): file size (%ld) is not a multiple of the key length (%d)", filename, (long int)st.st_size, hashlen);

	if(OK && st.st_size > (off_t)hashlen) {
		hs.buf = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
		if(hs.buf == MAP_FAILED) {
			PyErr_SetFromErrnoWithFilename(PyExc_OsErr, filename);
		} else {
			hs.size = hs.mapsize = st.st_size;
			hs.hashlen = hashlen;
			qsort_lr(hs.buf, hs.size / hashlen, hashlen, memcmp, NULL);
			dedup(&hs);

			if(msync(hs.buf, hs.mapsize, MS_SYNC) == -1)
				PyErr_SetFromErrnoWithFilename(PyExc_OsErr, filename);

			if(munmap(hs.buf, hs.mapsize) == -1 && OK)
				PyErr_SetFromErrnoWithFilename(PyExc_OsErr, filename);

			if(OK && hs.size != hs.mapsize && ftruncate(fd, hs.size) == -1)
				PyErr_SetFromErrnoWithFilename(PyExc_OsErr, filename);
		}
	}

	if(close(fd) == -1 && OK)
		PyErr_SetFromErrnoWithFilename(PyExc_OsErr, filename);

	RETURN_NONE_IF_OK;
}

PyObject *HashSet_merge(PyObject *class, PyObject *args) {
	hash_merge_state_t state = hash_merge_state_0;
	int i;

	if(!OK)
		return NULL;

	if(!PyTuple_Check(args))
		return PyErr_SetString(PyExc_SystemError, "HashSet.merge: new style getargs format but argument is not a tuple");

	state.numsources = PyTuple_GET_SIZE(args) - 1;
	if(state.numsources < 0)
		return PyErr_SetString(PyExc_TypeError, "HashSet.merge: needs at least 1 argument (0 given)");

	if(!PyUnicode_FSConverter(PyTuple_GET_ITEM(args, 0), &state.filename_obj))
		return NULL;

	state.filename = PyBytes_AsString(state.filename_obj);
	if(state.filename) {
		state.sources = malloc(state.numsources * sizeof *state.sources);
		if(state.sources) {
			for(i = 0; i < state.numsources; i++) {
				state.sources[i] = HashSet_Check(PyTuple_GET_ITEM(args, i + 1));
				if(!state.sources[i])
					break;
				if(state.sources[i]->hashlen != state.sources[0]->hashlen) {
					PyErr_SetString(PyExc_SystemError, "HashSet.merge: objects with differing hashlen (%d, %d)",
						state.sources[0]->hashlen, state.sources[i]->hashlen);
					break;
				}
			}

			if(OK)
				merge_do(&state);
		} else {
			PyErr_SetString(PyExc_TypeError, "HashSet.merge: out of memory");
		}
	}

	merge_cleanup(&state);

	RETURN_NONE_IF_OK;
}

PyObject *HashSet_new(PyTypeObject *subtype, PyObject *args, PyObject *kwargs) {
	HashSet_t *hs;
	const char *bytes;
	Py_ssize_t len;
	Py_ssize_t hashlen;

	if(!OK)
		return NULL;

	PyArg_ParseTuple(args, "y#n:HashSet.new", &bytes, &len, &hashlen);

	if(hashlen < 1)
		return PyErr_Format(PyExc_ValueError, "HashSet.new: hash length (%z) must be larger than 0", hashlen);

	if(len % hashlen)
		return PyErr_Format(PyExc_ValueError, "HashSet.new: buffer size (%d) is not a multiple of the key length (%z)", len, hashlen);

	hs = PyObject_New(HashSet_t, subtype);
	if(hs) {
		hs->hashlen = (size_t)hashlen;

		if(len) {
			hs->buf = mmap(NULL, (size_t)len, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
			if(hs->buf == MAP_FAILED) {
				PyErr_SetFromErrno(PyExc_OsErr);
			} else {
				hs->size = hs->mapsize = len;
				memcpy(hs->buf, bytes, len);
				qsort_lr(hs->buf, len / hashlen, hashlen, memcmp, NULL);
				dedup(hs);
				return &hs->ob_base;
			}
		}

		PyObject_Del(&hs->ob_base);
	}

	return NULL;
}

PyObject *load(PyObject *class, const char *filename, size_t hashlen) {
	HashSet_t *hs;
	int fd;
	struct stat st;

	if(!OK)
		return NULL;

	if(!hashlen)
		croak("HashSet.open: unsupported hash length (%d)", hashlen);
	hs.hashlen = hashlen;

	fd = open(filename, O_RDONLY|O_NOCTTY|O_LARGEFILE);
	if(fd == -1)
		return PyErr_SetFromErrnoWithFilename(PyExc_OsErr, filename);

	if(fstat(fd, &st) == -1) {
		PyErr_SetFromErrnoWithFilename(PyExc_OsErr, filename);
	} else {
		if(st.st_size % hashlen)
			PyErr_Format(PyExc_ValueError, "HashSet.load(%s): file size (%d) is not a multiple of the key length (%z)", filename, (long int)st.st_size, hashlen);

		if(st.st_size) {
			hs.buf = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, *fd_ptr, 0);
			if(hs.buf == MAP_FAILED)
				return PyErr_SetFromErrnoWithFilename(PyExc_OsErr, filename);
		}
		hs.size = hs.mapsize = st.st_size;

		if(st.st_size) {
			madvise(hs.buf, hs.mapsize, MADV_WILLNEED);
	#ifdef MADV_UNMERGEABLE
			madvise(hs.buf, hs.mapsize, MADV_UNMERGEABLE);
	#endif
		}
		hs.filename = strdup(filename);
	}

	if(close(fd) == -1)
		return PyErr_SetFromErrnoWithFilename(PyExc_OsErr, filename);

	RETURN_IF_OK(&hs->ob_base);
}

PyObject *HashSet_exists(HashSet_t *hs, PyObject *args)
	const char *key;
	Py_ssize_t len;
	bool res;

	if(!PyArg_ParseTuple(args, "y#:HashSet.exists", &key, &len))
		return NULL;

	if(!HashSet_exists(hs, key, len, &res))
		return NULL;

	if(res)
		Py_RETURN_TRUE;
	else
		Py_RETURN_FALSE;
}

PyObject *HashSet_iterator(HashSet_t *self, SV *key = NULL) {
	HashSet_t *hs;
	HashSetIterator_t c;
	HV *hash;
	const char *k;
	STRLEN len;

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
}

PyObject HashSetIterator_fetch(SV *self) {
	HashSet_t *hs;
	HashSetIterator_t *c;

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
}
