#define _LARGEFILE64_SOURCE 1

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

#ifndef O_LARGEFILE
#define O_LARGEFILE 0
#endif

typedef int (*qsort_lr_cmp)(const void *, const void *, size_t, void *);

extern void qsort_lr(void *const pbase, size_t total_elems, size_t size, qsort_lr_cmp, void *arg);

typedef struct Hashset {
	PyObject_HEAD
	uint64_t magic;
	void *buf;
	char *filename;
	PyObject *filename_obj;
	size_t size;
	size_t mapsize;
	size_t hashlen;
} Hashset_t;
static const Hashset_t Hashset_0 = {.buf = MAP_FAILED};

typedef struct HashsetIterator {
	PyObject_HEAD
	uint64_t magic;
	Hashset_t *hs;
	size_t off;
} HashsetIterator_t;

typedef struct hash_merge_source {
	char *buf;
	size_t off;
	size_t end;
	Hashset_t *hs;
} hash_merge_source_t;
static const hash_merge_source_t hash_merge_source_0;

typedef struct hash_merge_state {
	off_t written;
	hash_merge_source_t *sources;
	hash_merge_source_t **queue;
	char *buf;
	const char *filename;
	PyObject *filename_obj;
	size_t fill;
	size_t numsources;
	size_t queuelen;
	size_t hashlen;
	int fd;
} hash_merge_state_t;
static const hash_merge_state_t hash_merge_state_0 = {.fd = -1, .buf = MAP_FAILED};

static struct PyModuleDef hashset_module;
struct hashset_module_state {
	PyTypeObject *Hashset_type;
	PyTypeObject *HashsetIterator_type;
};

#define HASHSET_MAGIC UINT64_C(0xC63E9FDB3D336988)
#define HASHSET_ITERATOR_MAGIC UINT64_C(0x2BF1D59A332EF8E5)

#ifdef WITH_THREAD
#define DECLARE_THREAD_SAVE PyThreadState *_save;
#else
#define DECLARE_THREAD_SAVE
#endif

#define MERGEBUFSIZE (1 << 21)
#define OK (!PyErr_Occurred())
#define RETURN_IF_OK(x) return PyErr_Occurred() ? NULL : (x)
#define RETURN_NONE_IF_OK RETURN_IF_OK((Py_INCREF(Py_None), Py_None))

static inline Hashset_t *Hashset_Check(PyObject *v) {
	struct hashset_module_state *state = PyModule_GetState(PyState_FindModule(&hashset_module));
	if(v && Py_TYPE(v) == state->Hashset_type && ((Hashset_t *)v)->magic == HASHSET_MAGIC)
		return (Hashset_t *)v;
	PyErr_SetString(PyExc_SystemError, "invalid Hashset object in internal call");
	return NULL;
}

static inline HashsetIterator_t *HashsetIterator_Check(PyObject *v) {
	struct hashset_module_state *state = PyModule_GetState(PyState_FindModule(&hashset_module));
	if(v && Py_TYPE(v) == state->HashsetIterator_type && ((HashsetIterator_t *)v)->magic == HASHSET_ITERATOR_MAGIC)
		return (HashsetIterator_t *)v;
	PyErr_SetString(PyExc_SystemError, "invalid HashsetIterator object in internal call");
	return NULL;
}

__attribute__((unused))
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

__attribute__((unused))
static bool hashset_module_object_to_buffer(PyObject *obj, Py_buffer *buffer) {
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
	size_t i;
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

static void dedup(Hashset_t *hs) {
	size_t hashlen = hs->hashlen;
	uint8_t *buf = hs->buf;
	uint8_t *dst = buf + hashlen;
	const uint8_t *prv = buf;
	const uint8_t *src = buf + hashlen;
	const uint8_t *end = buf + hs->size;

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

	return;
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

static bool exists_ge(const Hashset_t *hs, const void *key, size_t len, uint64_t *retp) {
	const uint8_t *buf, *cur_buf;
	uint64_t lower, upper, cur, lower_hash, upper_hash, target;
	int d;

	if(len != hs->hashlen)
		return PyErr_Format(PyExc_ValueError, "key does not have the configured length (%ld != %ld) ", (long int)len, (long int)hs->hashlen), false;
	if(len < 8)
		return PyErr_Format(PyExc_ValueError, "key too small (%ld < 8) ", (long int)len), false;
	if(hs->size % len)
		return PyErr_Format(PyExc_ValueError, "hashset size (%ld) is not a multiple of key length (%ld)", (long int)hs->size, (long int)len), false;

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
				return PyErr_SetFromErrnoWithFilename(PyExc_OSError, state->filename), false;
			case 0:
				return PyErr_Format(PyExc_OSError, "write(%s): Returned 0", state->filename), false;
		}
		buf += (size_t)r;
		state->fill -= (size_t)r;
	}
	return true;
}

static bool merge_do(hash_merge_state_t *state) {
	size_t i;
	Hashset_t *hs;
	hash_merge_source_t *src;
	char *last;
	int fd;
	size_t hashlen = 0;

	if(state->numsources) {
		if(MERGEBUFSIZE % hashlen)
			return PyErr_Format(PyExc_ValueError, "buffer length (%d) is not a multiple of hash length (%d)", (int)MERGEBUFSIZE, (int)hashlen), false;

#ifdef MAP_HUGETLB
		state->buf = mmap(NULL, MERGEBUFSIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_HUGETLB, -1, 0);
		if(state->buf == MAP_FAILED)
#endif
		state->buf = mmap(NULL, MERGEBUFSIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
		if(state->buf == MAP_FAILED)
			return PyErr_SetFromErrno(PyExc_OSError), false;
	}

	fd = state->fd = open(state->filename, O_WRONLY|O_CREAT|O_NOCTTY|O_LARGEFILE, 0666);
	if(fd == -1)
		return PyErr_SetFromErrnoWithFilename(PyExc_OSError, state->filename), false;

	state->queue = malloc(state->numsources * sizeof *state->queue);
	if(!state->queue)
		return PyErr_NoMemory(), false;

	state->sources = malloc(state->numsources * sizeof *state->sources);
	if(!state->sources)
		return PyErr_NoMemory(), false;

	for(i = 0; i < state->numsources; i++)
		state->sources[i] = hash_merge_source_0;

	for(i = 0; i < state->numsources; i++) {
		src = state->sources + i;
		hs = src->hs;
		src->buf = hs->buf;
		src->end = hs->size;
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
		return PyErr_SetFromErrnoWithFilename(PyExc_OSError, state->filename), false;

	if(fdatasync(fd) == -1)
		return PyErr_SetFromErrnoWithFilename(PyExc_OSError, state->filename), false;

	state->fd = -1;
	if(close(fd) == -1)
		return PyErr_SetFromErrnoWithFilename(PyExc_OSError, state->filename), false;

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

static int Hashset_dealloc(Hashset_t *obj) {
	if(obj->buf != MAP_FAILED)
		munmap(obj->buf, obj->mapsize);
	obj->buf = MAP_FAILED;

	free(obj->filename);
	obj->filename = NULL;

	Py_CLEAR(obj->filename_obj);

	return 0;
}

PyObject *Hashset_sortfile(PyObject *class, const char *filename, size_t hashlen) {
	int fd;
	struct stat st;
	Hashset_t hs = Hashset_0;

	if(!OK)
		return NULL;

	if(!hashlen)
		return PyErr_Format(PyExc_ValueError, "Hashset.sortfile(%s): hash length must not be 0", filename), NULL;

	fd = open(filename, O_RDWR|O_NOCTTY|O_LARGEFILE);
	if(fd == -1)
		return PyErr_SetFromErrnoWithFilename(PyExc_OSError, filename), NULL;

	/* we have an open fd now, so we can't just return wantonly */

	if(fstat(fd, &st) == -1)
		PyErr_SetFromErrnoWithFilename(PyExc_OSError, filename);

	if(OK && st.st_size % hashlen)
		PyErr_Format(PyExc_ValueError, "Hashset.sortfile(%s): file size (%ld) is not a multiple of the key length (%d)", filename, (long int)st.st_size, hashlen);

	if(OK && st.st_size > (off_t)hashlen) {
		hs.buf = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
		if(hs.buf == MAP_FAILED) {
			PyErr_SetFromErrnoWithFilename(PyExc_OSError, filename);
		} else {
			hs.size = hs.mapsize = st.st_size;
			hs.hashlen = hashlen;
			qsort_lr(hs.buf, hs.size / hashlen, hashlen, (qsort_lr_cmp)memcmp, NULL);
			dedup(&hs);

			if(msync(hs.buf, hs.mapsize, MS_SYNC) == -1)
				PyErr_SetFromErrnoWithFilename(PyExc_OSError, filename);

			if(munmap(hs.buf, hs.mapsize) == -1 && OK)
				PyErr_SetFromErrnoWithFilename(PyExc_OSError, filename);

			if(OK && hs.size != hs.mapsize && ftruncate(fd, hs.size) == -1)
				PyErr_SetFromErrnoWithFilename(PyExc_OSError, filename);
		}
	}

	if(close(fd) == -1 && OK)
		PyErr_SetFromErrnoWithFilename(PyExc_OSError, filename);

	RETURN_NONE_IF_OK;
}

PyObject *Hashset_merge(PyObject *class, PyObject *args) {
	Hashset_t *hs;
	hash_merge_state_t state = hash_merge_state_0;
	int i;

	if(!OK)
		return NULL;

	if(!PyTuple_Check(args))
		return PyErr_SetString(PyExc_SystemError, "Hashset.merge: new style getargs format but argument is not a tuple"), NULL;

	state.numsources = PyTuple_GET_SIZE(args) - 1;
	if(state.numsources < 0)
		return PyErr_SetString(PyExc_TypeError, "Hashset.merge: needs at least 1 argument (0 given)"), NULL;

	if(!PyUnicode_FSConverter(PyTuple_GET_ITEM(args, 0), &state.filename_obj))
		return NULL;

	state.filename = PyBytes_AsString(state.filename_obj);
	if(state.filename) {
		state.sources = malloc(state.numsources * sizeof *state.sources);
		if(state.sources) {
			for(i = 0; i < state.numsources; i++) {
				hs = Hashset_Check(PyTuple_GET_ITEM(args, i + 1));
				if(!hs)
					break;
				state.sources[i].hs = hs;
				if(i) {
					if(state.hashlen != hs->hashlen) {
						PyErr_Format(PyExc_SystemError, "Hashset.merge: objects with differing hashlen (%d, %d)",
							state.hashlen, hs->hashlen);
						break;
					}
				} else {
					state.hashlen = hs->hashlen;
				}
			}

			if(OK)
				merge_do(&state);
		} else {
			PyErr_SetString(PyExc_TypeError, "Hashset.merge: out of memory");
		}
	}

	merge_cleanup(&state);

	RETURN_NONE_IF_OK;
}

PyObject *Hashset_new(PyTypeObject *subtype, PyObject *args, PyObject *kwargs) {
	Hashset_t *hs;
	const char *bytes;
	Py_ssize_t len;
	Py_ssize_t hashlen;

	if(!OK)
		return NULL;

	if(!PyArg_ParseTuple(args, "y#n:Hashset.new", &bytes, &len, &hashlen))
		return NULL;

	if(hashlen < 1)
		return PyErr_Format(PyExc_ValueError, "Hashset.new: hash length (%z) must be larger than 0", hashlen);

	if(len % hashlen)
		return PyErr_Format(PyExc_ValueError, "Hashset.new: buffer size (%d) is not a multiple of the key length (%z)", len, hashlen);

	hs = PyObject_New(Hashset_t, subtype);
	if(hs) {
		hs->hashlen = (size_t)hashlen;

		if(len) {
			hs->buf = mmap(NULL, (size_t)len, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
			if(hs->buf == MAP_FAILED) {
				PyErr_SetFromErrno(PyExc_OSError);
			} else {
				hs->size = hs->mapsize = len;
				memcpy(hs->buf, bytes, len);
				qsort_lr(hs->buf, len / hashlen, hashlen, (qsort_lr_cmp)memcmp, NULL);
				dedup(hs);
				return &hs->ob_base;
			}
		}

		PyObject_Del(&hs->ob_base);
	}

	return NULL;
}

PyObject *Hashset_load(PyObject *class, PyObject *args, PyObject *kwargs) {
	Hashset_t *hs;
	int fd = -1;
	struct stat st;
	Py_ssize_t hashlen;
	PyBytesObject *filename_obj;
	char *filename;

	if(!PyArg_ParseTuple(args, "O&n:Hashset.load", PyUnicode_FSConverter, &filename_obj, &hashlen))
		return NULL;

	if(hashlen) {
		struct hashset_module_state *state = PyModule_GetState(PyState_FindModule(&hashset_module));
		if(state) {
			hs = PyObject_New(Hashset_t, state->Hashset_type);
			if(hs) {
				hs->hashlen = hashlen;

				fd = open(filename, O_RDONLY|O_NOCTTY|O_LARGEFILE);
				if(fd != -1) {
					if(fstat(fd, &st) != -1) {
						if(st.st_size % hashlen == 0) {
							hs->buf = st.st_size ? mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0) : NULL;
							if(close(fd) != -1) {
								if(hs->buf != MAP_FAILED) {
									hs->size = hs->mapsize = st.st_size;
									if(st.st_size)
										madvise(hs->buf, hs->mapsize, MADV_WILLNEED);

									hs->filename = strdup(filename);
									if(hs->filename)
										return hs; FIXME
									else
										PyErr_NoMemory();
								} else {
									PyErr_SetFromErrnoWithFilename(PyExc_OSError, filename);
								}
							} else {
								PyErr_SetFromErrnoWithFilename(PyExc_OSError, filename);
							}
						} else {
							PyErr_Format(PyExc_ValueError, "Hashset.load(%s): file size (%d) is not a multiple of the key length (%z)", filename, (long int)st.st_size, hashlen);
						}
					} else {
						PyErr_SetFromErrnoWithFilename(PyExc_OSError, filename);
					}
				} else {
					PyErr_SetFromErrnoWithFilename(PyExc_OSError, filename);
				}
			}
		} else {
			PyErr_SetString(PyExc_SystemError, "internal error: unable to locate module state");
		}
	} else {
		PyErr_Format(PyExc_ValueError, "Hashset.open: unsupported hash length (%d)", hashlen);
	}

	Py_DecRef(&filename_obj->ob_base.ob_base);

	RETURN_IF_OK(&hs->ob_base);
}

PyObject *Hashset_exists(Hashset_t *hs, PyObject *args) {
	const char *key;
	Py_ssize_t len;
	uint64_t off;

	if(!PyArg_ParseTuple(args, "y#:Hashset.exists", &key, &len))
		return NULL;

	if(!hs->size)
		Py_RETURN_FALSE;

	if(!exists_ge(hs, key, len, &off))
		return NULL;

	if(memcmp((const char *)hs->buf + off, key, len))
		Py_RETURN_FALSE;
	else
		Py_RETURN_TRUE;
}

PyObject *Hashset_iterator(Hashset_t *self, PyObject *args) {
	HashsetIterator_t *c;
	const char *key = NULL;
	Py_ssize_t len;
	size_t off = 0;

	if(!PyArg_ParseTuple(args, "|y#:Hashset.exists", &key, &len))
		return NULL;

	if(key && !exists_ge(self, key, len, &off))
		return NULL;

	struct hashset_module_state *state = PyModule_GetState(PyState_FindModule(&hashset_module));
	c = PyObject_New(HashsetIterator_t, state->HashsetIterator_type);
	if(!c)
		return NULL;

	c->magic = HASHSET_ITERATOR_MAGIC;
	c->hs = self;
	c->off = off;

	Py_IncRef(&self->ob_base);

	return &c->ob_base;
}

static PyMethodDef Hashset_methods[] = {
	{"exists", (PyCFunction)Hashset_exists, METH_O, "test if this key is contained in the Hashset"},
	{"__iter__", (PyCFunction)Hashset_iterator, METH_NOARGS, "returns an iterator for this hashet"},
//	{"__enter__", (PyCFunction)Hashset_enter, METH_NOARGS, "return a context manager for 'with'"},
//	{"__exit__", (PyCFunction)Hashset_exit, METH_VARARGS, "callback for 'with' context manager"},
	{NULL}
};

static PyType_Slot Hashset_slots[] = {
	{Py_tp_dealloc, (destructor)Hashset_dealloc},
//	{Py_tp_as_mapping, &Hashset_as_mapping},
//	{Py_tp_iter, (getiterfunc)Hashset_iter},
	{Py_tp_methods, Hashset_methods},
//	{Py_tp_getset, Hashset_getset},
	{Py_tp_new, (newfunc)Hashset_new},
	{0, NULL}
};

static PyType_Spec Hashset_spec = {
	"hashset.Hashset",
	sizeof(Hashset_t),
	0,
	Py_TPFLAGS_DEFAULT,
	Hashset_slots
};

PyObject *HashsetIterator_next(HashsetIterator_t *self) {
	Hashset_t *hs;
	size_t off;

	hs = self->hs;
	if(!hs)
		return PyErr_SetString(PyExc_TypeError, "Hashset.merge: needs at least 1 argument (0 given)"), NULL;

	off = self->off;
	if(off >= hs->size)
		return NULL;

	self->off = off + hs->hashlen;
	return PyBytes_FromStringAndSize((const char *)hs->buf + off, hs->hashlen);
}

static int HashsetIterator_dealloc(HashsetIterator_t *obj) {
	Py_CLEAR(obj->hs);

	return 0;
}

static PyMethodDef HashsetIterator_methods[] = {
	{"__next__", (PyCFunction)HashsetIterator_next, METH_NOARGS, "returns the next value for this iterator"},
//	{"__enter__", (PyCFunction)HashsetIterator_enter, METH_NOARGS, "return a context manager for 'with'"},
//	{"__exit__", (PyCFunction)HashsetIterator_exit, METH_VARARGS, "callback for 'with' context manager"},
	{NULL}
};

static PyType_Slot HashsetIterator_slots[] = {
	{Py_tp_dealloc, (destructor)HashsetIterator_dealloc},
//	{Py_tp_as_mapping, &Hashset_as_mapping},
//	{Py_tp_iter, (getiterfunc)Hashset_iter},
	{Py_tp_methods, HashsetIterator_methods},
//	{Py_tp_getset, HashsetIterator_getset},
//	{Py_tp_new, (newfunc)HashsetIterator_new},
	{0, NULL}
};

static PyType_Spec HashsetIterator_spec = {
	"hashset.HashsetIterator",
	sizeof(HashsetIterator_t),
	0,
	Py_TPFLAGS_DEFAULT,
	HashsetIterator_slots
};

PyDoc_STRVAR(hashset_module_doc, "Functions for creating, querying and manipulating sorted hash files");

static void hashset_module_free(PyObject *module) {
	struct hashset_module_state *state = PyModule_GetState(module);
	Py_CLEAR(state->HashsetIterator_type);
	Py_CLEAR(state->Hashset_type);
}

static struct PyModuleDef hashset_module = {
	PyModuleDef_HEAD_INIT,
	.m_name = "hashset",
	.m_doc = hashset_module_doc,
//	.m_methods = hashset_module_functions,
	.m_size = sizeof(struct hashset_module_state),
	.m_free = (freefunc)hashset_module_free,
};

PyMODINIT_FUNC PyInit_hashset(void) {
	PyObject *module = PyModule_Create(&hashset_module);
	if(module) {
		struct hashset_module_state *state = PyModule_GetState(module);
		state->Hashset_type = (PyTypeObject *)PyType_FromSpec(&Hashset_spec);
		if(PyModule_AddObject(module, "Hashset", &state->Hashset_type->ob_base.ob_base) != -1) {
			Py_IncRef(&state->Hashset_type->ob_base.ob_base);
			state->HashsetIterator_type = (PyTypeObject *)PyType_FromSpec(&HashsetIterator_spec);
			if(PyModule_AddObject(module, "HashsetIterator", &state->HashsetIterator_type->ob_base.ob_base) != -1) {
				Py_IncRef(&state->HashsetIterator_type->ob_base.ob_base);
				return module;
			}
			Py_CLEAR(state->HashsetIterator_type);
		}
		Py_CLEAR(state->Hashset_type);
		Py_DecRef(module);
	}
	return NULL;
}
