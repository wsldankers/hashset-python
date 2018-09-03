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

#ifdef WITH_THREAD
#define DECLARE_THREAD_SAVE PyThreadState *_save;
#else
#define DECLARE_THREAD_SAVE
#endif

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
static PyTypeObject Hashset_type;
static PyTypeObject HashsetIterator_type;

#define HASHSET_MAGIC UINT64_C(0xC63E9FDB3D336988)
#define HASHSET_ITERATOR_MAGIC UINT64_C(0x2BF1D59A332EF8E5)

typedef enum {
		HASHSET_ERROR_NONE,
		HASHSET_ERROR_ERRNO,
		HASHSET_ERROR_HASHLEN,
		HASHSET_ERROR_PYTHON,
} hashset_error_type_t;

typedef struct hashset_error {
	const char *filename;
	union {
		int saved_errno;
		Py_ssize_t hashlen[2];
	} parameters;
	hashset_error_type_t type:8;
} hashset_error_t;

static const hashset_error_t hashset_error_0 = {0, {0}, HASHSET_ERROR_NONE};

#define HASHLEN_MIN ((Py_ssize_t)8)

#ifdef WITH_THREAD
#define DECLARE_THREAD_SAVE PyThreadState *_save;
#else
#define DECLARE_THREAD_SAVE
#endif

#define MERGEBUFSIZE (1 << 21)

static void hashset_error_to_python(const char *function, hashset_error_t *err) {
	switch(err->type) {
		case HASHSET_ERROR_NONE:
		case HASHSET_ERROR_PYTHON:
			break;
		case HASHSET_ERROR_HASHLEN:
			if(err->parameters.hashlen[1] < HASHLEN_MIN)
				PyErr_Format(PyExc_ValueError, "Hashset.%s(%s): hash length (%ld) must not be smaller than %ld", function, err->filename, (long int)err->parameters.hashlen[0], (long int)err->parameters.hashlen[1]);
			else
				PyErr_Format(PyExc_ValueError, "Hashset.%s(%s): hash lengths do not match (%ld, %ld)", function, err->filename, (long int)err->parameters.hashlen[0], (long int)err->parameters.hashlen[1]);
			break;
		case HASHSET_ERROR_ERRNO:
			if(err->parameters.saved_errno == ENOMEM) {
				PyErr_NoMemory();
			} else {
				errno = err->parameters.saved_errno;
				if(err->filename)
					PyErr_SetFromErrnoWithFilename(PyExc_OSError, err->filename);
				else
					PyErr_SetFromErrno(PyExc_OSError);
			}
			break;
	}
}

static inline void hashset_clear_error(hashset_error_t *err) {
	err->type = HASHSET_ERROR_NONE;
}

static inline void hashset_record_hashlen_error(hashset_error_t *err, Py_ssize_t hashlen0, Py_ssize_t hashlen1) {
	err->type = HASHSET_ERROR_HASHLEN;
	err->parameters.hashlen[0] = hashlen0;
	err->parameters.hashlen[1] = hashlen1;
}

static inline void hashset_record_errno(hashset_error_t *err, int saved_errno) {
	err->type = HASHSET_ERROR_ERRNO;
	err->parameters.saved_errno = saved_errno;
}

static inline void hashset_record_python_error(hashset_error_t *err) {
	err->type = HASHSET_ERROR_PYTHON;
}

static inline Hashset_t *Hashset_Check(PyObject *v) {
	return v && PyObject_TypeCheck(v, &Hashset_type) && ((Hashset_t *)v)->magic == HASHSET_MAGIC
		? (Hashset_t *)v
		: NULL;
}

static inline HashsetIterator_t *HashsetIterator_Check(PyObject *v) {
	return v && PyObject_TypeCheck(v, &HashsetIterator_type) && ((HashsetIterator_t *)v)->magic == HASHSET_ITERATOR_MAGIC
		? (HashsetIterator_t *)v
		: NULL;
}

static int hashset_module_filename(PyObject *filename_object, PyObject **dst) {
	if(filename_object) {
		if(PyUnicode_Check(filename_object)) {
			return PyUnicode_FSConverter(filename_object, dst);
		} else if(PyBytes_Check(filename_object)) {
			Py_IncRef(filename_object);
			*dst = filename_object;
		} else {
			*dst = PyBytes_FromObject(filename_object);
		}
	} else if(dst) {
		Py_CLEAR(*dst);
		return true;
	} else {
		return false;
	}
	return Py_CLEANUP_SUPPORTED;
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

static uint64_t exists_ge(const Hashset_t *hs, const void *key, size_t len, hashset_error_t *err) {
	const uint8_t *buf, *cur_buf;
	uint64_t lower, upper, cur, lower_hash, upper_hash, target;
	int d;

	if(len != hs->hashlen)
		return hashset_record_hashlen_error(err, len, hs->hashlen), 0;

	upper = hs->size / len;
	if(!upper)
		return err->type = HASHSET_ERROR_NONE, 0;

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

	return hashset_clear_error(err), cur * (uint64_t)len;
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
	size_t i = state->queuelen / 2;

	do queue_update_up(state, i);
		while(i--);
}

/*
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

	// bubble down
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
*/

static void safewrite(hash_merge_state_t *state, hashset_error_t *err) {
	ssize_t r;
	const char *buf = state->buf;
	while(state->fill) {
		r = write(state->fd, buf, state->fill);
		switch(r) {
			case -1:
				return hashset_record_errno(err, errno);
			case 0:
				return hashset_record_errno(err, EAGAIN);
		}
		buf += (size_t)r;
		state->fill -= (size_t)r;
		state->written += (size_t)r;
	}
	return hashset_clear_error(err);
}

static void merge_do(hash_merge_state_t *state, hashset_error_t *err) {
	size_t i;
	Hashset_t *hs;
	hash_merge_source_t *src;
	char *last;
	int fd;
	size_t hashlen = state->hashlen;

	if(state->numsources) {
		if(MERGEBUFSIZE % hashlen)
			return hashset_record_hashlen_error(err, MERGEBUFSIZE, hashlen);
#ifdef MAP_HUGETLB
		state->buf = mmap(NULL, MERGEBUFSIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_HUGETLB, -1, 0);
		if(state->buf == MAP_FAILED)
#endif
		state->buf = mmap(NULL, MERGEBUFSIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
		if(state->buf == MAP_FAILED)
			return hashset_record_errno(err, errno);
	}

	fd = state->fd = open(state->filename, O_WRONLY|O_CREAT|O_NOCTTY|O_LARGEFILE|O_CLOEXEC, 0666);
	if(fd == -1)
		return hashset_record_errno(err, errno);

	if(state->numsources) {
		state->queue = malloc(state->numsources * sizeof *state->queue);
		if(!state->queue)
			return hashset_record_errno(err, errno);

		for(i = 0; i < state->numsources; i++) {
			src = state->sources + i;
			hs = src->hs;
			src->off = 0;
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

			if(state->fill == MERGEBUFSIZE) {
				safewrite(state, err);
				if(err->type != HASHSET_ERROR_NONE)
					return;
			}
		}

		if(state->fill) {
			safewrite(state, err);
			if(err->type != HASHSET_ERROR_NONE)
				return;
		}
	}

	if(ftruncate(fd, state->written) == -1)
		return hashset_record_errno(err, errno);

	if(fdatasync(fd) == -1)
		return hashset_record_errno(err, errno);

	state->fd = -1;
	if(close(fd) == -1)
		return hashset_record_errno(err, errno);

	return hashset_clear_error(err);
}

static void merge_cleanup(hash_merge_state_t *state) {
	free(state->sources);
	free(state->queue);
	if(state->fd != -1)
		close(state->fd);
	if(state->buf != MAP_FAILED)
		munmap(state->buf, MERGEBUFSIZE);
	Py_CLEAR(state->filename_obj);

	*state = hash_merge_state_0;
}

static PyObject *Hashset_merge(PyObject *class, PyObject *args) {
	Hashset_t *hs;
	hash_merge_state_t state = hash_merge_state_0;
	int i;
	hashset_error_t err = hashset_error_0;

	if(!PyTuple_Check(args))
		return PyErr_SetString(PyExc_SystemError, "Hashset.merge: new style getargs format but argument is not a tuple"), NULL;

	state.numsources = PyTuple_GET_SIZE(args) - 1;
	if(state.numsources < 0)
		return PyErr_SetString(PyExc_TypeError, "Hashset.merge: needs at least 1 argument (0 given)"), NULL;

	if(!hashset_module_filename(PyTuple_GET_ITEM(args, 0), &state.filename_obj))
		return NULL;

	state.filename = PyBytes_AsString(state.filename_obj);
	if(state.filename) {
		err.filename = state.filename;
		state.sources = malloc(state.numsources * sizeof *state.sources);
		if(state.sources) {
			for(i = 0; i < state.numsources; i++) {
				hs = Hashset_Check(PyTuple_GET_ITEM(args, i + 1));
				if(!hs) {
					hashset_record_python_error(&err);
					break;
				}
				state.sources[i].hs = hs;
				if(i) {
					if(state.hashlen != hs->hashlen) {
						PyErr_Format(PyExc_SystemError, "Hashset.merge: objects with differing hashlen (%d, %d)",
							state.hashlen, hs->hashlen);
						hashset_record_python_error(&err);
						break;
					}
				} else {
					state.hashlen = hs->hashlen;
				}
			}

			if(i == state.numsources) {
				Py_BEGIN_ALLOW_THREADS
				merge_do(&state, &err);
				Py_END_ALLOW_THREADS
				hashset_error_to_python("merge", &err);
			}
		} else {
			hashset_record_python_error(&err);
			PyErr_NoMemory();
		}
	} else {
		hashset_record_python_error(&err);
	}

	merge_cleanup(&state);

	if(err.type == HASHSET_ERROR_NONE)
		Py_RETURN_NONE;
	else
		return NULL;
}

static int Hashset_dealloc(Hashset_t *obj) {
	if(obj->buf != MAP_FAILED)
		munmap(obj->buf, obj->mapsize);
	obj->buf = MAP_FAILED;

	obj->filename = NULL;
	Py_CLEAR(obj->filename_obj);

	freefunc tp_free = Py_TYPE(obj)->tp_free ?: PyObject_Free;
	tp_free(obj);

	return 0;
}

static PyObject *Hashset_sortfile(PyObject *class, PyObject *args) {
	int fd;
	struct stat st;
	Hashset_t hs = Hashset_0;
	PyObject *filename_obj;
	Py_ssize_t hashlen;
	char *filename;
	hashset_error_t err = hashset_error_0;

	if(!PyArg_ParseTuple(args, "O&n:sortfile", hashset_module_filename, &filename_obj, &hashlen))
		return NULL;

	filename = PyBytes_AsString(filename_obj);
	if(filename) {
		err.filename = filename;
		Py_BEGIN_ALLOW_THREADS
		if(hashlen >= HASHLEN_MIN) {
			fd = open(filename, O_RDWR|O_NOCTTY|O_LARGEFILE|O_CLOEXEC);
			if(fd != -1) {
				if(fstat(fd, &st) != -1) {
					if(st.st_size % hashlen == 0) {
						if(st.st_size) {
							hs.buf = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
							if(hs.buf != MAP_FAILED) {
								hs.size = hs.mapsize = st.st_size;
								hs.hashlen = hashlen;
								qsort_lr(hs.buf, hs.size / hashlen, hashlen, (qsort_lr_cmp)memcmp, NULL);
								dedup(&hs);

								if(msync(hs.buf, hs.mapsize, MS_SYNC) == -1)
									hashset_record_errno(&err, errno);
								if(munmap(hs.buf, hs.mapsize) == -1)
									hashset_record_errno(&err, errno);
								if(err.type == HASHSET_ERROR_NONE && hs.size != hs.mapsize && ftruncate(fd, hs.size) == -1)
									hashset_record_errno(&err, errno);
							} else {
								hashset_record_errno(&err, errno);
							}
						} else {
							hashset_record_errno(&err, errno);
						}
					} else {
						hashset_record_hashlen_error(&err, st.st_size, hashlen);
					}
				} else {
					hashset_record_errno(&err, errno);
				}
				if(close(fd) == -1 && err.type == HASHSET_ERROR_NONE)
					hashset_record_errno(&err, errno);
			} else {
				hashset_record_errno(&err, errno);
			}
		} else {
			hashset_record_hashlen_error(&err, hashlen, HASHLEN_MIN);
		}
		Py_END_ALLOW_THREADS
		hashset_error_to_python("sortfile", &err);
		err.filename = NULL;
	} else {
		hashset_record_python_error(&err);
	}

	Py_DecRef(filename_obj);

	if(err.type == HASHSET_ERROR_NONE)
		Py_RETURN_NONE;
	else
		return NULL;
}

static PyObject *Hashset_new(PyTypeObject *subtype, PyObject *args, PyObject *kwargs) {
	Hashset_t *hs;
	const char *bytes;
	Py_ssize_t len;
	Py_ssize_t hashlen;

	if(!PyArg_ParseTuple(args, "y#n:Hashset.new", &bytes, &len, &hashlen))
		return NULL;

	if(hashlen < HASHLEN_MIN)
		return PyErr_Format(PyExc_ValueError, "Hashset.new: hash length (%zd) must be at least %zd", hashlen, HASHLEN_MIN);

	if(len % hashlen)
		return PyErr_Format(PyExc_ValueError, "Hashset.new: buffer size (%zd) is not a multiple of the key length (%zd)", len, hashlen);

	hs = PyObject_New(Hashset_t, subtype);
	if(!hs)
		return NULL;

	hs->magic = HASHSET_MAGIC;
	hs->buf = MAP_FAILED;
	hs->filename = NULL;
	hs->filename_obj = NULL;
	hs->size = 0;
	hs->mapsize = 0;
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

	Py_DecRef(&hs->ob_base);

	return NULL;
}

static PyObject *Hashset_load(PyObject *class, PyObject *args) {
	Hashset_t *hs = NULL;
	int fd = -1;
	struct stat st;
	hashset_error_t err = hashset_error_0;

	hs = PyObject_New(Hashset_t, &Hashset_type);
	if(!hs)
		return NULL;

	hs->magic = HASHSET_MAGIC;
	hs->buf = MAP_FAILED;
	hs->filename = NULL;
	hs->filename_obj = NULL;
	hs->size = 0;
	hs->mapsize = 0;
	hs->hashlen = 0;

	if(PyArg_ParseTuple(args, "O&n:Hashset.load", hashset_module_filename, &hs->filename_obj, &hs->hashlen)) {
		hs->filename = PyBytes_AsString(hs->filename_obj);
		if(hs->filename) {
			err.filename = hs->filename;
			if(hs->hashlen >= HASHLEN_MIN) {
				Py_BEGIN_ALLOW_THREADS
				fd = open(hs->filename, O_RDONLY|O_NOCTTY|O_LARGEFILE|O_CLOEXEC);
				if(fd != -1) {
					if(fstat(fd, &st) != -1) {
						if(st.st_size) {
							if(st.st_size % hs->hashlen == 0) {
								hs->buf = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
								if(hs->buf != MAP_FAILED) {
									hs->mapsize = hs->size = st.st_size;
									if(close(fd) != -1)
										madvise(hs->buf, st.st_size, MADV_WILLNEED);
									else
										hashset_record_errno(&err, errno);
									fd = -1;
								} else {
									hashset_record_errno(&err, errno);
								}
							} else {
								hashset_record_hashlen_error(&err, st.st_size, hs->hashlen);
							}
						} else {
							if(close(fd) == -1)
								hashset_record_errno(&err, errno);
							fd = -1;
						}
					} else {
						hashset_record_errno(&err, errno);
					}
					if(fd != -1)
						close(fd);
				} else {
					hashset_record_errno(&err, errno);
				}
				Py_END_ALLOW_THREADS
			} else {
				PyErr_Format(PyExc_ValueError, "Hashset.load(%s, %zd): hash length must be at least %zd", hs->filename, hs->hashlen, HASHLEN_MIN);
				hashset_record_python_error(&err);
			}
		} else {
			hashset_record_python_error(&err);
		}
	} else {
		hashset_record_python_error(&err);
	}

	if(err.type == HASHSET_ERROR_NONE) {
		return &hs->ob_base;
	} else {
		err.filename = hs->filename;
		hashset_error_to_python("load", &err);
		Py_DecRef(&hs->ob_base);
		return NULL;
	}
}

static Py_ssize_t Hashset_length(Hashset_t *hs) {
	return hs->size / hs->hashlen;
}

static PyObject *Hashset_item(Hashset_t *hs, Py_ssize_t index) {
	uint64_t off;
	char *buf;
	PyObject *bytes;
	Py_ssize_t hashlen = hs->hashlen;
	Py_ssize_t len = hs->size / hashlen;

	if(index < 0)
		index += len;
	if(index < 0 || index >= len)
		return PyErr_SetString(PyExc_IndexError, "index out of range"), NULL;
	off = index * hashlen;

	bytes = PyBytes_FromStringAndSize(NULL, hashlen);
	if(!bytes)
		return NULL;
	buf = PyBytes_AsString(bytes);

	Py_BEGIN_ALLOW_THREADS
	memcpy(buf, hs->buf + off, hashlen);
	Py_END_ALLOW_THREADS

	return bytes;
}

static PyObject *Hashset_subscript(Hashset_t *hs, PyObject *key) {
	uint64_t off = 0;
	hashset_error_t err = hashset_error_0;
	int d = 0;
	Py_ssize_t index;
	Py_buffer buf;

	if(PyIndex_Check(key)) {
		index = PyNumber_AsSsize_t(key, PyExc_IndexError);
		if(index == -1 && PyErr_Occurred())
			return NULL;
		return Hashset_item(hs, index);
	}

	if(!hs->size)
		return PyErr_SetObject(PyExc_KeyError, key), NULL;

	if(!hashset_module_object_to_buffer(key, &buf))
		return NULL;

	Py_BEGIN_ALLOW_THREADS
	off = exists_ge(hs, buf.buf, buf.len, &err);
	if(err.type == HASHSET_ERROR_NONE)
		d = memcmp((const char *)hs->buf + off, buf.buf, buf.len);
	Py_END_ALLOW_THREADS

	PyBuffer_Release(&buf);

	if(err.type == HASHSET_ERROR_HASHLEN) {
		return PyErr_SetObject(PyExc_KeyError, key), NULL;
	} else if(err.type != HASHSET_ERROR_NONE) {
		err.filename = hs->filename;
		hashset_error_to_python("subscript", &err);
		return NULL;
	}

	if(d)
		return PyErr_SetObject(PyExc_KeyError, key), NULL;
	else
		return PyLong_FromSize_t(off / hs->hashlen);
}

static int Hashset_contains(Hashset_t *hs, PyObject *key) {
	uint64_t off = 0;
	hashset_error_t err = hashset_error_0;
	int d = 0;
	Py_ssize_t index;
	Py_buffer buf;

	if(!hs->size)
		return 0;

	if(PyIndex_Check(key)) {
		index = PyNumber_AsSsize_t(key, PyExc_IndexError);
		if(index == -1 && PyErr_Occurred())
			return -1;
		return index >= 0 && index < hs->size / hs->hashlen;
	}

	if(!hashset_module_object_to_buffer(key, &buf))
		return -1;

	Py_BEGIN_ALLOW_THREADS
	off = exists_ge(hs, buf.buf, buf.len, &err);
	if(err.type == HASHSET_ERROR_NONE)
		d = memcmp((const char *)hs->buf + off, buf.buf, buf.len);
	Py_END_ALLOW_THREADS

	PyBuffer_Release(&buf);

	if(err.type == HASHSET_ERROR_HASHLEN) {
		return 0;
	} else if(err.type != HASHSET_ERROR_NONE) {
		err.filename = hs->filename;
		hashset_error_to_python("contains", &err);
		return -1;
	}

	return !d;
}

static PyObject *Hashset_iter(Hashset_t *self) {
	HashsetIterator_t *c;

	c = PyObject_New(HashsetIterator_t, &HashsetIterator_type);
	if(!c)
		return NULL;

	c->magic = HASHSET_ITERATOR_MAGIC;
	c->hs = self;
	c->off = 0;

	Py_IncRef(&self->ob_base);

	return &c->ob_base;
}

static PyObject *Hashset_iterate(Hashset_t *self, PyObject *args) {
	HashsetIterator_t *c;
	const char *key = NULL;
	Py_ssize_t len;
	size_t off = 0;
	hashset_error_t err = hashset_error_0;

	if(!PyArg_ParseTuple(args, "|y#:Hashset.exists", &key, &len))
		return NULL;

	if(key) {
		Py_BEGIN_ALLOW_THREADS
		off = exists_ge(self, key, len, &err);
		Py_END_ALLOW_THREADS
		if(err.type != HASHSET_ERROR_NONE) {
			err.filename = self->filename;
			hashset_error_to_python("iterator", &err);
			return NULL;
		}
	}

	c = PyObject_New(HashsetIterator_t, &HashsetIterator_type);
	if(!c)
		return NULL;

	c->magic = HASHSET_ITERATOR_MAGIC;
	c->hs = self;
	c->off = off;

	Py_IncRef(&self->ob_base);

	return &c->ob_base;
}

static PyObject *Hashset_self(PyObject *self, PyObject *args) {
	Py_IncRef(self);
	return self;
}

static PyObject *Hashset_none(PyObject *self, PyObject *args) {
	Py_RETURN_NONE;
}

static PyMethodDef Hashset_methods[] = {
	{"sortfile", Hashset_sortfile, METH_VARARGS|METH_STATIC, "sort the hashes in a file"},
	{"merge", Hashset_merge, METH_VARARGS|METH_STATIC, "merge Hashsets into a file"},
	{"load", Hashset_load, METH_VARARGS|METH_STATIC, "load a Hashset from a file"},
	{"iterate", (PyCFunction)Hashset_iterate, METH_VARARGS, "sort the hashes in a file"},
	{"__enter__", (PyCFunction)Hashset_self, METH_NOARGS, "return a context manager for 'with'"},
	{"__exit__", (PyCFunction)Hashset_none, METH_VARARGS, "callback for 'with' context manager"},
	{NULL}
};

static PySequenceMethods Hashset_as_sequence = {
	.sq_contains = (objobjproc)Hashset_contains,
	.sq_item = (ssizeargfunc)Hashset_item,
	.sq_length = (lenfunc)Hashset_length,
};

static PyMappingMethods Hashset_as_mapping = {
	.mp_subscript = (binaryfunc)Hashset_subscript,
	.mp_length = (lenfunc)Hashset_length,
};

static PyTypeObject Hashset_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_basicsize = sizeof(Hashset_t),
	.tp_name = "hashset.Hashset",
	.tp_new = (newfunc)Hashset_new,
	.tp_dealloc = (destructor)Hashset_dealloc,
	.tp_iter = (getiterfunc)Hashset_iter,
	.tp_methods = Hashset_methods,
	.tp_as_mapping = &Hashset_as_mapping,
	.tp_as_sequence = &Hashset_as_sequence,
};

static PyObject *HashsetIterator_iternext(HashsetIterator_t *self) {
	Hashset_t *hs;
	size_t off;
	char *buf;
	PyObject *bytes;

	hs = self->hs;

	off = self->off;
	if(off >= hs->size)
		return NULL;

	self->off = off + hs->hashlen;

	bytes = PyBytes_FromStringAndSize(NULL, hs->hashlen);
	if(!bytes)
		return NULL;
	buf = PyBytes_AsString(bytes);

	Py_BEGIN_ALLOW_THREADS
	memcpy(buf, hs->buf + off, hs->hashlen);
	Py_END_ALLOW_THREADS

	return bytes;
}

static int HashsetIterator_dealloc(HashsetIterator_t *obj) {
	Py_CLEAR(obj->hs);

	freefunc tp_free = Py_TYPE(obj)->tp_free ?: PyObject_Free;
	tp_free(obj);

	return 0;
}

static PyMethodDef HashsetIterator_methods[] = {
	{"__enter__", Hashset_self, METH_NOARGS, "return a context manager for 'with'"},
	{"__exit__", Hashset_none, METH_VARARGS, "callback for 'with' context manager"},
	{NULL}
};

static PyTypeObject HashsetIterator_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_basicsize = sizeof(HashsetIterator_t),
	.tp_name = "hashset.HashsetIterator",
	.tp_dealloc = (destructor)HashsetIterator_dealloc,
	.tp_iter = PyObject_SelfIter,
	.tp_iternext = (getiterfunc)HashsetIterator_iternext,
	.tp_methods = HashsetIterator_methods,
};


PyDoc_STRVAR(hashset_module_doc, "Functions for creating, querying and manipulating sorted hash files");

static struct PyModuleDef hashset_module = {
	PyModuleDef_HEAD_INIT,
	.m_name = "hashset",
	.m_doc = hashset_module_doc,
};

PyMODINIT_FUNC PyInit_hashset(void) {
	if(PyType_Ready(&Hashset_type) == -1)
		return NULL;
	if(PyType_Ready(&HashsetIterator_type) == -1)
		return NULL;

	PyObject *module = PyModule_Create(&hashset_module);
	if(module) {
		if(PyModule_AddObject(module, "Hashset", &Hashset_type.ob_base.ob_base) != -1
		&& PyModule_AddObject(module, "HashsetIterator", &HashsetIterator_type.ob_base.ob_base) != -1)
			return module;
		Py_DecRef(module);
	}
	return NULL;
}
