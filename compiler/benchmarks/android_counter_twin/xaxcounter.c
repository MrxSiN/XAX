/* Conventional twin of the XAX counter's native callbacks (ADR-111, ADR-153):
 * read the 8-byte count, optionally increment, write, and fdatasync it, then close
 * the descriptor the Java side handed over. */
#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

static jlong counter(int fd, int increment) {
    uint64_t *cell = malloc(sizeof *cell);
    *cell = 0;
    pread(fd, cell, sizeof *cell, 0);
    uint64_t count = *cell;
    if (increment) {
        *cell = ++count;
        pwrite(fd, cell, sizeof *cell, 0);
        fdatasync(fd);
    }
    close(fd);
    free(cell);
    return (jlong)count;
}

JNIEXPORT jlong JNICALL Java_xax_counter_CounterActivity_xaxOnCreate(JNIEnv *env, jobject self, jobject state, jint fd) {
    (void)env; (void)self; (void)state;
    return counter(fd, 0);
}

JNIEXPORT jlong JNICALL Java_xax_counter_CounterClickListener_xaxOnClick(JNIEnv *env, jobject self, jobject view, jint fd) {
    (void)env; (void)self; (void)view;
    return counter(fd, 1);
}
