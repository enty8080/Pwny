/*
 * MIT License
 *
 * Copyright (c) 2020-2024 EntySec
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#ifndef __windows__
#include <termios.h>
#include <spawn.h>
#if defined(__iphone__) || defined(__macintosh__)
#include <util.h>
#else
#include <pty.h>
#endif
#endif

#include <ev.h>
#include <pwny/misc.h>
#include <pwny/log.h>
#include <pwny/queue.h>
#include <pwny/child.h>

#include <uthash/uthash.h>

#ifndef __iphone__
#include <pawn.h>
#endif

void child_set_links(child_t *child,
                     link_t out_link,
                     link_t err_link,
                     link_t exit_link,
                     void *data)
{
    child->out_link = out_link;
    child->err_link = err_link;
    child->exit_link = exit_link;
    child->link_data = data != NULL ? data : child;
}

size_t child_read(child_t *child, void *buffer, size_t length)
{
    size_t bytes;

    if ((bytes = queue_remove(child->out_queue.queue, buffer, length)) < length)
    {
        bytes += queue_remove(child->err_queue.queue, buffer + bytes, length - bytes);
    }

    return bytes;
}

size_t child_write(child_t *child, void *buffer, size_t length)
{
    ssize_t count;
    ssize_t stat;

    for (count = 0; count < length; NULL)
    {
        do
        {
            stat = write(child->in, buffer + count, length - count);
        }
        while (stat == -1 && errno == EINTR);

        if (stat < 0)
        {
            break;
        }

        log_debug("* Writing bytes to child (%d)\n", stat);
        count += stat;
    }

    return count > 0 ? count : -1;
}

void child_out(struct ev_loop *loop, struct ev_io *w, int events)
{
    child_t *child;
    int length;

    child = w->data;
    log_debug("* Child read out event initialized (%d)\n", w->fd);

    while ((length = queue_from_fd(child->out_queue.queue, w->fd)) > 0)
    {
        log_debug("* Child read from out (%d)\n", length);

        if (child->out_link)
        {
            child->out_link(child->link_data);
        }
    }
}

void child_err(struct ev_loop *loop, struct ev_io *w, int events)
{
    child_t *child;
    int length;

    child = w->data;
    log_debug("* Child read err event initialized (%d)\n", w->fd);

    while ((length = queue_from_fd(child->err_queue.queue, w->fd)) > 0)
    {
        log_debug("* Child read from err (%d)\n", length);

        if (child->err_link)
        {
            child->err_link(child->link_data);
        }
    }
}

void child_exit(struct ev_loop *loop, struct ev_child *w, int revents)
{
    child_t *child;

    child = w->data;
    log_debug("* Child exit event initialized\n");

    child->status = CHILD_DEAD;

    if (child->exit_link)
    {
        child->exit_link(child->link_data);
    }

    /* ev_child_stop(loop, w); */
    ev_io_stop(child->loop, &child->out_queue.io);
    ev_io_stop(child->loop, &child->err_queue.io);
}

child_t *child_create(char *filename, unsigned char *image, child_options_t *options)
{
    return NULL;
}

void child_kill(child_t *child)
{
    NULL; /* kill(child->pid, SIGINT); */
}

void child_destroy(child_t *child)
{
    close(child->in);
    close(child->out);
    close(child->err);

    queue_free(child->out_queue.queue);
    queue_free(child->err_queue.queue);

    free(child);
}
