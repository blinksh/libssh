/*
 * gzip.c - hooks for compression of packets
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003      by Aris Adamantiadis
 * Copyright (c) 2009      by Andreas Schneider <asn@cryptomilk.org>
 *
 * The SSH Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * The SSH Library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the SSH Library; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include "config.h"

#include <string.h>
#include <stdlib.h>
#include <zlib.h>

#include "libssh/priv.h"
#include "libssh/buffer.h"
#include "libssh/crypto.h"
#include "libssh/session.h"

#define BLOCKSIZE 1024 * 4

static z_stream *initcompress(ssh_session session, int level) {
  z_stream *stream = NULL;
  int status;

  stream = calloc(1, sizeof(z_stream));
  if (stream == NULL) {
    return NULL;
  }

  status = deflateInit(stream, level);
  if (status != Z_OK) {
    SAFE_FREE(stream);
    ssh_set_error(session, SSH_FATAL,
        "status %d inititalising zlib deflate", status);
    return NULL;
  }

  return stream;
}

static ssh_buffer gzip_compress(ssh_session session,ssh_buffer source,int level){
  z_stream *zout = session->current_crypto->compress_out_ctx;
  void *in_ptr = ssh_buffer_get(source);
  unsigned long in_size = ssh_buffer_get_len(source);
  ssh_buffer dest = NULL;
  unsigned char out_buf[BLOCKSIZE] = {0};
  unsigned long len;
  int status;

  if(zout == NULL) {
    zout = session->current_crypto->compress_out_ctx = initcompress(session, level);
    if (zout == NULL) {
      return NULL;
    }
  }

  dest = ssh_buffer_new();
  if (dest == NULL) {
    return NULL;
  }

  zout->next_out = out_buf;
  zout->next_in = in_ptr;
  zout->avail_in = in_size;
  do {
    zout->avail_out = BLOCKSIZE;
    status = deflate(zout, Z_PARTIAL_FLUSH);
    if (status != Z_OK) {
      ssh_buffer_free(dest);
      ssh_set_error(session, SSH_FATAL,
          "status %d deflating zlib packet", status);
      return NULL;
    }
    len = BLOCKSIZE - zout->avail_out;
    if (ssh_buffer_add_data(dest, out_buf, len) < 0) {
      ssh_buffer_free(dest);
      return NULL;
    }
    zout->next_out = out_buf;
  } while (zout->avail_out == 0);

  return dest;
}

int compress_buffer(ssh_session session, ssh_buffer buf) {
  ssh_buffer dest = NULL;

  dest = gzip_compress(session, buf, session->opts.compressionlevel);
  if (dest == NULL) {
    return -1;
  }

  if (ssh_buffer_reinit(buf) < 0) {
    ssh_buffer_free(dest);
    return -1;
  }

  if (ssh_buffer_add_data(buf, ssh_buffer_get(dest), ssh_buffer_get_len(dest)) < 0) {
    ssh_buffer_free(dest);
    return -1;
  }

  ssh_buffer_free(dest);
  return 0;
}

/* decompression */

static z_stream *initdecompress(ssh_session session) {
  z_stream *stream = NULL;
  int status;

  stream = calloc(1, sizeof(z_stream));
  if (stream == NULL) {
    return NULL;
  }

  status = inflateInit(stream);
  if (status != Z_OK) {
    SAFE_FREE(stream);
    ssh_set_error(session, SSH_FATAL,
        "Status = %d initiating inflate context!", status);
    return NULL;
  }

  return stream;
}

static ssh_buffer gzip_decompress(ssh_session session, ssh_buffer source, size_t maxlen) {
  z_stream *zin = session->current_crypto->compress_in_ctx;
  void *in_ptr = ssh_buffer_get(source);
  unsigned long in_size = ssh_buffer_get_len(source);
  unsigned char out_buf[BLOCKSIZE] = {0};
  ssh_buffer dest = NULL;
  unsigned long len;
  int status;

  if (zin == NULL) {
    zin = session->current_crypto->compress_in_ctx = initdecompress(session);
    if (zin == NULL) {
      return NULL;
    }
  }

  dest = ssh_buffer_new();
  if (dest == NULL) {
    return NULL;
  }

  zin->next_in = in_ptr;
  zin->avail_in = in_size;

  do {
    zin->next_out = out_buf;
    zin->avail_out = BLOCKSIZE;

    status = inflate(zin, Z_PARTIAL_FLUSH);

    if (status != Z_OK && status != Z_BUF_ERROR) {
      ssh_set_error(session, SSH_FATAL,
          "status %d inflating zlib packet", status);
      ssh_buffer_free(dest);
      return NULL;
    }
    len = BLOCKSIZE - zin->avail_out;
    if (ssh_buffer_add_data(dest, out_buf, len) < 0) {
      ssh_buffer_free(dest);
      return NULL;
    }
    if (ssh_buffer_get_len(dest) > maxlen){
      /* Size of packet exceeded, avoid a denial of service attack */
      ssh_buffer_free(dest);
      return NULL;
    }
  } while (zin->avail_out == 0);

  return dest;
}

static int _gzip_decompress(ssh_session session, ssh_buffer source, void **dest,
                        size_t *dest_len, size_t maxlen) {
  z_stream *zin = session->current_crypto->compress_in_ctx;
  void *in_ptr = ssh_buffer_get(source);
  unsigned long in_size = ssh_buffer_get_len(source);

  char *out;
  int out_maxlen = 4 * in_size;

  /* In practice they never come smaller than this */
  if (out_maxlen < 25)
    out_maxlen = 25;

  if (out_maxlen > (int) maxlen)
    out_maxlen = maxlen;

  if (zin == NULL) {
    zin = session->current_crypto->compress_in_ctx = initdecompress(session);
    if (zin == NULL) {
      return SSH_ERROR;
    }
  }
  zin->next_in = in_ptr;
  zin->avail_in = in_size;
  zin->next_out = (unsigned char *) malloc(out_maxlen);
  out = (char *) zin->next_out;
  zin->avail_out = out_maxlen;
  if (!zin->next_out) {
      ssh_set_error(session, SSH_FATAL,
          "Unable to allocate decompression buffer");
      return SSH_ERROR;
  }

  /* Loop until it's all inflated or hit error */
  for (;;) {
    int status;
    size_t out_ofs;
    char *newout;

    status = inflate(zin, Z_PARTIAL_FLUSH);

    if (status == Z_OK) {
      if (zin->avail_out > 0)
        /* status is OK and the output buffer has not been exhausted so we're done */
        break;
    } else if (status == Z_BUF_ERROR) {
      /* the input data has been exhausted so we are done */
      break;
    } else {
      /* error state */
      free(out);
      ssh_set_error(session, SSH_FATAL,
          "status %d inflating zlib packet", status);
      return SSH_ERROR;
    }

    if (out_maxlen >= (int) maxlen) {
      free(out);
      ssh_set_error(session, SSH_FATAL,
          "Excessive growth in decompression phase");
      return SSH_ERROR;
    }

    /* If we get here we need to grow the output buffer and try again */
    out_ofs = out_maxlen - zin->avail_out;
    out_maxlen *= 2;
    newout = realloc(out, out_maxlen);
    if (!newout) {
      free(out);
      ssh_set_error(session, SSH_FATAL,
          "Unable to expand decompression buffer");
      return SSH_ERROR;
    }
    out = newout;
    zin->next_out = (unsigned char *) out + out_ofs;
    zin->avail_out = out_maxlen - out_ofs;
  }

  *dest = (unsigned char *) out;
  *dest_len = out_maxlen - zin->avail_out;

  return 0;
}

int decompress_buffer(ssh_session session, ssh_buffer buf, size_t maxlen) {

  size_t out_size;
  void *buffer = NULL;
  int rc = _gzip_decompress(session, buf, &buffer, &out_size, maxlen);
  if (rc == SSH_ERROR) {
    return -1;
  }

  if (ssh_buffer_reinit(buf) < 0) {
    free(buffer);
    return -1;
  }

  if (ssh_buffer_add_data(buf, buffer, out_size) < 0) {
    free(buffer);
    return -1;
  }

  free(buffer);
  return 0;
}
