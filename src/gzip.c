/**************************************************************************
 * gzip.c
 *
 * Minimal gzip (RFC 1952) container around raw DEFLATE from miniz.
 * CRC is mz_crc32 = CRC-32/ISO-HDLC (poly 0xEDB88320), the gzip CRC.
 *
 * This file is part of the ringserver.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (C) 2026:
 * @author Chad Trabant, EarthScope Data Services
 **************************************************************************/

#include "gzip.h"

/* Miniz build options — disable unused ZIP/stdio/time/zlib-compatible defines */
#define MINIZ_NO_ARCHIVE_APIS
#define MINIZ_NO_STDIO
#define MINIZ_NO_TIME
#define MINIZ_NO_ZLIB_COMPATIBLE_NAMES

#include "miniz.h"

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/**************************************************************************
 * gzip_compress:
 *
 * Compress `inlen` bytes at `in` into a complete gzip (RFC 1952) stream.
 *
 * @param in: Buffer to compress.
 * @param inlen: Length of `in` in bytes.
 * @param out: Set to a newly malloc'd buffer containing the gzip stream
 * on success. Caller must free() it. Left untouched on failure.
 * @param outlen: Set to the length of `*out` in bytes on success. Left
 * untouched on failure.
 *
 * @return: 0 on success, -1 on error.
 **************************************************************************/
int
gzip_compress (const void *in, size_t inlen, char **out, size_t *outlen)
{
  if (!in || !out || !outlen || inlen > (size_t)UINT_MAX)
    return -1;

  /* Raw DEFLATE (window_bits <= 0 => no zlib header) at max level. */
  mz_uint flags = (mz_uint)tdefl_create_comp_flags_from_zip_params (MZ_UBER_COMPRESSION, -15,
                                                                    MZ_DEFAULT_STRATEGY);

  size_t deflate_len = 0;

  void *deflated = tdefl_compress_mem_to_heap (in, inlen, &deflate_len, flags);

  if (!deflated)
    return -1;

  /* 10-byte header + deflate body + 8-byte trailer */
  unsigned char *buf = malloc ((size_t)10 + deflate_len + 8);
  if (!buf)
  {
    mz_free (deflated);
    return -1;
  }

  /* gzip header */
  buf[0] = 0x1f; /* ID1 */
  buf[1] = 0x8b; /* ID2 */
  buf[2] = 0x08; /* CM = DEFLATE */
  buf[3] = 0x00; /* FLG */
  buf[4] = 0x00; /* MTIME = 0 */
  buf[5] = 0x00; /* MTIME = 0 */
  buf[6] = 0x00; /* MTIME = 0 */
  buf[7] = 0x00; /* MTIME = 0 */
  buf[8] = 0x00; /* XFL */
  buf[9] = 0xff; /* OS = unknown */

  memcpy (buf + 10, deflated, deflate_len);
  mz_free (deflated);

  size_t pos = (size_t)10 + deflate_len;

  uint32_t crc = (uint32_t)mz_crc32 (MZ_CRC32_INIT, (const unsigned char *)in, inlen);

  uint32_t isize = (uint32_t)(inlen & 0xffffffffu);

  /* trailer, little-endian */
  buf[pos++] = (unsigned char)(crc & 0xff);
  buf[pos++] = (unsigned char)((crc >> 8) & 0xff);
  buf[pos++] = (unsigned char)((crc >> 16) & 0xff);
  buf[pos++] = (unsigned char)((crc >> 24) & 0xff);
  buf[pos++] = (unsigned char)(isize & 0xff);
  buf[pos++] = (unsigned char)((isize >> 8) & 0xff);
  buf[pos++] = (unsigned char)((isize >> 16) & 0xff);
  buf[pos++] = (unsigned char)((isize >> 24) & 0xff);

  *out = (char *)buf;
  *outlen = pos;
  return 0;
}
