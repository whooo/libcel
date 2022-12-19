/* Copyright (c) 2022 by Erik Larsson
   SPDX-License-Identifier: GPL-3.0-or-later
*/

#include <unistd.h>
#include <stdint.h>
#include <endian.h>
#include <string.h>
#include "cel_types.h"
#include "cel_io.h"

int
is_buffer_short(
  ssize_t len,
  ssize_t offset,
  ssize_t required)
{
  if ((len - offset) < required) {
    return 1;
  }

  return 0;
}

CEL_RC
get_le_uint32(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  uint32_t *dst)
{
  uint32_t *tv = NULL;
  size_t off = get_offset(offset);

  CHECK_NULL(buffer);
  CHECK_NULL(dst);

  if (is_buffer_short(len, off, sizeof(uint32_t))) {
    return CEL_RC_SHORT_BUFFER;
  }

  tv = (uint32_t *) (buffer + off);
  *dst = le32toh(*tv);
  off += sizeof(uint32_t);

  set_offset(offset, off);

  return CEL_RC_SUCCESS;
}

CEL_RC
get_le_uint16(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  uint16_t *dst)
{
  uint16_t *tv = NULL;
  size_t off = get_offset(offset);

  CHECK_NULL(buffer);
  CHECK_NULL(dst);

  if (is_buffer_short(len, off, sizeof(uint16_t))) {
    return CEL_RC_SHORT_BUFFER;
  }

  tv = (uint16_t *) (buffer + off);
  *dst = le16toh(*tv);
  off += sizeof(uint16_t);

  set_offset(offset, off);

  return CEL_RC_SUCCESS;
}

CEL_RC
get_uefi_bytebuffer(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  BYTEBUFFER *dst)
{
  CEL_RC r;
  uint32_t slen;
  size_t off = get_offset(offset);

  CHECK_NULL(buffer);
  CHECK_NULL(dst);

  r = get_le_uint32(buffer, len, &off, &slen);
  if (r) {
    return r;
  }

  if (slen > sizeof(dst->buffer)) {
    return CEL_RC_VALUE_TOO_LARGE;
  }

  if (is_buffer_short(len, off, slen)) {
    return CEL_RC_SHORT_BUFFER;
  }

  memcpy(dst->buffer, buffer + off, slen);
  dst->size = slen;

  off += slen;

  set_offset(offset, off);

  return CEL_RC_SUCCESS;
}

CEL_RC
get_bytes(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  uint8_t *dst,
  size_t dstlen)
{
  size_t off = get_offset(offset);

  CHECK_NULL(buffer);
  CHECK_NULL(dst);

  if (is_buffer_short(len, off, dstlen)) {
    return CEL_RC_SHORT_BUFFER;
  }

  memcpy(dst, buffer + off, dstlen);
  off += dstlen;

  set_offset(offset, off);

  return CEL_RC_SUCCESS;
}

size_t
get_offset(
  const size_t *offset)
{
  if (offset) {
    return *offset;
  }
  return 0;
}

void
set_offset(
  size_t *dst,
  size_t src)
{
  if (dst) {
    *dst = src;
  }
}

size_t
get_digest_size(
  TPM2_ALG_ID alg)
{
  switch (alg) {
  case TPM2_ALG_SHA1:
    return TPM2_SHA1_DIGEST_SIZE;
  case TPM2_ALG_SHA256:
    return TPM2_SHA256_DIGEST_SIZE;
  case TPM2_ALG_SHA384:
    return TPM2_SHA384_DIGEST_SIZE;
  case TPM2_ALG_SHA512:
    return TPM2_SHA512_DIGEST_SIZE;
  case TPM2_ALG_SM3_256:
    return TPM2_SM3_256_DIGEST_SIZE;
  }

  return 0;
}

CEL_RC
get_be_uint32(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  UINT32 *dest)
{
  UINT32 *be_ptr;
  size_t off = get_offset(offset);

  CHECK_NULL(buffer);
  CHECK_NULL(dest);

  if (is_buffer_short(len, off, 4)) {
    return CEL_RC_SHORT_BUFFER;
  }

  be_ptr = (UINT32 *) (buffer + off);
  *dest = be32toh(*be_ptr);
  off += 4;

  set_offset(offset, off);

  return CEL_RC_SUCCESS;
}

int
is_nv_index(TPM2_HANDLE handle) {
  if ((handle & 0xFF000000) == 0x20000000) {
    return 1;
  }
  return 0;
}

int
is_pcr(TPM2_HANDLE handle) {
  if (handle < TPM2_MAX_PCRS) {
    return 1;
  }
  return 0;
}

