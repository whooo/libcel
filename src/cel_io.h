/* Copyright (c) 2022 by Erik Larsson
   SPDX-License-Identifier: GPL-3.0-or-later
*/

#include <stdint.h>
#include <sys/types.h>
#include "cel_types.h"

#ifndef _CEL_IO_H_
#define _CEL_IO_H_

int
is_buffer_short(
  ssize_t len,
  ssize_t offset,
  ssize_t required);

CEL_RC
get_le_uint32(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  uint32_t *dst);

CEL_RC
get_le_uint16(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  uint16_t *dst);

CEL_RC
get_uefi_bytebuffer(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  BYTEBUFFER *dst);

CEL_RC
get_bytes(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  uint8_t *dst,
  size_t dstlen);

size_t
get_offset(
  const size_t *offset);

void
set_offset(
  size_t *dst,
  size_t src);

size_t
get_digest_size(
  TPM2_ALG_ID alg);

CEL_RC
get_be_uint32(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  UINT32 *dest);

#define CHECK_NULL(x) if (!x) { return CEL_RC_BAD_REFERENCE; }

#endif
