/* Copyright (c) 2022 by Erik Larsson
   SPDX-License-Identifier: GPL-3.0-or-later
*/

#include <stddef.h>
#include <endian.h>
#include <string.h>
#include "cel_io.h"
#include "cel_types.h"

#define UINT64_MSB 0xFF00000000000000
#define INT_MAX_BYTES 8
#define TL_SIZE 5

CEL_RC
put_tlv(
  CEL_TYPE t,
  UINT32 l,
  const void *v,
  uint8_t *buffer,
  size_t len,
  size_t *offset)
{
  size_t off = get_offset(offset);
  UINT32 be_l = htobe32(l);

  if (buffer && is_buffer_short(len, off, TL_SIZE + l)) {
    return CEL_RC_SHORT_BUFFER;
  }

  if (buffer) {
    buffer[off] = t;
    off++;
    memcpy(buffer + off, &be_l, 4);
    off += sizeof(UINT32);
    if (v) {
      memcpy(buffer + off, v, l);
      off += l;
    }
  } else {
    off += TL_SIZE;
    if (v) {
      off += l;
    }
  }

  set_offset(offset, off);

  return CEL_RC_SUCCESS;
}

CEL_RC
get_tl_with_type(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  CEL_TYPE type,
  UINT32 *sublen)
{
  CEL_RC r;
  size_t off = get_offset(offset);

  CHECK_NULL(buffer);
  CHECK_NULL(sublen);

  if (is_buffer_short(len, off, TL_SIZE)) {
    return CEL_RC_SHORT_BUFFER;
  }

  if (buffer[off] != type) {
    return CEL_RC_INVALID_TYPE;
  }
  off++;

  r = get_be_uint32(buffer, len, &off, sublen);
  if (r) {
    return r;
  }

  if (is_buffer_short(len, off, *sublen)) {
    return CEL_RC_SHORT_BUFFER;
  }

  set_offset(offset, off);

  return CEL_RC_SUCCESS;
}

CEL_RC
CEL_TLV_UINT64_Marshal(
  CEL_TYPE type,
  UINT64 src,
  uint8_t *buffer,
  size_t len,
  size_t *offset)
{
  UINT32 r, num_len = INT_MAX_BYTES;
  size_t off = get_offset(offset);
  UINT64 be_src = htobe64(src);
  BYTE *be_ptr = (BYTE *) &be_src;

  for (UINT32 i=0;i < (num_len*8);i++) {
    if (src & (UINT64_MSB >> (i*8))) {
      break;
    }
    num_len--;
    be_ptr++;
  }

  if (!num_len) {
    num_len++; // all zeros are one byte
    be_ptr--;
  }

  r = put_tlv(type, num_len, be_ptr, buffer, len, &off);
  if (r) {
    return r;
  }

  set_offset(offset, off);

  return CEL_RC_SUCCESS;
}

CEL_RC
CEL_TLV_RECNUM_Marshal(
  RECNUM src,
  uint8_t *buffer,
  size_t len,
  size_t *offset)
{
  return CEL_TLV_UINT64_Marshal(CEL_TYPE_RECNUM,
				src,
				buffer,
				len, offset);
}

CEL_RC
CEL_TLV_NV_INDEX_Marshal(
  UINT32 src,
  uint8_t *buffer,
  size_t len,
  size_t *offset)
{
  return CEL_TLV_UINT64_Marshal(CEL_TYPE_NV_INDEX,
				src,
				buffer,
				len,
				offset);
}

CEL_RC
CEL_TLV_PCR_Marshal(
  UINT32 src,
  uint8_t *buffer,
  size_t len,
  size_t *offset)
{
  return CEL_TLV_UINT64_Marshal(CEL_TYPE_PCR,
				src,
				buffer,
				len,
				offset);
}

CEL_RC
CEL_TLV_TPMT_HA_Marshal(
  const TPMT_HA *src,
  uint8_t *buffer,
  size_t len,
  size_t *offset)
{
  CEL_RC r;
  int digsize;
  size_t off = get_offset(offset);

  CHECK_NULL(src);

  digsize = get_digest_size(src->hashAlg);
  if (!digsize) {
    return CEL_RC_UNSUPPORTED_DIGEST;
  }

  r = put_tlv(src->hashAlg,
	      digsize,
	      src->digest.sha512,
	      buffer,
	      len,
	      &off);
  if (r) {
    return r;
  }

  set_offset(offset, off);

  return CEL_RC_SUCCESS;
}

CEL_RC
CEL_TLV_TPML_DIGEST_VALUES_Marshal(
  const TPML_DIGEST_VALUES *src,
  uint8_t *buffer,
  size_t len,
  size_t *offset)
{
  CEL_RC r;
  size_t off = get_offset(offset), suboff = 0;

  CHECK_NULL(src);

  for (UINT32 i=0;i < src->count;i++) {
    r = CEL_TLV_TPMT_HA_Marshal(&src->digests[i], NULL, 0, &suboff);
    if (r) {
      return r;
    }
  }

  r = put_tlv(CEL_TYPE_DIGESTS, suboff, NULL, buffer, len, &off);
  if (r) {
    return r;
  }

  for (UINT32 i=0;i < src->count;i++) {
    r = CEL_TLV_TPMT_HA_Marshal(&src->digests[i], buffer, len, &off);
    if (r) {
      return r;
    }
  }

  set_offset(offset, off);

  return CEL_RC_SUCCESS;
}

CEL_RC
CEL_TLV_TPMS_CEL_VERSION_Marshal(
  const TPMS_CEL_VERSION *src,
  uint8_t *buffer,
  size_t len,
  size_t *offset)
{
  CEL_RC r;
  size_t off = get_offset(offset), suboff = 0;

  CHECK_NULL(src);

  CEL_TLV_UINT64_Marshal(CEL_TYPE_MGMT_CEL_VERSION_MAJOR,
			 src->major,
			 NULL,
			 0,
			 &suboff);
  CEL_TLV_UINT64_Marshal(CEL_TYPE_MGMT_CEL_VERSION_MINOR,
			 src->minor,
			 NULL,
			 0,
			 &suboff);

  r = put_tlv(CEL_TYPE_MGMT_CEL_VERSION,
	      suboff,
	      NULL,
	      buffer,
	      len,
	      &off);
  if (r) {
    return r;
  }

  r = CEL_TLV_UINT64_Marshal(CEL_TYPE_MGMT_CEL_VERSION_MAJOR,
			     src->major,
			     buffer,
			     len,
			     &off);
  if (r) {
    return r;
  }

  r = CEL_TLV_UINT64_Marshal(CEL_TYPE_MGMT_CEL_VERSION_MINOR,
			     src->minor,
			     buffer,
			     len,
			     &off);
  if (r) {
    return r;
  }

  set_offset(offset, off);

  return CEL_RC_SUCCESS;
}

CEL_RC
CEL_TLV_TPMS_EVENT_CELMGT_Marshal(
  const TPMS_EVENT_CELMGT *src,
  uint8_t *buffer,
  size_t len,
  size_t *offset)
{
  CEL_RC r;
  size_t off = get_offset(offset);

  CHECK_NULL(src);

  switch (src->type) {
  case CEL_TYPE_MGMT_CEL_VERSION:
    r = CEL_TLV_TPMS_CEL_VERSION_Marshal(&src->data.cel_version,
					 buffer,
					 len,
					 &off);
    break;
  case CEL_TYPE_MGMT_FIRMWARE_END:
    r = put_tlv(CEL_TYPE_MGMT_FIRMWARE_END,
		0,
		NULL,
		buffer,
		len,
		&off);
    break;
  case CEL_TYPE_MGMT_CEL_TIMESTAMP:
    r = CEL_TLV_UINT64_Marshal(CEL_TYPE_MGMT_CEL_TIMESTAMP,
			       src->data.cel_timestamp,
			       buffer,
			       len,
			       &off);
    break;
  case CEL_TYPE_MGMT_STATE_TRANS:
    r = CEL_TLV_UINT64_Marshal(CEL_TYPE_MGMT_STATE_TRANS,
			       src->data.state_trans,
			       buffer,
			       len,
			       &off);
    break;
  default:
    return CEL_RC_INVALID_TYPE;
  }
  if (r) {
    return r;
  }

  set_offset(offset, off);

  return CEL_RC_SUCCESS;
}

CEL_RC
CEL_TLV_TPML_EVENT_CELMGT_Marshal(
  const TPML_EVENT_CELMGT *src,
  uint8_t *buffer,
  size_t len,
  size_t *offset)
{
  CEL_RC r;
  size_t off = get_offset(offset), suboff = 0;

  CHECK_NULL(src);

  for (UINT16 i=0;i < src->count;i++) {
    r = CEL_TLV_TPMS_EVENT_CELMGT_Marshal(&src->events[i],
					  NULL,
					  0,
					  &suboff);
    if (r) {
      return r;
    }
  }

  r = put_tlv(CEL_TYPE_MGMT, suboff, NULL, buffer, len, &off);
  if (r) {
    return r;
  }

  for (UINT16 i=0;i < src->count;i++) {
    r = CEL_TLV_TPMS_EVENT_CELMGT_Marshal(&src->events[i],
					  buffer,
					  len,
					  &off);
    if (r) {
      return r;
    }
  }

  set_offset(offset, off);

  return CEL_RC_SUCCESS;
}

CEL_RC
CEL_TLV_BYTEBUFFER_Marshal(
  CEL_TYPE type,
  const BYTEBUFFER *src,
  uint8_t *buffer,
  size_t len,
  size_t *offset)
{
  return put_tlv(type, src->size, src->buffer, buffer, len, offset);
}

CEL_RC
CEL_TLV_STRING_Marshal(
  CEL_TYPE type,
  const char *src,
  uint8_t *buffer,
  size_t len,
  size_t *offset)
{
  size_t slen = strlen(src);
  return put_tlv(type, slen, src, buffer, len, offset);
}

CEL_RC
CEL_TLV_TPMS_EVENT_PCCLIENT_STD_Marshal(
  const TPMS_EVENT_PCCLIENT_STD *src,
  uint8_t *buffer,
  size_t len,
  size_t *offset)
{
  CEL_RC r;
  size_t off = get_offset(offset), suboff = 0;

  CHECK_NULL(src);

  CEL_TLV_UINT64_Marshal(CEL_TYPE_PCCLIENT_STD_EVENT_TYPE,
			 src->event_type,
			 NULL,
			 0,
			 &suboff);
  CEL_TLV_BYTEBUFFER_Marshal(CEL_TYPE_PCCLIENT_STD_EVENT_DATA,
			     &src->event_data,
			     NULL,
			     0,
			     &suboff);

  r = put_tlv(CEL_TYPE_PCCLIENT_STD, suboff, NULL, buffer, len, &off);
  if (r) {
    return r;
  }

  r = CEL_TLV_UINT64_Marshal(CEL_TYPE_PCCLIENT_STD_EVENT_TYPE,
			     src->event_type,
			     buffer,
			     len,
			     &off);
  if (r) {
    return r;
  }

  r = CEL_TLV_BYTEBUFFER_Marshal(CEL_TYPE_PCCLIENT_STD_EVENT_DATA,
				 &src->event_data,
				 buffer,
				 len,
				 &off);
  if (r) {
    return r;
  }

  set_offset(offset, off);

  return CEL_RC_SUCCESS;
}

CEL_RC
CEL_TLV_TPMS_EVENT_IMA_TEMPLATE_Marshal(
  const TPMS_EVENT_IMA_TEMPLATE *src,
  uint8_t *buffer,
  size_t len,
  size_t *offset)
{
  CEL_RC r;
  size_t off = get_offset(offset), suboff = 0;

  CHECK_NULL(src);

  CEL_TLV_STRING_Marshal(CEL_TYPE_IMA_TEMPLATE_NAME,
			 src->template_name,
			 NULL,
			 0,
			 &suboff);
  CEL_TLV_BYTEBUFFER_Marshal(CEL_TYPE_IMA_TEMPLATE_DATA,
			     &src->template_data,
			     NULL,
			     0,
			     &suboff);

  r = put_tlv(CEL_TYPE_IMA_TEMPLATE, suboff, NULL, buffer, len, &off);
  if (r) {
    return r;
  }

  r = CEL_TLV_STRING_Marshal(CEL_TYPE_IMA_TEMPLATE_NAME,
			     src->template_name,
			     buffer,
			     len,
			     &off);
  if (r) {
    return r;
  }

  r = CEL_TLV_BYTEBUFFER_Marshal(CEL_TYPE_IMA_TEMPLATE_DATA,
				 &src->template_data,
				 buffer,
				 len,
				 &off);
  if (r) {
    return r;
  }

  set_offset(offset, off);

  return CEL_RC_SUCCESS;
}

CEL_RC
CEL_TLV_TPMS_CEL_EVENT_Marshal(
  const TPMS_CEL_EVENT *src,
  uint8_t *buffer,
  size_t len,
  size_t *offset)
{
  CEL_RC r;
  size_t off = get_offset(offset);
  const TPMU_EVENT_CONTENT *cont = NULL;

  CHECK_NULL(src);
  cont = &src->content;

  r = CEL_TLV_RECNUM_Marshal(src->recnum, buffer, len, &off);
  if (r) {
    return r;
  }

  if (is_nv_index(src->nv_index)) {
    r = CEL_TLV_NV_INDEX_Marshal(src->nv_index, buffer, len, &off);
  } else if (is_pcr(src->pcr)) {
    r = CEL_TLV_PCR_Marshal(src->pcr, buffer, len, &off);
  } else {
    return CEL_RC_INVALID_VALUE;
  }
  if (r) {
    return r;
  }

  r = CEL_TLV_TPML_DIGEST_VALUES_Marshal(&src->digests,
					 buffer,
					 len,
					 &off);
  if (r) {
    return r ;
  }

  switch (src->content_type) {
  case CEL_TYPE_MGMT:
    r = CEL_TLV_TPML_EVENT_CELMGT_Marshal(&cont->celmgt,
					  buffer,
					  len,
					  &off);
    break;
  case CEL_TYPE_PCCLIENT_STD:
    r = CEL_TLV_TPMS_EVENT_PCCLIENT_STD_Marshal(&cont->pcclient_std,
						buffer,
						len,
						&off);
    break;
  case CEL_TYPE_IMA_TEMPLATE:
    r = CEL_TLV_TPMS_EVENT_IMA_TEMPLATE_Marshal(&cont->ima_template,
						buffer,
						len,
						&off);
    break;
  default:
    r = CEL_RC_INVALID_TYPE;
  }
  if (r) {
    return r;
  }

  set_offset(offset, off);

  return CEL_RC_SUCCESS;
}

CEL_RC
get_type(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  CEL_TYPE *type)
{
  size_t off = get_offset(offset);

  CHECK_NULL(type);

  if (is_buffer_short(len, off, 1)) {
    return CEL_RC_SHORT_BUFFER;
  }

  *type = buffer[off];
  off++;

  set_offset(offset, off);

  return CEL_RC_SUCCESS;
}

CEL_RC
peek_type(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  CEL_TYPE *type)
{
  CEL_RC r;

  r = get_type(buffer, len, offset, type);
  if (r) {
    return r;
  }

  if (offset) {
    *offset -= 1;
  }

  return CEL_RC_SUCCESS;
}

CEL_RC
CEL_TLV_UINT64_Unmarshal(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  CEL_TYPE type,
  UINT64 *dest)
{
  CEL_RC r;
  UINT32 num_len = 0;
  UINT64 ti = 0;
  size_t off = get_offset(offset);

  CHECK_NULL(buffer);
  CHECK_NULL(dest);

  r = get_tl_with_type(buffer, len, &off, type, &num_len);
  if (r) {
    return r;
  }

  if (num_len > 8) {
    return CEL_RC_VALUE_TOO_LARGE;
  }

  memcpy((uint8_t *) &ti + (8 - num_len), buffer + off, num_len);
  *dest = be64toh(ti);
  off += num_len;

  set_offset(offset, off);

  return CEL_RC_SUCCESS;
}

CEL_RC
CEL_TLV_UINT32_Unmarshal(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  CEL_TYPE type,
  UINT32 *dest)
{
  CEL_RC r;
  UINT64 ti = 0;
  size_t off = get_offset(offset);

  CHECK_NULL(buffer);
  CHECK_NULL(dest);

  r = CEL_TLV_UINT64_Unmarshal(buffer, len, &off, type, &ti);
  if (r) {
    return r;
  }

  if (ti > UINT32_MAX) {
    return CEL_RC_VALUE_TOO_LARGE;
  }

  *dest = ti;

  set_offset(offset, off);

  return CEL_RC_SUCCESS;
}

CEL_RC
CEL_TLV_UINT16_Unmarshal(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  CEL_TYPE type,
  UINT16 *dest)
{
  CEL_RC r;
  UINT64 ti = 0;
  size_t off = get_offset(offset);

  CHECK_NULL(buffer);
  CHECK_NULL(dest);

  r = CEL_TLV_UINT64_Unmarshal(buffer, len, &off, type, &ti);
  if (r) {
    return r;
  }

  if (ti > UINT16_MAX) {
    return CEL_RC_VALUE_TOO_LARGE;
  }

  *dest = ti;

  set_offset(offset, off);

  return CEL_RC_SUCCESS;
}

CEL_RC
CEL_TLV_RECNUM_Unmarshal(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  RECNUM *dest)
{
  return CEL_TLV_UINT64_Unmarshal(buffer,
				  len,
				  offset,
				  CEL_TYPE_RECNUM,
				  dest);
}

CEL_RC
CEL_TLV_NV_INDEX_Unmarshal(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  TPM2_HANDLE *dest)
{
  return CEL_TLV_UINT32_Unmarshal(buffer,
				  len,
				  offset,
				  CEL_TYPE_NV_INDEX,
				  dest);
}

CEL_RC
CEL_TLV_PCR_Unmarshal(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  TPM2_HANDLE *dest)
{
  return CEL_TLV_UINT32_Unmarshal(buffer,
				  len,
				  offset,
				  CEL_TYPE_PCR,
				  dest);
}

CEL_RC
CEL_TLV_TPMT_HA_Unmarshal(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  TPMT_HA *dest)
{
  CEL_RC r;
  UINT32 diglen;
  CEL_TYPE alg;
  size_t off = get_offset(offset), digsize;

  CHECK_NULL(buffer);
  CHECK_NULL(dest);

  r = get_type(buffer, len, &off, &alg);
  if (r) {
    return r;
  }
  dest->hashAlg = alg;

  digsize = get_digest_size(alg);
  if (!digsize) {
    return CEL_RC_UNSUPPORTED_DIGEST;
  }

  r = get_be_uint32(buffer, len, &off, &diglen);
  if (r) {
    return r;
  }
  if (diglen != digsize) {
    return CEL_RC_INVALID_VALUE;
  }
  r = get_bytes(buffer, len, &off, dest->digest.sha512, digsize);
  if (r) {
    return r;
  }

  set_offset(offset, off);

  return CEL_RC_SUCCESS;
}

CEL_RC CEL_TLV_TPML_DIGEST_VALUES_Unmarshal(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  TPML_DIGEST_VALUES *dest)
{
  CEL_RC r;
  UINT32 sublen = 0;
  size_t off = get_offset(offset), suboff = 0;

  CHECK_NULL(buffer);
  CHECK_NULL(dest);

  r = get_tl_with_type(buffer, len, &off, CEL_TYPE_DIGESTS, &sublen);
  if (r) {
    return r;
  }

  dest->count = 0;
  while (suboff < sublen && dest->count < TPM2_NUM_PCR_BANKS) {
    r = CEL_TLV_TPMT_HA_Unmarshal(buffer + off,
				  sublen,
				  &suboff,
				  &dest->digests[dest->count]);
    if (r) {
      return r;
    }
    dest->count++;
  }
  off += suboff;

  set_offset(offset, off);

  return CEL_RC_SUCCESS;
}

CEL_RC
CEL_TLV_TPMS_CEL_VERSION_Unmarshal(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  TPMS_CEL_VERSION *dest)
{
  CEL_RC r;
  UINT32 sublen;
  size_t off = get_offset(offset), suboff = 0;
  CEL_TYPE type;
  enum { CheckType = 0, SetMajor = 1, SetMinor = 2, Done = 3 } state =
    CheckType, compl = CheckType;

  CHECK_NULL(buffer);
  CHECK_NULL(dest);

  r = get_tl_with_type(buffer,
		       len,
		       &off,
		       CEL_TYPE_MGMT_CEL_VERSION,
		       &sublen);
  if (r) {
    return r;
  }

  while (compl < Done) {
    compl += state;
    switch (state) {
    case CheckType:
      r = peek_type(buffer + off, sublen, &suboff, &type);
      if (r) {
	break;
      }
      switch (type) {
      case CEL_TYPE_MGMT_CEL_VERSION_MAJOR:
	state = SetMajor;
	break;
      case CEL_TYPE_MGMT_CEL_VERSION_MINOR:
	state = SetMinor;
	break;
      default:
	r = CEL_RC_INVALID_TYPE;
	break;
      }
      break;
    case SetMajor:
      state = SetMinor;
      r = CEL_TLV_UINT16_Unmarshal(buffer + off,
				   sublen,
				   &suboff,
				   CEL_TYPE_MGMT_CEL_VERSION_MAJOR,
				   &dest->major);
      break;
    case SetMinor:
      state = SetMajor;
      r = CEL_TLV_UINT16_Unmarshal(buffer + off,
				   sublen,
				   &suboff,
				   CEL_TYPE_MGMT_CEL_VERSION_MINOR,
				   &dest->minor);
      break;
    case Done:
      break;
    default:
      r = CEL_RC_INVALID_TYPE;
      break;
    }
    if (r) {
      return r;
    }
  }
  if (suboff < sublen) {
    return CEL_RC_INVALID_VALUE;
  }
  off += suboff;

  set_offset(offset, off);

  return CEL_RC_SUCCESS;
}

CEL_RC
CEL_TLV_TPMS_EVENT_CELMGT_Unmarshal(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  TPMS_EVENT_CELMGT *dest)
{
  CEL_RC r;
  UINT32 num_len = 0;
  CEL_TYPE type;
  size_t off = get_offset(offset);

  CHECK_NULL(buffer);
  CHECK_NULL(dest);

  r = peek_type(buffer, len, &off, &type);
  if (r) {
    return r;
  }

  dest->type = type;

  switch (type) {
  case CEL_TYPE_MGMT_CEL_VERSION:
    r = CEL_TLV_TPMS_CEL_VERSION_Unmarshal(buffer,
					   len,
					   &off,
					   &dest->data.cel_version);
    break;
  case CEL_TYPE_MGMT_FIRMWARE_END:
    off++;
    r = get_be_uint32(buffer, len, &off, &num_len);
    if (!r && num_len) {
      r = CEL_RC_INVALID_VALUE;
    }
    break;
  case CEL_TYPE_MGMT_CEL_TIMESTAMP:
    r = CEL_TLV_UINT64_Unmarshal(buffer, len,
				 &off,
				 CEL_TYPE_MGMT_CEL_TIMESTAMP,
				 &dest->data.cel_timestamp);
    break;
  case CEL_TYPE_MGMT_STATE_TRANS:
    r = CEL_TLV_UINT32_Unmarshal(buffer,
				 len,
				 &off,
				 CEL_TYPE_MGMT_STATE_TRANS,
				 &dest->data.state_trans);
    break;
  default:
    r = CEL_RC_INVALID_TYPE;
  }
  if (r) {
    return r;
  }

  set_offset(offset, off);

  return CEL_RC_SUCCESS;
}

CEL_RC
CEL_TLV_BYTEBUFFER_Unmarshal(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  CEL_TYPE type,
  BYTEBUFFER *dest)
{
  CEL_RC r;
  UINT32 data_len;
  size_t off = get_offset(offset);

  CHECK_NULL(buffer);
  CHECK_NULL(dest);

  r = get_tl_with_type(buffer, len, &off, type, &data_len);
  if (r) {
    return r;
  }
  if (data_len > sizeof(dest->buffer)) {
    return CEL_RC_VALUE_TOO_LARGE;
  }

  dest->size = data_len;
  memcpy(dest->buffer, buffer + off, data_len);
  off += data_len;

  set_offset(offset, off);

  return CEL_RC_SUCCESS;
}

CEL_RC
CEL_TLV_STRING_Unmarshal(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  CEL_TYPE type,
  char *dest,
  size_t size)
{
  CEL_RC r;
  UINT32 data_len;
  size_t off = get_offset(offset);

  CHECK_NULL(buffer);
  CHECK_NULL(dest);

  r = get_tl_with_type(buffer, len, &off, type, &data_len);
  if (r) {
    return r;
  }
  if (data_len >= size) {
    return CEL_RC_VALUE_TOO_LARGE;
  }

  memcpy(dest, buffer + off, data_len);
  dest[data_len] = '\x00';
  off += data_len;

  set_offset(offset, off);

  return CEL_RC_SUCCESS;
}

CEL_RC
CEL_TLV_TPMS_EVENT_PCCLIENT_STD_Unmarshal(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  TPMS_EVENT_PCCLIENT_STD *dest)
{
  CEL_RC r;
  UINT32 sublen;
  size_t off = get_offset(offset), suboff = 0;
  CEL_TYPE type;
  enum { CheckType = 0, SetType = 1, SetData = 2, Done = 3 } state =
    CheckType, compl = CheckType;

  CHECK_NULL(buffer);
  CHECK_NULL(dest);

  r = get_tl_with_type(buffer,
		       len,
		       &off,
		       CEL_TYPE_PCCLIENT_STD,
		       &sublen);
  if (r) {
    return r;
  }

  while (compl < Done) {
    compl += state;
    switch (state) {
    case CheckType:
      r = peek_type(buffer + off, sublen, &suboff, &type);
      if (r) {
	break;
      }
      switch (type) {
      case CEL_TYPE_PCCLIENT_STD_EVENT_TYPE:
	state = SetType;
	break;
      case CEL_TYPE_PCCLIENT_STD_EVENT_DATA:
	state = SetData;
	break;
      default:
	r = CEL_RC_INVALID_TYPE;
	break;
      }
      break;
    case SetType:
      state = SetData;
      r = CEL_TLV_UINT32_Unmarshal(buffer + off,
				   sublen,
				   &suboff,
				   CEL_TYPE_PCCLIENT_STD_EVENT_TYPE,
				   &dest->event_type);
      break;
    case SetData:
      state = SetType;
      r =
	CEL_TLV_BYTEBUFFER_Unmarshal(buffer + off,
				     sublen,
				     &suboff,
				     CEL_TYPE_PCCLIENT_STD_EVENT_DATA,
				     &dest->event_data);
      break;
    case Done:
      break;
    default:
      r = CEL_RC_INVALID_TYPE;
      break;
    }
    if (r) {
      return r;
    }
  }
  if (suboff < sublen) {
    return CEL_RC_INVALID_VALUE;
  }
  off += suboff;

  set_offset(offset, off);

  return CEL_RC_SUCCESS;
}

CEL_RC
CEL_TLV_TPMS_EVENT_IMA_TEMPLATE_Unmarshal(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  TPMS_EVENT_IMA_TEMPLATE *dest)
{
  CEL_RC r;
  UINT32 sublen;
  size_t off = get_offset(offset), suboff = 0;
  CEL_TYPE type;
  enum { CheckType = 0, SetName = 1, SetData = 2, Done = 3 } state =
    CheckType, compl = CheckType;

  CHECK_NULL(buffer);
  CHECK_NULL(dest);

  r = get_tl_with_type(buffer,
		       len,
		       &off,
		       CEL_TYPE_IMA_TEMPLATE,
		       &sublen);
  if (r) {
    return r;
  }

  while (compl < Done) {
    compl += state;
    switch (state) {
    case CheckType:
      r = peek_type(buffer + off, sublen, &suboff, &type);
      if (r) {
	break;
      }
      switch (type) {
      case CEL_TYPE_IMA_TEMPLATE_NAME:
	state = SetName;
	break;
      case CEL_TYPE_IMA_TEMPLATE_DATA:
	state = SetData;
	break;
      default:
	r = CEL_RC_INVALID_TYPE;
	break;
      }
      break;
    case SetName:
      state = SetData;
      r = CEL_TLV_STRING_Unmarshal(buffer + off,
				   sublen, &suboff,
				   CEL_TYPE_IMA_TEMPLATE_NAME,
				   dest->template_name,
				   sizeof(dest->template_name));
      break;
    case SetData:
      state = SetName;
      r = CEL_TLV_BYTEBUFFER_Unmarshal(buffer + off,
				       sublen,
				       &suboff,
				       CEL_TYPE_IMA_TEMPLATE_DATA,
				       &dest->template_data);
      break;
    case Done:
      break;
    default:
      r = CEL_RC_INVALID_TYPE;
      break;
    }
    if (r) {
      return r;
    }
  }
  if (suboff < sublen) {
    return CEL_RC_INVALID_VALUE;
  }
  off += suboff;

  set_offset(offset, off);

  return CEL_RC_SUCCESS;
}

CEL_RC
CEL_TLV_TPML_EVENT_CELMGT_Unmarshal(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  TPML_EVENT_CELMGT *dest)
{
  CEL_RC r;
  UINT32 sublen;
  size_t off = get_offset(offset), suboff = 0;

  CHECK_NULL(buffer);
  CHECK_NULL(dest);

  r = get_tl_with_type(buffer, len, &off, CEL_TYPE_MGMT, &sublen);
  if (r) {
    return r;
  }

  dest->count = 0;
  while (suboff < sublen && dest->count <= 15) {
    r =
      CEL_TLV_TPMS_EVENT_CELMGT_Unmarshal(buffer + off,
					  sublen,
					  &suboff,
					  &dest->events[dest->count]);
    if (r) {
      return r;
    }
    dest->count++;
  }
  if (suboff < sublen) {
    return CEL_RC_INVALID_VALUE;
  }
  off += suboff;

  set_offset(offset, off);

  return CEL_RC_SUCCESS;
}

CEL_RC
CEL_TLV_TPMS_CEL_EVENT_Unmarshal(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  TPMS_CEL_EVENT *dest)
{
  CEL_RC r;
  size_t off = get_offset(offset);
  CEL_TYPE type;
  TPMU_EVENT_CONTENT *cont = NULL;

  CHECK_NULL(buffer);
  CHECK_NULL(dest);
  cont = &dest->content;

  r = CEL_TLV_RECNUM_Unmarshal(buffer, len, &off, &dest->recnum);
  if (r) {
    return r;
  }

  r = peek_type(buffer, len, &off, &type);
  if (r) {
    return r;
  }
  switch (type) {
  case CEL_TYPE_PCR:
    r = CEL_TLV_PCR_Unmarshal(buffer, len, &off, &dest->pcr);
    break;
  case CEL_TYPE_NV_INDEX:
    r = CEL_TLV_NV_INDEX_Unmarshal(buffer,
				   len,
				   &off,
				   &dest->nv_index);
    break;
  default:
    r = CEL_RC_INVALID_TYPE;
    break;
  }
  if (r) {
    return r;
  }

  r = CEL_TLV_TPML_DIGEST_VALUES_Unmarshal(buffer,
					   len,
					   &off,
					   &dest->digests);
  if (r) {
    return r;
  }

  r = peek_type(buffer, len, &off, &type);
  if (r) {
    return r;
  }
  dest->content_type = type;

  switch (type) {
  case CEL_TYPE_MGMT:
    r = CEL_TLV_TPML_EVENT_CELMGT_Unmarshal(buffer,
					    len,
					    &off,
					    &cont->celmgt);
    break;
  case CEL_TYPE_PCCLIENT_STD:
    r =
      CEL_TLV_TPMS_EVENT_PCCLIENT_STD_Unmarshal(buffer,
						len,
						&off,
						&cont->pcclient_std);
    break;
  case CEL_TYPE_IMA_TEMPLATE:
    r =
      CEL_TLV_TPMS_EVENT_IMA_TEMPLATE_Unmarshal(buffer,
						len,
						&off,
						&cont->ima_template);
    break;
  default:
    r = CEL_RC_INVALID_TYPE;
    break;
  }
  if (r) {
    return r;
  }

  set_offset(offset, off);

  return CEL_RC_SUCCESS;
}

