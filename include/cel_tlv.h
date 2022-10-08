/* Copyright (c) 2022 by Erik Larsson
   SPDX-License-Identifier: GPL-3.0-or-later
*/

#include "cel_types.h"

#ifndef _CEL_TLV_H_
#define _CEL_TLV_H_

CEL_RC
CEL_TLV_RECNUM_Marshal(
  RECNUM src,
  uint8_t *buffer,
  size_t len,
  size_t *offset);

CEL_RC
CEL_TLV_NV_INDEX_Marshal(
  UINT32 src,
  uint8_t *buffer,
  size_t len,
  size_t *offset);

CEL_RC
CEL_TLV_PCR_Marshal(
  UINT32 src,
  uint8_t *buffer,
  size_t len,
  size_t *offset);

CEL_RC
CEL_TLV_TPMT_HA_Marshal(
  const TPMT_HA *src,
  uint8_t *buffer,
  size_t len,
  size_t *offset);

CEL_RC
CEL_TLV_TPML_DIGEST_VALUES_Marshal(
  const TPML_DIGEST_VALUES *src,
  uint8_t *buffer,
  size_t len,
  size_t *offset);

CEL_RC
CEL_TLV_TPMS_CEL_VERSION_Marshal(
  const TPMS_CEL_VERSION *src,
  uint8_t *buffer,
  size_t len,
  size_t *offset);

CEL_RC
CEL_TLV_TPMS_EVENT_CELMGT_Marshal(
  const TPMS_EVENT_CELMGT *src,
  uint8_t *buffer,
  size_t len,
  size_t *offset);

CEL_RC
CEL_TLV_TPML_EVENT_CELMGT_Marshal(
  const TPML_EVENT_CELMGT *src,
  uint8_t *buffer,
  size_t len,
  size_t *offset);

CEL_RC
CEL_TLV_TPMS_EVENT_PCCLIENT_STD_Marshal(
  const TPMS_EVENT_PCCLIENT_STD *src,
  uint8_t *buffer,
  size_t len,
  size_t *offset);

CEL_RC
CEL_TLV_TPMS_EVENT_IMA_TEMPLATE_Marshal(
  const TPMS_EVENT_IMA_TEMPLATE *src,
  uint8_t *buffer,
  size_t len,
  size_t *offset);

CEL_RC
CEL_TLV_TPMS_CEL_EVENT_Marshal(
  const TPMS_CEL_EVENT *src,
  uint8_t *buffer,
  size_t len,
  size_t *offset);

CEL_RC
CEL_TLV_RECNUM_Unmarshal(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  RECNUM *dest);

CEL_RC
CEL_TLV_NV_INDEX_Unmarshal(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  TPM2_HANDLE *dest);

CEL_RC
CEL_TLV_PCR_Unmarshal(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  TPM2_HANDLE *dest);

CEL_RC
CEL_TLV_TPMT_HA_Unmarshal(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  TPMT_HA *dest);

CEL_RC
CEL_TLV_TPML_DIGEST_VALUES_Unmarshal(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  TPML_DIGEST_VALUES *dest);

CEL_RC
CEL_TLV_TPMS_CEL_VERSION_Unmarshal(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  TPMS_CEL_VERSION *dest);

CEL_RC
CEL_TLV_TPMS_EVENT_CELMGT(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  TPMS_EVENT_CELMGT *dest);

CEL_RC
CEL_TLV_TPMS_EVENT_CELMGT_Unmarshal(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  TPMS_EVENT_CELMGT *dest);

CEL_RC
CEL_TLV_TPMS_EVENT_PCCLIENT_STD_Unmarshal(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  TPMS_EVENT_PCCLIENT_STD *dest);

CEL_RC
CEL_TLV_TPMS_EVENT_IMA_TEMPLATE_Unmarshal(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  TPMS_EVENT_IMA_TEMPLATE *dest);

CEL_RC
CEL_TLV_TPML_EVENT_CELMGT_Unmarshal(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  TPML_EVENT_CELMGT *dest);

CEL_RC
CEL_TLV_TPMS_CEL_EVENT_Unmarshal(
  const uint8_t *buffer,
  size_t len,
  size_t *offset,
  TPMS_CEL_EVENT *dest);

#endif
