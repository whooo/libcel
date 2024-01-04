/* Copyright (c) 2022 by Erik Larsson
   SPDX-License-Identifier: GPL-3.0-or-later
*/

#include <tss2/tss2_tpm2_types.h>
#include "cel_types.h"

#ifndef _CEL_STRINGS_H_

#define MAX_DIGEST_HEX TPM2_SHA512_DIGEST_SIZE * 2

const char *
alg_to_str(TPM2_ALG_ID alg);

CEL_RC
str_to_alg(const char *str, TPM2_ALG_ID *dest);

CEL_RC
hexlify(const uint8_t *src, size_t src_len, char *dst, size_t dst_len);

CEL_RC
unhexlify(const char *src, uint8_t *dst, size_t dst_len);

const char *
pcclient_event_to_str(uint32_t event_type);

CEL_RC
str_to_pcclient_event(const char *str, uint32_t *dest);

const char *
mgt_type_to_str(CEL_TYPE type);

CEL_RC
str_to_mgt_type(const char *str, TPMI_CELMGTTYPE *dest);

const char *
content_type_to_str(CEL_TYPE type);

CEL_RC
str_to_content_type(const char *str, CEL_TYPE *dest);

const char *
state_trans_to_str(CEL_TYPE trans);

CEL_RC
str_to_state_trans(const char *str, TPMI_STATE_TRANS *dest);

const char *
systemd_event_to_str(TPMI_SYSTEMD_EVENTS event_type);

CEL_RC
str_to_systemd_event(const char *str, TPMI_SYSTEMD_EVENTS *dest);

#define _CEL_STRINGS_H_
#endif
