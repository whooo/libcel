/* Copyright (c) 2022 by Erik Larsson
   SPDX-License-Identifier: GPL-3.0-or-later
*/

#include <tss2/tss2_tpm2_types.h>
#include <stdio.h>
#include <string.h>
#include "cel_types.h"

struct {
  TPM2_ALG_ID alg;
  const char *algstr;
} alg_str[] = {
  {
    .alg = TPM2_ALG_SHA1,
    .algstr = "sha1",
  },
  {
    .alg = TPM2_ALG_SHA256,
    .algstr = "sha256",
  },
  {
    .alg = TPM2_ALG_SHA384,
    .algstr = "sha384",
  },
  {
    .alg = TPM2_ALG_SHA512,
    .algstr = "sha512",
  },
  {
    .alg = TPM2_ALG_SM3_256,
    .algstr = "sm3_256",
  },
  {
    .alg = TPM2_ALG_ERROR,
    .algstr = NULL,
  }
};

struct {
  uint32_t type;
  const char *typestr;
} pcclient_str[] = {
  {
    .type = 0x00000001,
    .typestr = "ev_post_code",
  },
  {
    .type = 0x00000003,
    .typestr = "ev_no_action",
  },
  {
    .type = 0x00000004,
    .typestr = "ev_separator",
  },
  {
    .type = 0x00000005,
    .typestr = "ev_action",
  },
  {
    .type = 0x00000006,
    .typestr = "ev_event_tag",
  },
  {
    .type = 0x00000007,
    .typestr = "ev_s_crtm_contents",
  },
  {
    .type = 0x00000008,
    .typestr = "ev_s_crtm_version",
  },
  {
    .type = 0x00000009,
    .typestr = "ev_cpu_microcode",
  },
  {
    .type = 0x0000000A,
    .typestr = "ev_platform_config_flags",
  },
  {
    .type = 0x0000000B,
    .typestr = "ev_table_of_devices",
  },
  {
    .type = 0x0000000C,
    .typestr = "ev_compact_hash",
  },
  {
    .type = 0x0000000D,
    .typestr = "ev_ipl",
  },
  {
    .type = 0x0000000E,
    .typestr = "ev_ipl_partition_data",
  },
  {
    .type = 0x0000000F,
    .typestr = "ev_nonhost_code",
  },
  {
    .type = 0x00000010,
    .typestr = "ev_nonhost_config",
  },
  {
    .type = 0x00000011,
    .typestr = "ev_nonhost_info",
  },
  {
    .type = 0x00000012,
    .typestr = "ev_omit_boot_device_events",
  },
  {
    .type = 0x80000001,
    .typestr = "ev_efi_variable_driver_config",
  },
  {
    .type = 0x80000002,
    .typestr = "ev_efi_variable_boot",
  },
  {
    .type = 0x80000003,
    .typestr = "ev_efi_boot_services_application",
  },
  {
    .type = 0x80000004,
    .typestr = "ev_efi_boot_services_driver",
  },
  {
    .type = 0x80000005,
    .typestr = "ev_efi_runtime_services_driver",
  },
  {
    .type = 0x80000006,
    .typestr = "ev_efi_gpt_event",
  },
  {
    .type = 0x80000007,
    .typestr = "ev_efi_action",
  },
  {
    .type = 0x80000008,
    .typestr = "ev_efi_platform_firmware_blob",
  },
  {
    .type = 0x80000009,
    .typestr = "ev_efi_handoff_tables",
  },
  {
    .type = 0x8000000A,
    .typestr = "ev_efi_platform_firmwate_blob2",
  },
  {
    .type = 0x8000000B,
    .typestr = "ev_efi_handoff_tables2",
  },
  {
    .type = 0x8000000C,
    .typestr = "ev_efi_variable_boot2",
  },
  {
    .type = 0x80000010,
    .typestr = "ev_efi_hcrtm_event",
  },
  {
    .type = 0x800000E0,
    .typestr = "ev_efi_variable_authority",
  },
  {
    .type = 0x800000E1,
    .typestr = "ev_efi_spdm_firmware_blob",
  },
  {
    .type = 0x800000E2,
    .typestr = "ev_efi_spdm_firmware_config",
  },
  {
    .type = 0,
    .typestr = NULL,
  },
};

struct {
  CEL_TYPE type;
  const char *typestr;
} content_type_str[] = {
  {
    .type = CEL_TYPE_MGMT,
    .typestr = "cel",
  },
  {
    .type = CEL_TYPE_PCCLIENT_STD,
    .typestr = "pcclient_std",
  },
  {
    .type = CEL_TYPE_IMA_TEMPLATE,
    .typestr = "ima_template",
  },
  {
    .type = CEL_TYPE_IMA_TLV,
    .typestr = "ima_tlv",
  },
  {
    .type = CEL_TYPE_SYSTEMD,
    .typestr = "systemd",
  },
  {
    .type = 0,
    .typestr = NULL,
  },
};

struct {
  CEL_TYPE type;
  const char *typestr;
} mgt_type_str[] = {
  {
    .type = CEL_TYPE_MGMT_CEL_VERSION,
    .typestr = "cel_version",
  },
  {
    .type = CEL_TYPE_MGMT_FIRMWARE_END,
    .typestr = "firmware_end",
  },
  {
    .type = CEL_TYPE_MGMT_CEL_TIMESTAMP,
    .typestr = "cel_timestamp",
  },
  {
    .type = CEL_TYPE_MGMT_STATE_TRANS,
    .typestr = "state_trans",
  },
  {
    .type = 0,
    .typestr = NULL,
  },
};

struct {
  TPMI_STATE_TRANS trans;
  const char *transstr;
} state_trans_str[] = {
  {
    .trans = CEL_STATE_TRANS_SUSPEND,
    .transstr = "suspend",
  },
  {
    .trans = CEL_STATE_TRANS_HIBERNATE,
    .transstr = "hibernate",
  },
  {
    .trans = CEL_STATE_TRANS_KEXEC,
    .transstr = "kexec",
  },
  {
    .trans = 0xFF,
    .transstr = NULL,
  },
};

struct {
  TPMI_SYSTEMD_EVENTS type;
  const char *typestr;
} systemd_event_str[] = {
  {
    .type = CEL_TYPE_SYSTEMD_EVENT_PHASE,
    .typestr = "phase",
  },
  {
    .type = CEL_TYPE_SYSTEMD_EVENT_FILESYSTEM,
    .typestr = "filesystem",
  },
  {
    .type = CEL_TYPE_SYSTEMD_EVENT_VOLUME_KEY,
    .typestr = "volume-key",
  },
  {
    .type = CEL_TYPE_SYSTEMD_EVENT_MACHINE_ID,
    .typestr = "machine-id",
  },
  {
    .type = 0xFF,
    .typestr = NULL,
  }
};

const char *
alg_to_str(TPM2_ALG_ID alg) {
  for (int i=0;alg_str[i].alg != TPM2_ALG_ERROR;i++) {
    if (alg_str[i].alg == alg) {
      return alg_str[i].algstr;
    }
  }

  return NULL;
}

CEL_RC
str_to_alg(const char *str, TPM2_ALG_ID *dest) {
  for (int i=0;alg_str[i].algstr != NULL;i++) {
    if (!strcasecmp(str, alg_str[i].algstr)) {
      *dest = alg_str[i].alg;
      return CEL_RC_SUCCESS;
    }
  }

  return CEL_RC_INVALID_TYPE;
}

CEL_RC
hexlify(const uint8_t *src, size_t src_len, char *dst, size_t dst_len) {
  if (dst_len < (src_len * 2) + 1) {
    return CEL_RC_SHORT_BUFFER;
  }

  for (size_t i=0;i < src_len;i++) {
    snprintf((char *) dst + (i * 2), 3, "%02x", src[i]);
  }
  dst[dst_len - 1] = '\x00';

  return CEL_RC_SUCCESS;
}

CEL_RC
unhexlify(const char *src, uint8_t *dst, size_t dst_len) {
  int r;
  size_t sl;

  sl = strlen(src);
  if (sl % 2) {
    return CEL_RC_INVALID_VALUE;
  }
  if (strlen(src) > dst_len * 2) {
    return CEL_RC_SHORT_BUFFER;
  }

  for (size_t i=0;i < dst_len && (i*2) < sl;i++) {
    r = sscanf(src + (i*2), "%2hhx", dst + i);
    if (r != 1) {
      return CEL_RC_INVALID_VALUE;
    }
  }
  return CEL_RC_SUCCESS;
}

const char *
pcclient_event_to_str(uint32_t event_type) {
  for (int i=0;pcclient_str[i].typestr != NULL;i++) {
    if (pcclient_str[i].type == event_type) {
      return pcclient_str[i].typestr;
    }
  }

  return NULL;
}

CEL_RC
str_to_pcclient_event(const char *str, uint32_t *dest) {
  for (int i=0;pcclient_str[i].typestr != NULL;i++) {
    if (!strcasecmp(str, pcclient_str[i].typestr)) {
      *dest = pcclient_str[i].type;
      return CEL_RC_SUCCESS;
    }
  }
  return CEL_RC_INVALID_VALUE;
}

const char *
mgt_type_to_str(CEL_TYPE type) {
  for (int i=0;mgt_type_str[i].typestr != NULL;i++) {
    if (mgt_type_str[i].type == type) {
      return mgt_type_str[i].typestr;
    }
  }

  return NULL;
}

CEL_RC
str_to_mgt_type(const char *str, TPMI_CELMGTTYPE *dest) {
  for (int i=0;mgt_type_str[i].typestr != NULL;i++) {
    if (!strcasecmp(str, mgt_type_str[i].typestr)) {
      *dest = mgt_type_str[i].type;
      return CEL_RC_SUCCESS;
    }
  }

  return CEL_RC_INVALID_TYPE;
}

const char *
content_type_to_str(CEL_TYPE type) {
  for (int i=0;content_type_str[i].typestr != NULL;i++) {
    if (content_type_str[i].type == type) {
      return content_type_str[i].typestr;
    }
  }

  return NULL;
}

CEL_RC
str_to_content_type(const char *str, CEL_TYPE *dest) {
  for (int i=0;content_type_str[i].typestr != NULL;i++) {
    if (!strcasecmp(str, content_type_str[i].typestr)) {
      *dest = content_type_str[i].type;
      return CEL_RC_SUCCESS;
    }
  }

  return CEL_RC_INVALID_TYPE;
}

const char *
state_trans_to_str(TPMI_STATE_TRANS trans) {
  for (int i=0;state_trans_str[i].transstr != NULL;i++) {
    if (state_trans_str[i].trans == trans) {
      return state_trans_str[i].transstr;
    }
  }

  return NULL;
}

CEL_RC
str_to_state_trans(const char *str, TPMI_STATE_TRANS *dest) {
  for (int i=0;state_trans_str[i].transstr != NULL;i++) {
    if (!strcasecmp(str, state_trans_str[i].transstr)) {
      *dest = state_trans_str[i].trans;
      return CEL_RC_SUCCESS;
    }
  }
  return CEL_RC_INVALID_VALUE;
}

const char *
systemd_event_to_str(TPMI_SYSTEMD_EVENTS event_type) {
  for (int i=0;systemd_event_str[i].typestr != NULL;i++) {
    if (systemd_event_str[i].type == event_type) {
      return systemd_event_str[i].typestr;
    }
  }

  return NULL;
}

CEL_RC
str_to_systemd_event(const char *str, TPMI_SYSTEMD_EVENTS *dest) {
  for (int i=0;systemd_event_str[i].typestr != NULL;i++) {
    if (!strcasecmp(str, systemd_event_str[i].typestr)) {
      *dest = systemd_event_str[i].type;
      return CEL_RC_SUCCESS;
    }
  }
  return CEL_RC_INVALID_TYPE;
}
