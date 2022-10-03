/* Copyright (c) 2022 by Erik Larsson
   SPDX-License-Identifier: GPL-3.0-or-later
*/

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include "cel_types.h"
#include "cel_tlv.h"

#define TL_SIZE 5

void test_tlv_recnum(void **state) {
  (void) state;
  RECNUM recnum = 1234, out_recnum;
  UINT32 r;
  size_t off = 0;
  uint8_t buffer[TL_SIZE + 2], expected_buffer[TL_SIZE + 2] = "\x00\x00\x00\x00\x02\x04\xD2", num_large_buffer[TL_SIZE] = "\x00\x00\x00\x00\x09";

  r = CEL_TLV_RECNUM_Marshal(recnum, buffer, 7, &off);
  assert_int_equal(r, 0);
  assert_int_equal(off, TL_SIZE + 2);
  assert_memory_equal(buffer, expected_buffer, TL_SIZE + 2);

  // test NULL buffer
  off = 0;
  r = CEL_TLV_RECNUM_Marshal(recnum, NULL, 1234, &off);
  assert_int_equal(r, 0);
  assert_int_equal(off, TL_SIZE + 2);

  // test too small buffer
  off = 100000000000;
  r = CEL_TLV_RECNUM_Marshal(recnum, buffer, 7, &off);
  assert_int_equal(r, CEL_RC_SHORT_BUFFER);

  // ummarshal
  off = 0;
  r = CEL_TLV_RECNUM_Unmarshal(buffer, TL_SIZE + 2, &off, &out_recnum);
  assert_int_equal(r, 0);
  assert_int_equal(off, TL_SIZE + 2);
  assert_int_equal(recnum, out_recnum);

  // unmarshal bad type
  off = 0;
  buffer[0] = 0xFF;
  r = CEL_TLV_RECNUM_Unmarshal(buffer, TL_SIZE + 2, &off, &out_recnum);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);

  // unmarshal NULL buffer
  r = CEL_TLV_RECNUM_Unmarshal(NULL, TL_SIZE + 2, &off, &out_recnum);
  assert_int_equal(r, CEL_RC_BAD_REFERENCE);

  // unmarshal NULL dest
  r = CEL_TLV_RECNUM_Unmarshal(buffer, TL_SIZE + 2, &off, NULL);
  assert_int_equal(r, CEL_RC_BAD_REFERENCE);

  // unmarshal large number
  off = 0;
  r = CEL_TLV_RECNUM_Unmarshal(num_large_buffer, TL_SIZE + 9 , &off, &out_recnum);
  assert_int_equal(r, CEL_RC_VALUE_TOO_LARGE);

  // unmarshal short buffer
  off = 0;
  r = CEL_TLV_RECNUM_Unmarshal(expected_buffer, TL_SIZE, &off, &out_recnum);
  assert_int_equal(r, CEL_RC_SHORT_BUFFER);

}

void test_tlv_nv_index(void **state) {
  (void) state;
  TPM2_HANDLE nv_index = 0x12341234, nv_index_out;
  UINT32 r;
  size_t off = 0;
  uint8_t buffer[TL_SIZE + 4], expected_buffer[TL_SIZE + 4] = "\x02\x00\x00\x00\x04\x12\x34\x12\x34", large_num_buffer[TL_SIZE + 5] = "\x02\x00\x00\x00\x05\x12\x34\x12\x34\x56";

  r = CEL_TLV_NV_INDEX_Marshal(nv_index, buffer, TL_SIZE + 4, &off);
  assert_int_equal(r, 0);
  assert_int_equal(off, TL_SIZE + 4);
  assert_memory_equal(buffer, expected_buffer, TL_SIZE + 4);

  // test NULL buffer
  off = 0;
  r = CEL_TLV_NV_INDEX_Marshal(nv_index, NULL, 0, &off);
  assert_int_equal(r, 0);
  assert_int_equal(off, TL_SIZE + 4);

  // test too small buffer
  off = 1234;
  r = CEL_TLV_NV_INDEX_Marshal(nv_index, buffer, TL_SIZE + 4, &off);
  assert_int_equal(r, CEL_RC_SHORT_BUFFER);

  // unmarshal
  off = 0;
  r = CEL_TLV_NV_INDEX_Unmarshal(buffer, TL_SIZE + 4, &off, &nv_index_out);
  assert_int_equal(r, 0);
  assert_int_equal(off, TL_SIZE + 4);
  assert_int_equal(nv_index_out, nv_index);

  // unmarshal NULL buffer
  r = CEL_TLV_NV_INDEX_Unmarshal(NULL, TL_SIZE + 4, &off, &nv_index_out);
  assert_int_equal(r, CEL_RC_BAD_REFERENCE);

  // unmarshal NULL dest
  r = CEL_TLV_NV_INDEX_Unmarshal(buffer, TL_SIZE + 4, &off, NULL);
  assert_int_equal(r, CEL_RC_BAD_REFERENCE);

  // unmarshal short buffer
  off = 0;
  r = CEL_TLV_NV_INDEX_Unmarshal(buffer, TL_SIZE, &off, &nv_index_out);
  assert_int_equal(r, CEL_RC_SHORT_BUFFER);

  // unmarshal value to large
  off = 0;
  r = CEL_TLV_NV_INDEX_Unmarshal(large_num_buffer, TL_SIZE + 5, &off, &nv_index_out);
  assert_int_equal(r, CEL_RC_VALUE_TOO_LARGE);
}

void test_tlv_pcr(void **state) {
  (void) state;
  TPM2_HANDLE pcr = 0, pcr_out;
  UINT32 r;
  size_t off = 0;
  uint8_t buffer[TL_SIZE + 1], expected_buffer[TL_SIZE + 1] = "\x01\x00\x00\x00\x01\x00";

  r = CEL_TLV_PCR_Marshal(pcr, buffer, TL_SIZE + 4, &off);
  assert_int_equal(r, 0);
  assert_int_equal(off, TL_SIZE + 1);
  assert_memory_equal(buffer, expected_buffer, TL_SIZE + 1);

  // test NULL buffer
  off = 0;
  r = CEL_TLV_PCR_Marshal(pcr, NULL, 0, &off);
  assert_int_equal(r, 0);
  assert_int_equal(off, TL_SIZE + 1);

  // test too small buffer
  off = 1234;
  r = CEL_TLV_PCR_Marshal(pcr, buffer, TL_SIZE + 1, &off);
  assert_int_equal(r, CEL_RC_SHORT_BUFFER);

  // unmarshal
  off = 0;
  r = CEL_TLV_PCR_Unmarshal(buffer, TL_SIZE + 1, &off, &pcr_out);
  assert_int_equal(r, 0);
  assert_int_equal(off, TL_SIZE + 1);
  assert_int_equal(pcr, pcr_out);

}

void test_tlv_tpmt_ha(void **state) {
  (void) state;
  TPMT_HA dig = {
    .hashAlg = TPM2_ALG_SHA,
    .digest = {
      .sha1 = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x20",
    },
  }, dig_out;
  UINT32 r;
  size_t off = 0;
  uint8_t buffer[TL_SIZE + 20], expected_buffer[TL_SIZE] = "\x04\x00\x00\x00\x14";

  r = CEL_TLV_TPMT_HA_Marshal(&dig, buffer, TL_SIZE + 20, &off);
  assert_int_equal(r, 0);
  assert_int_equal(off, TL_SIZE + 20);
  assert_memory_equal(buffer, expected_buffer, TL_SIZE);
  assert_memory_equal(buffer + TL_SIZE, dig.digest.sha1, 20);

  // test NULL buffer
  off = 0;
  r = CEL_TLV_TPMT_HA_Marshal(&dig, NULL, 0, &off);
  assert_int_equal(r, 0);
  assert_int_equal(off, TL_SIZE + 20);

  // test too small buffer
  off = 1234;
  r = CEL_TLV_TPMT_HA_Marshal(&dig, buffer, TL_SIZE + 20, &off);
  assert_int_equal(r, CEL_RC_SHORT_BUFFER);

  // test bad alg
  off = 0;
  dig.hashAlg = TPM2_ALG_NULL;
  r = CEL_TLV_TPMT_HA_Marshal(&dig, buffer, TL_SIZE + 20, &off);
  assert_int_equal(r, CEL_RC_UNSUPPORTED_DIGEST);

  // test NULL pointer
  r = CEL_TLV_TPMT_HA_Marshal(NULL, NULL, 0, NULL);
  assert_int_equal(r, CEL_RC_BAD_REFERENCE);

  // unmarshal
  off = 0;
  dig.hashAlg = TPM2_ALG_SHA1;
  r = CEL_TLV_TPMT_HA_Unmarshal(buffer, TL_SIZE + 20, &off, &dig_out);
  assert_int_equal(r, 0);
  assert_int_equal(off, TL_SIZE + 20);
  assert_int_equal(dig.hashAlg, dig_out.hashAlg);
  assert_memory_equal(dig.digest.sha1, dig_out.digest.sha1, 20);

  // unmarshal NULL buffer
  off = 0;
  r = CEL_TLV_TPMT_HA_Unmarshal(NULL, TL_SIZE + 20, &off, &dig_out);
  assert_int_equal(r, CEL_RC_BAD_REFERENCE);

  // unmarshal NULL dest
  off = 0;
  r = CEL_TLV_TPMT_HA_Unmarshal(buffer, TL_SIZE + 20, &off, NULL);
  assert_int_equal(r, CEL_RC_BAD_REFERENCE);

  // unmarshal small buffer
  off = 0;
  r = CEL_TLV_TPMT_HA_Unmarshal(buffer, 0, &off, &dig_out);
  assert_int_equal(r, CEL_RC_SHORT_BUFFER);

  // unmarshal bad digest
  off = 0;
  buffer[0] = 0x10;
  r = CEL_TLV_TPMT_HA_Unmarshal(buffer, TL_SIZE, &off, &dig_out);
  assert_int_equal(r, CEL_RC_UNSUPPORTED_DIGEST);
  buffer[0] = 0x04;

  // unmarshal small buffer value len
  off = 0;
  r = CEL_TLV_TPMT_HA_Unmarshal(buffer, TL_SIZE - 1, &off, &dig_out);
  assert_int_equal(r, CEL_RC_SHORT_BUFFER);

  // unmarshal digsize value len mismatch
  off = 0;
  buffer[4] = 0x10;
  r = CEL_TLV_TPMT_HA_Unmarshal(buffer, TL_SIZE, &off, &dig_out);
  assert_int_equal(r, CEL_RC_INVALID_VALUE);
  buffer[4] = 0x14;
}

void test_tlv_tpml_digest_values(void **state) {
  (void) state;
  TPML_DIGEST_VALUES digs = { .count = 1 }, digs_out;
  UINT32 r;
  size_t off = 0;
  uint8_t buffer[TL_SIZE + 25], expected_buffer[TL_SIZE] = "\x03\x00\x00\x00\x19";

  digs.digests[0].hashAlg = TPM2_ALG_SHA1;
  memcpy(&digs.digests[0].digest.sha1, "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x20", 20);

  r = CEL_TLV_TPML_DIGEST_VALUES_Marshal(&digs, buffer, TL_SIZE + 25, &off);
  assert_int_equal(r, 0);
  assert_int_equal(off, TL_SIZE + 25);
  assert_memory_equal(buffer, expected_buffer, TL_SIZE);
  assert_memory_equal(buffer + TL_SIZE + TL_SIZE, digs.digests[0].digest.sha1, 20);

  // test NULL buffer
  off = 0;
  r = CEL_TLV_TPML_DIGEST_VALUES_Marshal(&digs, NULL, 0, &off);
  assert_int_equal(r, 0);
  assert_int_equal(off, TL_SIZE + 25);

  // test too small buffer
  off = 1234;
  r = CEL_TLV_TPML_DIGEST_VALUES_Marshal(&digs, buffer, TL_SIZE + 20, &off);
  assert_int_equal(r, CEL_RC_SHORT_BUFFER);

  // test NULL pointer
  r = CEL_TLV_TPML_DIGEST_VALUES_Marshal(NULL, buffer, 0, &off);
  assert_int_equal(r, CEL_RC_BAD_REFERENCE);

  // test entry bad alg
  off = 0;
  digs.digests[0].hashAlg = TPM2_ALG_ERROR;
  r = CEL_TLV_TPML_DIGEST_VALUES_Marshal(&digs, NULL, 0, &off);
  assert_int_equal(r, CEL_RC_UNSUPPORTED_DIGEST);

  // unmarshal
  off = 0;
  digs.digests[0].hashAlg = TPM2_ALG_SHA1;
  r = CEL_TLV_TPML_DIGEST_VALUES_Unmarshal(buffer, TL_SIZE + 25, &off, &digs_out);
  assert_int_equal(r, 0);
  assert_int_equal(off, TL_SIZE + 25);
  assert_int_equal(digs.count, digs_out.count);
  assert_int_equal(digs.digests[0].hashAlg, digs_out.digests[0].hashAlg);
  assert_memory_equal(digs.digests[0].digest.sha1, digs_out.digests[0].digest.sha1, 20);

  // unmarshal NULL buffer
  off = 0;
  r = CEL_TLV_TPML_DIGEST_VALUES_Unmarshal(NULL, TL_SIZE + 25, &off, &digs_out);
  assert_int_equal(r, CEL_RC_BAD_REFERENCE);
  // unmarshal NULL dest
  r = CEL_TLV_TPML_DIGEST_VALUES_Unmarshal(buffer, TL_SIZE + 25, &off, NULL);
  assert_int_equal(r, CEL_RC_BAD_REFERENCE);
  // unmarshal bad type
  buffer[0] = 0xFF;
  r = CEL_TLV_TPML_DIGEST_VALUES_Unmarshal(buffer, TL_SIZE + 25, &off, &digs_out);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);
  buffer[0] = 0x03;
  // unmarshal small TL
  r = CEL_TLV_TPML_DIGEST_VALUES_Unmarshal(buffer, TL_SIZE - 1, &off, &digs_out);
  assert_int_equal(r, CEL_RC_SHORT_BUFFER);
  // unmarshal to large sublen
  r = CEL_TLV_TPML_DIGEST_VALUES_Unmarshal(buffer, TL_SIZE, &off, &digs_out);
  assert_int_equal(r, CEL_RC_SHORT_BUFFER);

  // unmarshal bad element
  buffer[5] = 0xFF;
  r = CEL_TLV_TPML_DIGEST_VALUES_Unmarshal(buffer, TL_SIZE + 25, &off, &digs_out);
  assert_int_equal(r, CEL_RC_UNSUPPORTED_DIGEST);
  buffer[5] = 0x04;

}

void test_tlv_tpms_cel_version(void **state) {
  (void) state;
  TPMS_CEL_VERSION ver = { .major = 1, .minor = 0 }, ver_out;
  UINT32 r;
  size_t off = 0;
  uint8_t buffer[TL_SIZE + 12],
    expected_buffer[TL_SIZE + 12] = "\x01\x00\x00\x00\x0c\x00\x00\x00\x00\x01\x01\x01\x00\x00\x00\x01\x00",
    out_buffer[TL_SIZE + 12] = "\x01\x00\x00\x00\x0c\x01\x00\x00\x00\x01\x01\x00\x00\x00\x00\x01\x00",
    large_maj_buffer[TL_SIZE + 8] = "\x01\x00\x00\x00\x08\x00\x00\x00\x00\x03\xff\x00\x00";

  r = CEL_TLV_TPMS_CEL_VERSION_Marshal(&ver, buffer, TL_SIZE + 12, &off);
  assert_int_equal(r, 0);
  assert_int_equal(off, TL_SIZE + 12);
  assert_memory_equal(buffer, expected_buffer, TL_SIZE + 12);

  // test NULL buffer
  off = 0;
  r = CEL_TLV_TPMS_CEL_VERSION_Marshal(&ver, NULL, TL_SIZE + 12, &off);
  assert_int_equal(r, 0);
  assert_int_equal(off, TL_SIZE + 12);

  // test to small buffer
  off = 1234;
  r = CEL_TLV_TPMS_CEL_VERSION_Marshal(&ver, buffer, TL_SIZE + 12, &off);
  assert_int_equal(r, CEL_RC_SHORT_BUFFER);

  // test NULL pointer
  off = 0;
  r = CEL_TLV_TPMS_CEL_VERSION_Marshal(NULL, NULL, 0, NULL);
  assert_int_equal(r, CEL_RC_BAD_REFERENCE);

  // unmarshal
  off = 0;
  r = CEL_TLV_TPMS_CEL_VERSION_Unmarshal(out_buffer, TL_SIZE + 12, &off, &ver_out);
  assert_int_equal(r, 0);
  assert_int_equal(off, TL_SIZE + 12);
  assert_int_equal(ver_out.major, 0);
  assert_int_equal(ver_out.minor, 1);

  // unmarshal NULL buffer
  off = 0;
  r = CEL_TLV_TPMS_CEL_VERSION_Unmarshal(NULL, 0, NULL, NULL);
  assert_int_equal(r, CEL_RC_BAD_REFERENCE);
  // unmarshal NULL dest
  off = 0;
  r = CEL_TLV_TPMS_CEL_VERSION_Unmarshal(out_buffer, 0, NULL, NULL);
  assert_int_equal(r, CEL_RC_BAD_REFERENCE);
  // unmarshal short buffer
  off = 0;
  r = CEL_TLV_TPMS_CEL_VERSION_Unmarshal(out_buffer, TL_SIZE - 1, &off, &ver_out);
  assert_int_equal(r, CEL_RC_SHORT_BUFFER);
  // unmarshal short value
  off = 0;
  r = CEL_TLV_TPMS_CEL_VERSION_Unmarshal(out_buffer, TL_SIZE, &off, &ver_out);
  assert_int_equal(r, CEL_RC_SHORT_BUFFER);
  // unmarshal large major
  off = 0;
  r = CEL_TLV_TPMS_CEL_VERSION_Unmarshal(large_maj_buffer, TL_SIZE + 8, &off, &ver_out);
  assert_int_equal(r, CEL_RC_VALUE_TOO_LARGE);

  // unmarshal bad subtype
  off = 0;
  out_buffer[5] = 0xFF;
  r = CEL_TLV_TPMS_CEL_VERSION_Unmarshal(out_buffer, TL_SIZE + 12, &off, &ver_out);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);
  out_buffer[5] = 0x01;

  // unmarshal bad type
  off = 0;
  out_buffer[0] = 0xFF;
  r = CEL_TLV_TPMS_CEL_VERSION_Unmarshal(out_buffer, TL_SIZE + 12, &off, &ver_out);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);
  out_buffer[0] = 0x01;

  // unmarshal sublen > suboff
  off = 0;
  out_buffer[4]++;
  r = CEL_TLV_TPMS_CEL_VERSION_Unmarshal(out_buffer, TL_SIZE + 13, &off, &ver_out);
  assert_int_equal(r, CEL_RC_INVALID_VALUE);
  out_buffer[4]--;
}

void test_tlv_tpms_event_celmgt(void **state) {
  (void) state;
  TPMS_EVENT_CELMGT mgt, mgt_out;
  UINT32 r;
  size_t off = 0;
  uint8_t
    buffer[TL_SIZE + 2],
    expected_firmware_end_buffer[TL_SIZE] = "\x02\x00\x00\x00\x00",
    expected_cel_timestamp_buffer[TL_SIZE + 2] = "\x50\x00\x00\x00\x02\x12\x34",
    expected_state_trans_buffer[TL_SIZE + 1] = "\x51\x00\x00\x00\x01\x02",
    bad_firmware_end_buffer[TL_SIZE + 1] = "\x02\x00\x00\x00\x01\xff"
    ;

  // test firmware end
  mgt.type = CEL_TYPE_MGMT_FIRMWARE_END;
  r = CEL_TLV_TPMS_EVENT_CELMGT_Marshal(&mgt, buffer, TL_SIZE, &off);
  assert_int_equal(r, 0);
  assert_int_equal(off, TL_SIZE);
  assert_memory_equal(buffer, expected_firmware_end_buffer, TL_SIZE);
  // test timestamp
  off = 0;
  mgt.type = CEL_TYPE_MGMT_CEL_TIMESTAMP;
  mgt.data.cel_timestamp = 0x1234;
  r = CEL_TLV_TPMS_EVENT_CELMGT_Marshal(&mgt, buffer, TL_SIZE + 2, &off);
  assert_int_equal(r, 0);
  assert_int_equal(off, TL_SIZE + 2);
  assert_memory_equal(buffer, expected_cel_timestamp_buffer, TL_SIZE + 2);
  // test state_trans
  off = 0;
  mgt.type = CEL_TYPE_MGMT_STATE_TRANS;
  mgt.data.state_trans = CEL_STATE_TRANS_KEXEC;
  r = CEL_TLV_TPMS_EVENT_CELMGT_Marshal(&mgt, buffer, TL_SIZE + 1, &off);
  assert_int_equal(r, 0);
  assert_int_equal(off, TL_SIZE + 1);
  assert_memory_equal(buffer, expected_state_trans_buffer, TL_SIZE + 1);

  // test bad type
  off = 0;
  mgt.type = 0xFF;
  r = CEL_TLV_TPMS_EVENT_CELMGT_Marshal(&mgt, buffer, TL_SIZE + 1, &off);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);
  assert_int_equal(off, 0);

  // test NULL buffer
  off = 0;
  mgt.type = CEL_TYPE_MGMT_FIRMWARE_END;
  r = CEL_TLV_TPMS_EVENT_CELMGT_Marshal(&mgt, NULL, TL_SIZE, &off);
  assert_int_equal(r, 0);
  assert_int_equal(off, TL_SIZE);

  // test too small buffer
  off = 1234;
  r = CEL_TLV_TPMS_EVENT_CELMGT_Marshal(&mgt, buffer, TL_SIZE, &off);
  assert_int_equal(r, CEL_RC_SHORT_BUFFER);

  // test NULL pointer
  r = CEL_TLV_TPMS_EVENT_CELMGT_Marshal(NULL, buffer, TL_SIZE, 0);
  assert_int_equal(r, CEL_RC_BAD_REFERENCE);

  // unmarshal firmware end
  off = 0;
  r = CEL_TLV_TPMS_EVENT_CELMGT_Unmarshal(expected_firmware_end_buffer, TL_SIZE + 2, &off, &mgt_out);
  assert_int_equal(r, 0);
  assert_int_equal(off, TL_SIZE);
  assert_int_equal(mgt_out.type, CEL_TYPE_MGMT_FIRMWARE_END);
  // unmarshal timestamp
  off = 0;
  r = CEL_TLV_TPMS_EVENT_CELMGT_Unmarshal(expected_cel_timestamp_buffer, TL_SIZE + 2, &off, &mgt_out);
  assert_int_equal(r, 0);
  assert_int_equal(off, TL_SIZE + 2);
  assert_int_equal(mgt_out.type, CEL_TYPE_MGMT_CEL_TIMESTAMP);
  assert_int_equal(mgt_out.data.cel_timestamp, 0x1234);
  // unmarhal state_trans
  off = 0;
  r = CEL_TLV_TPMS_EVENT_CELMGT_Unmarshal(expected_state_trans_buffer, TL_SIZE + 2, &off, &mgt_out);
  assert_int_equal(r, 0);
  assert_int_equal(off, TL_SIZE + 1);
  assert_int_equal(mgt_out.type, CEL_TYPE_MGMT_STATE_TRANS);
  assert_int_equal(mgt_out.data.state_trans, CEL_STATE_TRANS_KEXEC);

  // unmarshal NULL buffer
  off = 0;
  r = CEL_TLV_TPMS_EVENT_CELMGT_Unmarshal(NULL, 0, &off, &mgt_out);
  assert_int_equal(r, CEL_RC_BAD_REFERENCE);

  // unmarshal NULL dest
  off = 0;
  r = CEL_TLV_TPMS_EVENT_CELMGT_Unmarshal(expected_state_trans_buffer, 0, &off, NULL);
  assert_int_equal(r, CEL_RC_BAD_REFERENCE);

  // unmarshal short buffer
  off = 0;
  r = CEL_TLV_TPMS_EVENT_CELMGT_Unmarshal(expected_firmware_end_buffer, 0, &off, &mgt_out);
  assert_int_equal(r, CEL_RC_SHORT_BUFFER);

  // unmarshal long firmware end
  off = 0;
  r = CEL_TLV_TPMS_EVENT_CELMGT_Unmarshal(bad_firmware_end_buffer, TL_SIZE + 1, &off, &mgt_out);
  assert_int_equal(r, CEL_RC_INVALID_VALUE);

  // unmarshal bad type
  off = 0;
  bad_firmware_end_buffer[0] = 0xFF;
  r = CEL_TLV_TPMS_EVENT_CELMGT_Unmarshal(bad_firmware_end_buffer, TL_SIZE + 1, &off, &mgt_out);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);
}

void test_tlv_tpms_event_pcclient_std(void **state) {
  (void) state;
  TPMS_EVENT_PCCLIENT_STD pc, pc_out;
  UINT32 r;
  size_t off = 0;
  uint8_t
    buffer[TL_SIZE + 15],
    expected_buffer[TL_SIZE + 15] = "\x05\x00\x00\x00\x0f\x00\x00\x00\x00\x02\x12\x34\x01\x00\x00\x00\x03\x01\x02\x03"
    ;

  pc.event_type = 0x1234;
  pc.event_data.size = 3;
  memcpy(pc.event_data.buffer, "\x01\x02\x03", 3);

  // test usual
  r = CEL_TLV_TPMS_EVENT_PCCLIENT_STD_Marshal(&pc, buffer, TL_SIZE + 15, &off);
  assert_int_equal(r, 0);
  assert_int_equal(off, TL_SIZE + 15);
  assert_memory_equal(buffer, expected_buffer, TL_SIZE + 15);

  // test NULL buffer
  off = 0;
  r = CEL_TLV_TPMS_EVENT_PCCLIENT_STD_Marshal(&pc, NULL, 0, &off);
  assert_int_equal(r, 0);
  assert_int_equal(off, TL_SIZE + 15);

  // test too small buffer
  off = 1234;
  r = CEL_TLV_TPMS_EVENT_PCCLIENT_STD_Marshal(&pc, buffer, TL_SIZE + 15, &off);
  assert_int_equal(r, CEL_RC_SHORT_BUFFER);

  // test NULL pointer
  r = CEL_TLV_TPMS_EVENT_PCCLIENT_STD_Marshal(NULL, NULL, 0, &off);
  assert_int_equal(r, CEL_RC_BAD_REFERENCE);

  // unmarshal
  off = 0;
  r = CEL_TLV_TPMS_EVENT_PCCLIENT_STD_Unmarshal(buffer, TL_SIZE + 15, &off, &pc_out);
  assert_int_equal(r, 0);
  assert_int_equal(off, TL_SIZE + 15);
  assert_int_equal(pc_out.event_type, 0x1234);
  assert_int_equal(pc_out.event_data.size, pc.event_data.size);
  assert_memory_equal(pc_out.event_data.buffer, pc.event_data.buffer, pc.event_data.size);

  // unmarshal NULL buffer
  off = 0;
  r = CEL_TLV_TPMS_EVENT_PCCLIENT_STD_Unmarshal(NULL, TL_SIZE + 15, &off, &pc_out);
  assert_int_equal(r, CEL_RC_BAD_REFERENCE);

  // unmarshal NULL dest
  off = 0;
  r = CEL_TLV_TPMS_EVENT_PCCLIENT_STD_Unmarshal(buffer, TL_SIZE + 15, &off, NULL);
  assert_int_equal(r, CEL_RC_BAD_REFERENCE);

  // unmarshal bad type
  off = 0;
  buffer[0] = 0xFF;
  r = CEL_TLV_TPMS_EVENT_PCCLIENT_STD_Unmarshal(buffer, TL_SIZE + 15, &off, &pc_out);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);
  buffer[0] = 0x05;

  // unmarshal short buffer
  off = 0;
  r = CEL_TLV_TPMS_EVENT_PCCLIENT_STD_Unmarshal(buffer, 1, &off, &pc_out);
  assert_int_equal(r, CEL_RC_SHORT_BUFFER);

  // unmarshal short event_data
  off = 0;
  buffer[0] = 0xFF;
  r = CEL_TLV_TPMS_EVENT_PCCLIENT_STD_Unmarshal(buffer, TL_SIZE + 15, &off, &pc_out);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);
  buffer[0] = 0x05;

  // unmarshal bad subtype
  off = 0;
  buffer[5] = 0xFF;
  r = CEL_TLV_TPMS_EVENT_PCCLIENT_STD_Unmarshal(buffer, TL_SIZE + 15, &off, &pc_out);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);
  buffer[5] = CEL_TYPE_PCCLIENT_STD_EVENT_TYPE;

  // unmarshal sublen > suboff
  off = 0;
  buffer[4]++;
  r = CEL_TLV_TPMS_EVENT_PCCLIENT_STD_Unmarshal(buffer, TL_SIZE + 16, &off, &pc_out);
  assert_int_equal(r, CEL_RC_INVALID_VALUE);
  buffer[4]--;

  // unmarshal event data first, no event_type
  off = 0;
  buffer[5] = CEL_TYPE_PCCLIENT_STD_EVENT_DATA;
  r = CEL_TLV_TPMS_EVENT_PCCLIENT_STD_Unmarshal(buffer, TL_SIZE + 15, &off, &pc_out);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);
  buffer[5] = CEL_TYPE_PCCLIENT_STD_EVENT_TYPE;

}

void test_tlv_tpms_event_ima_template(void **state) {
  (void) state;
  TPMS_EVENT_IMA_TEMPLATE ima, ima_out;
  UINT32 r;
  size_t off = 0;
  uint8_t
    buffer[TL_SIZE + 18],
    expected_buffer[TL_SIZE + 18] = "\x07\x00\x00\x00\x12\x00\x00\x00\x00\x04test\x01\x00\x00\x00\x04" "1234"
    ;

  memcpy(ima.template_name.buffer, "test", 4);
  ima.template_name.size = 4;
  memcpy(ima.template_data.buffer, "1234", 4);
  ima.template_data.size = 4;

  r = CEL_TLV_TPMS_EVENT_IMA_TEMPLATE_Marshal(&ima, buffer, TL_SIZE + 18, &off);
  assert_int_equal(r, 0);
  assert_int_equal(off, 23);
  assert_memory_equal(buffer, expected_buffer, TL_SIZE + 18);

  // test NULL buffer
  off = 0;
  r = CEL_TLV_TPMS_EVENT_IMA_TEMPLATE_Marshal(&ima, NULL, 0, &off);
  assert_int_equal(r, 0);
  assert_int_equal(off, TL_SIZE + 18);

  // test too small buffer
  off = 1234;
  r = CEL_TLV_TPMS_EVENT_IMA_TEMPLATE_Marshal(&ima, buffer, TL_SIZE + 18, &off);
  assert_int_equal(r, CEL_RC_SHORT_BUFFER);

  // test NULL pointer
  r = CEL_TLV_TPMS_EVENT_IMA_TEMPLATE_Marshal(NULL, buffer, TL_SIZE + 18, NULL);
  assert_int_equal(r, CEL_RC_BAD_REFERENCE);

  // unmarshal
  off = 0;
  r = CEL_TLV_TPMS_EVENT_IMA_TEMPLATE_Unmarshal(buffer, TL_SIZE + 18, &off, &ima_out);
  assert_int_equal(r, 0);
  assert_int_equal(off, TL_SIZE + 18);
  assert_int_equal(ima_out.template_name.size, 4);
  assert_memory_equal(ima_out.template_name.buffer, "test", 4);
  assert_int_equal(ima_out.template_data.size, 4);
  assert_memory_equal(ima_out.template_data.buffer, "1234", 4);

  // unmarshal NULL buffer
  off = 0;
  r = CEL_TLV_TPMS_EVENT_IMA_TEMPLATE_Unmarshal(NULL, 0, NULL, NULL);
  assert_int_equal(r, CEL_RC_BAD_REFERENCE);
  // unmarshal NULL dest
  off = 0;
  r = CEL_TLV_TPMS_EVENT_IMA_TEMPLATE_Unmarshal(buffer, 0, NULL, NULL);
  assert_int_equal(r, CEL_RC_BAD_REFERENCE);

  // unmarshal bad type
  off = 0;
  buffer[0] = 0xFF;
  r = CEL_TLV_TPMS_EVENT_IMA_TEMPLATE_Unmarshal(buffer, TL_SIZE + 18, &off, &ima_out);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);
  buffer[0] = CEL_TYPE_IMA_TEMPLATE;

  // unmarshal short buffer
  off = 0;
  r = CEL_TLV_TPMS_EVENT_IMA_TEMPLATE_Unmarshal(buffer, 1, &off, &ima_out);
  assert_int_equal(r, CEL_RC_SHORT_BUFFER);

  // unmarshal short subbuffer
  off = 0;
  buffer[4]++;
  r = CEL_TLV_TPMS_EVENT_IMA_TEMPLATE_Unmarshal(buffer, TL_SIZE + 18, &off, &ima_out);
  assert_int_equal(r, CEL_RC_SHORT_BUFFER);
  buffer[4]--;

  // unmarshal bad subtype
  off = 0;
  buffer[5] = 0xFF;
  r = CEL_TLV_TPMS_EVENT_IMA_TEMPLATE_Unmarshal(buffer, TL_SIZE + 18, &off, &ima_out);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);
  buffer[5] = 0x0;

  // unmarshal sublen > suboff
  off = 0;
  buffer[4]++;
  r = CEL_TLV_TPMS_EVENT_IMA_TEMPLATE_Unmarshal(buffer, TL_SIZE + 19, &off, &ima_out);
  assert_int_equal(r, CEL_RC_INVALID_VALUE);
  buffer[4]--;

  // unmarshal template_data first
  off = 0;
  buffer[5] = CEL_TYPE_IMA_TEMPLATE_DATA;
  r = CEL_TLV_TPMS_EVENT_IMA_TEMPLATE_Unmarshal(buffer, TL_SIZE + 19, &off, &ima_out);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);
  buffer[5] = CEL_TYPE_IMA_TEMPLATE_NAME;

}

void test_tlv_tpml_event_celmgt(void **state) {
  (void) state;
  TPML_EVENT_CELMGT mgmt, mgmt_out;
  UINT32 r;
  size_t off = 0;
  uint8_t
    buffer[TL_SIZE + 22],
    expected_buffer[TL_SIZE + 22] = "\x04\x00\x00\x00\x16\x01\x00\x00\x00\x0c\x00\x00\x00\x00\x01\x02\x01\x00\x00\x00\x01\x03\x02\x00\x00\x00\x00",
    many_events_buffer[90] =
    "\x04\x00\x00\x00\x55" // 0 - 4 CEL_TYPE_MGMT + size
    "\x02\x00\x00\x00\x00"
    "\x02\x00\x00\x00\x00"
    "\x02\x00\x00\x00\x00"
    "\x02\x00\x00\x00\x00"
    "\x02\x00\x00\x00\x00"
    "\x02\x00\x00\x00\x00"
    "\x02\x00\x00\x00\x00"
    "\x02\x00\x00\x00\x00"
    "\x02\x00\x00\x00\x00"
    "\x02\x00\x00\x00\x00"
    "\x02\x00\x00\x00\x00"
    "\x02\x00\x00\x00\x00"
    "\x02\x00\x00\x00\x00"
    "\x02\x00\x00\x00\x00"
    "\x02\x00\x00\x00\x00"
    "\x02\x00\x00\x00\x00"
    "\x02\x00\x00\x00\x00"
    ;

  // setup mgmt
  mgmt.count = 2;
  mgmt.events[0].type = CEL_TYPE_MGMT_CEL_VERSION;
  mgmt.events[0].data.cel_version.major = 2;
  mgmt.events[0].data.cel_version.minor = 3;
  mgmt.events[1].type = CEL_TYPE_MGMT_FIRMWARE_END;
  // test usual
  r = CEL_TLV_TPML_EVENT_CELMGT_Marshal(&mgmt, buffer, TL_SIZE + 22, &off);
  assert_int_equal(r, 0);
  assert_int_equal(off, TL_SIZE + 22);
  assert_memory_equal(buffer, expected_buffer, TL_SIZE + 22);
  // test NULL buffer
  off = 0;
  r = CEL_TLV_TPML_EVENT_CELMGT_Marshal(&mgmt, NULL, 0, &off);
  assert_int_equal(r, 0);
  assert_int_equal(off, TL_SIZE + 22);

  // test too small buffer
  off = 1234;
  r = CEL_TLV_TPML_EVENT_CELMGT_Marshal(&mgmt, buffer, TL_SIZE + 22, &off);
  assert_int_equal(r, CEL_RC_SHORT_BUFFER);

  // test NULL pointer
  off = 0;
  r = CEL_TLV_TPML_EVENT_CELMGT_Marshal(NULL, NULL, 0, &off);
  assert_int_equal(r, CEL_RC_BAD_REFERENCE);

  // test bad element
  off = 0;
  mgmt.events[1].type = 0xFF;
  r = CEL_TLV_TPML_EVENT_CELMGT_Marshal(&mgmt, buffer, TL_SIZE + 22, &off);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);

  // unmarshal
  off = 0;
  r = CEL_TLV_TPML_EVENT_CELMGT_Unmarshal(buffer, TL_SIZE + 22, &off, &mgmt_out);
  assert_int_equal(r, 0);
  assert_int_equal(off, TL_SIZE + 22);
  assert_int_equal(mgmt_out.count, 2);
  assert_int_equal(mgmt_out.events[0].type, CEL_TYPE_MGMT_CEL_VERSION);
  assert_int_equal(mgmt_out.events[0].data.cel_version.major, 2);
  assert_int_equal(mgmt_out.events[0].data.cel_version.minor, 3);
  assert_int_equal(mgmt_out.events[1].type, CEL_TYPE_MGMT_FIRMWARE_END);

  // unmarshal NULL buffer
  off = 0;
  r = CEL_TLV_TPML_EVENT_CELMGT_Unmarshal(NULL, 0, NULL, NULL);
  assert_int_equal(r, CEL_RC_BAD_REFERENCE);

  // unmarshal NULL dest
  off = 0;
  r = CEL_TLV_TPML_EVENT_CELMGT_Unmarshal(buffer, 0, NULL, NULL);
  assert_int_equal(r, CEL_RC_BAD_REFERENCE);

  // unmarshal bad type
  off = 0;
  buffer[0]++;
  r = CEL_TLV_TPML_EVENT_CELMGT_Unmarshal(buffer, TL_SIZE + 22, &off, &mgmt_out);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);
  buffer[0]--;

  // unmarshal short buff
  off = 0;
  r = CEL_TLV_TPML_EVENT_CELMGT_Unmarshal(buffer, 4, &off, &mgmt_out);
  assert_int_equal(r, CEL_RC_SHORT_BUFFER);

  // unmarshal bad element
  off = 0;
  buffer[5] = 0xFF;
  r = CEL_TLV_TPML_EVENT_CELMGT_Unmarshal(buffer, TL_SIZE + 22, &off, &mgmt_out);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);
  buffer[5] = CEL_TYPE_MGMT_CEL_VERSION;

  // unmarshal short subbuffer
  off = 0;
  r = CEL_TLV_TPML_EVENT_CELMGT_Unmarshal(buffer, TL_SIZE, &off, &mgmt_out);
  assert_int_equal(r, CEL_RC_SHORT_BUFFER);

  // unmarshal to many events
  off = 0;
  r = CEL_TLV_TPML_EVENT_CELMGT_Unmarshal(many_events_buffer, 90, &off, &mgmt_out);
  assert_int_equal(r, CEL_RC_INVALID_VALUE);

}

void test_tlv_tpms_cel_event(void **state) {
  (void) state;
  TPMS_CEL_EVENT event, event_out;
  UINT32 r;
  size_t off = 0;
  uint8_t
    buffer[27],
    expected_buffer[27] =
    "\x00\x00\x00\x00\x01\x02" // 0 - 5 recnum
    "\x01\x00\x00\x00\x01\x03" // 6 - 11 pcr
    "\x03\x00\x00\x00\x00" // 12 - 16 empty digests
    "\x04\x00\x00\x00\x05" // 17 - 21 CEL mgmt
    "\x02\x00\x00\x00\x00" // 22 - 26 CEL firmware_end
    ;

  event.recnum = 2;
  event.pcr = 3;
  event.nv_index = 0;
  event.digests.count = 0;
  event.content_type = CEL_TYPE_MGMT;
  event.content.celmgt.count = 1;
  event.content.celmgt.events[0].type = CEL_TYPE_MGMT_FIRMWARE_END;
  // test usual
  r = CEL_TLV_TPMS_CEL_EVENT_Marshal(&event, buffer, 27, &off);
  assert_int_equal(r, 0);
  assert_int_equal(off, 27);
  assert_memory_equal(buffer, expected_buffer, 27);

  // test NULL buffer
  off = 0;
  r = CEL_TLV_TPMS_CEL_EVENT_Marshal(&event, NULL, 0, &off);
  assert_int_equal(r, 0);
  assert_int_equal(off, 27);

  // test too small buffer
  off = 1234;
  r = CEL_TLV_TPMS_CEL_EVENT_Marshal(&event, buffer, 27, &off);
  assert_int_equal(r, CEL_RC_SHORT_BUFFER);

  // test unsupported type
  off = 0;
  event.nv_index = 1234;
  event.content_type = 255;
  r = CEL_TLV_TPMS_CEL_EVENT_Marshal(&event, buffer, 220, &off);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);

  // test NULL pointer
  r = CEL_TLV_TPMS_CEL_EVENT_Marshal(NULL, buffer, TL_SIZE, &off);
  assert_int_equal(r, CEL_RC_BAD_REFERENCE);

  // test buffer too small PCR/NV
  off = 0;
  r = CEL_TLV_TPMS_CEL_EVENT_Marshal(&event, buffer, 6, &off);
  assert_int_equal(r, CEL_RC_SHORT_BUFFER);

  // test buffer too small digests
  off = 0;
  r = CEL_TLV_TPMS_CEL_EVENT_Marshal(&event, buffer, 13, &off);
  assert_int_equal(r, CEL_RC_SHORT_BUFFER);

  // test pcclient type
  off = 0;
  event.content_type = CEL_TYPE_PCCLIENT_STD;
  r = CEL_TLV_TPMS_CEL_EVENT_Marshal(&event, buffer, 18, &off);
  assert_int_equal(r, CEL_RC_SHORT_BUFFER);

  // test ima template type
  off = 0;
  event.content_type = CEL_TYPE_IMA_TEMPLATE;
  r = CEL_TLV_TPMS_CEL_EVENT_Marshal(&event, buffer, 18, &off);
  assert_int_equal(r, CEL_RC_SHORT_BUFFER);

  // unmarshal
  off = 0;
  r = CEL_TLV_TPMS_CEL_EVENT_Unmarshal(expected_buffer, 27, &off, &event_out);
  assert_int_equal(r, 0);
  assert_int_equal(off, 27);
  assert_int_equal(event_out.recnum, 2);
  assert_int_equal(event_out.pcr, 3);
  assert_int_equal(event_out.digests.count, 0);
  assert_int_equal(event_out.content_type, CEL_TYPE_MGMT);
  assert_int_equal(event_out.content.celmgt.count, 1);
  assert_int_equal(event_out.content.celmgt.events[0].type, CEL_TYPE_MGMT_FIRMWARE_END);

  // unmarshal NULL buffer
  off = 0;
  r = CEL_TLV_TPMS_CEL_EVENT_Unmarshal(NULL, 27, &off, &event_out);
  assert_int_equal(r, CEL_RC_BAD_REFERENCE);

  // unmarshal NULL dest
  off = 0;
  r = CEL_TLV_TPMS_CEL_EVENT_Unmarshal(buffer, 27, &off, NULL);
  assert_int_equal(r, CEL_RC_BAD_REFERENCE);

  // unmarshal bad recnum
  off = 0;
  expected_buffer[0] = 0xFF;
  r = CEL_TLV_TPMS_CEL_EVENT_Unmarshal(expected_buffer, 27, &off, &event_out);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);
  expected_buffer[0] = CEL_TYPE_RECNUM;

  // unmarshal bad pcr/nv
  off = 0;
  expected_buffer[6] = 0xFF;
  r = CEL_TLV_TPMS_CEL_EVENT_Unmarshal(expected_buffer, 27, &off, &event_out);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);
  expected_buffer[6] = CEL_TYPE_PCR;

  // unmarshal nv
  off = 0;
  expected_buffer[6] = CEL_TYPE_NV_INDEX;
  r = CEL_TLV_TPMS_CEL_EVENT_Unmarshal(expected_buffer, 27, &off, &event_out);
  assert_int_equal(r, 0);
  expected_buffer[6] = CEL_TYPE_PCR;

  // unmarshal bad digests
  off = 0;
  expected_buffer[12] = 0xFF;
  r = CEL_TLV_TPMS_CEL_EVENT_Unmarshal(expected_buffer, 27, &off, &event_out);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);
  expected_buffer[12] = CEL_TYPE_DIGESTS;

  // unmarshal CEL_TYPE_PCCLIENT_STD
  off = 0;
  expected_buffer[17] = CEL_TYPE_PCCLIENT_STD;
  r = CEL_TLV_TPMS_CEL_EVENT_Unmarshal(expected_buffer, 27, &off, &event_out);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);
  expected_buffer[17] = CEL_TYPE_MGMT;

  // unmarshal CEL_TYPE_IMA_TEMPLATE
  off = 0;
  expected_buffer[17] = CEL_TYPE_IMA_TEMPLATE;
  r = CEL_TLV_TPMS_CEL_EVENT_Unmarshal(expected_buffer, 27, &off, &event_out);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);
  expected_buffer[17] = CEL_TYPE_MGMT;

  // unmarshal bad type
  off = 0;
  expected_buffer[17] = 0xFF;
  r = CEL_TLV_TPMS_CEL_EVENT_Unmarshal(expected_buffer, 27, &off, &event_out);
  assert_int_equal(r, CEL_RC_INVALID_TYPE);
  expected_buffer[17] = CEL_TYPE_MGMT;

  // unmarshal only recnum
  off = 0;
  r = CEL_TLV_TPMS_CEL_EVENT_Unmarshal(expected_buffer, 6, &off, &event_out);
  assert_int_equal(r, CEL_RC_SHORT_BUFFER);

  // unmarshal short buffer, no content
  off = 0;
  r = CEL_TLV_TPMS_CEL_EVENT_Unmarshal(expected_buffer, 17, &off, &event_out);
  assert_int_equal(r, CEL_RC_SHORT_BUFFER);
}

int main(int argc, char **argv)
{
  (void) argc;
  (void) argv;

  const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_tlv_recnum),
    cmocka_unit_test(test_tlv_nv_index),
    cmocka_unit_test(test_tlv_pcr),
    cmocka_unit_test(test_tlv_tpmt_ha),
    cmocka_unit_test(test_tlv_tpml_digest_values),
    cmocka_unit_test(test_tlv_tpms_cel_version),
    cmocka_unit_test(test_tlv_tpms_event_celmgt),
    cmocka_unit_test(test_tlv_tpms_event_pcclient_std),
    cmocka_unit_test(test_tlv_tpms_event_ima_template),
    cmocka_unit_test(test_tlv_tpml_event_celmgt),
    cmocka_unit_test(test_tlv_tpms_cel_event),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}

