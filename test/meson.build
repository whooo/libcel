# Copyright (c) 2022 by Erik Larsson
# SPDX-License-Identifier: GPL-3.0-or-later

tlv_exe = executable('test_tlv', 'test_tlv.c', include_directories: inc, link_with: cel_lib, dependencies: test_dep)
test('tlv', tlv_exe)

if json_dep.found()
  json_exe = executable('test_json', 'test_json.c', include_directories: inc, link_with: cel_json_lib, dependencies: json_test_dep)
  test('json', json_exe, workdir: meson.current_source_dir())
endif

parse_exe = executable('test_parse', 'test_parse.c', include_directories: inc, link_with: cel_lib, dependencies: test_dep)
test('parse', parse_exe, workdir: meson.current_source_dir())
