# Copyright (c) 2022 by Erik Larsson
# SPDX-License-Identifier: GPL-3.0-or-later

project(
  'libcel', 'c',
  version : '1.0.0',
  license: 'GPL3',
  default_options : ['warning_level=3']
)
dependencies = [dependency('tss2-mu'), dependency('json-c')]
test_dep = [dependency('cmocka'), dependency('libcrypto'), dependency('json-c')]

inc = include_directories('include')

subdir('include')
subdir('src')
subdir('test')
