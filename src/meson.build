pkg = import('pkgconfig')

cel_sources = ['parse.c', 'cel_io.c', 'tlv.c']
cel_lib = shared_library('cel', cel_sources, include_directories: inc, dependencies: dependencies, install: true)

pkg.generate(cel_lib)

if json_dep.found()
  cel_json_sources = ['json.c', 'cel_io.c', 'cel_strings.c']
  cel_json_lib = shared_library('cel-json', cel_json_sources, include_directories: inc, dependencies: dependencies + json_dep, install: true)
  pkg.generate(cel_json_lib)
endif
