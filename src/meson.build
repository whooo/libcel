pkg = import('pkgconfig')

cel_sources = ['parse.c', 'cel_io.c', 'tlv.c', 'cel_strings.c', 'json.c', 'cel_json_utils.c']
cel_lib = shared_library('cel', cel_sources, include_directories: inc, dependencies: dependencies, install: true)

pkg.generate(cel_lib)
