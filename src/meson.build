fetchip_files = [
  'main.cpp',
]

lib_srcs = [
  'consensus.cpp',
  'dns.cpp',
  'dns_resolver.cpp',
  'http_client.cpp',
  'name_resolver.cpp',
]

version_hpp = configure_file(input: 'version.hpp.in',
                             output: 'version.hpp',
                             configuration: {'VERSION': meson.project_version()})

lib = static_library('fetchip', lib_srcs,
                     dependencies: deps,
                     install: false)

inc = include_directories('.')
fetchip_deps = declare_dependency(dependencies: deps, link_with: lib, include_directories: inc)
fetchip_exe = executable('fetchip',
           fetchip_files,
           dependencies : fetchip_deps,
           install : true
          )
