fetchip_files = [
  'main.cpp',
]

lib_srcs = [
  'dns.cpp',
  'dns_resolver.cpp',
]

lib = static_library('fetchip', lib_srcs,
                     dependencies: deps,
                     install: false)

inc = include_directories('.')
fetchip_deps = declare_dependency(dependencies: deps, link_with: lib, include_directories: inc)
executable('fetchip',
           fetchip_files,
           dependencies : fetchip_deps
          )
