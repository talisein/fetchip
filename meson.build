project('fetchip', 'cpp', default_options : ['cpp_std=c++23'])

cpphttplib_dep = dependency('cpp-httplib',
                            fallback : ['cpp-httplib'])
cxxopts_dep = dependency('cxxopts',
                         fallback: ['cxxopts'])

sdjournal_dep = dependency('libsystemd')
asio_dep = dependency('asio', fallback: ['asio'])
enum_dep = dependency('magic_enum', fallback: ['magic_enum'])
pfr_dep = dependency('PFR', fallback: ['pfr'])
blobify_dep = dependency('blobify', fallback: ['blobify'])

deps = [cpphttplib_dep, cxxopts_dep, sdjournal_dep, asio_dep, blobify_dep]

subdir('src')
