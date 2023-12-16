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
pcg_dep = dependency('pcg', fallback: ['pcg', 'pcg_cpp_dep'])

ut_dep = dependency('ut',
                    method: 'cmake',
                    modules: 'Boost::ut',
                    fallback: ['boostut', 'boostut_dep'])

add_project_arguments('-DBOOST_UT_DISABLE_MODULE', language: 'cpp')

deps = [cpphttplib_dep, cxxopts_dep, sdjournal_dep, asio_dep, blobify_dep, pcg_dep]

subdir('src')
subdir('tests')
