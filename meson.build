project('fetchip', 'cpp', default_options : ['cpp_std=c++26'])

cxxopts_dep = dependency('cxxopts',
                         fallback: ['cxxopts'])

sdjournal_dep = dependency('libsystemd')
boost_dep = dependency('boost', modules: ['system'], version: '>=1.86')
openssl_dep = dependency('openssl', version: '>=3.0.0')
enum_dep = dependency('magic_enum', fallback: ['magic_enum'])
pfr_dep = dependency('PFR', fallback: ['PFR'])
blobify_dep = dependency('blobify', fallback: ['blobify'])
pcg_dep = dependency('pcg', fallback: ['pcg', 'pcg_cpp_dep'])

ut_dep = dependency('ut',
                    method: 'cmake',
                    modules: 'Boost::ut',
                    fallback: ['boostut', 'boostut_dep'])

add_project_arguments('-DBOOST_UT_DISABLE_MODULE', language: 'cpp')

deps = [cxxopts_dep, sdjournal_dep, boost_dep, openssl_dep, blobify_dep, pcg_dep]

subdir('src')
subdir('tests')
