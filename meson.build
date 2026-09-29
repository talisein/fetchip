project('fetchip', 'cpp', version: '0.9.0', license: 'GPL-3.0-or-later', default_options : ['cpp_std=c++26'])

cxxopts_dep = dependency('cxxopts',
                         fallback: ['cxxopts'])

sdjournal_dep = dependency('libsystemd')
boost_dep = dependency('boost', modules: ['system'], version: '>=1.86')
openssl_dep = dependency('openssl', version: '>=3.0.0')
enum_dep = dependency('magic_enum', version: '>=0.9.6', fallback: ['magic_enum'])
blobify_dep = dependency('blobify', fallback: ['blobify'])

# Fedora's pcg-cpp-devel installs the headers with no pkg-config file.
cpp = meson.get_compiler('cpp')
if cpp.has_header('pcg_random.hpp')
  pcg_dep = declare_dependency()
else
  pcg_dep = dependency('pcg', fallback: ['pcg', 'pcg_cpp_dep'])
endif

ut_dep = dependency('ut',
                    method: 'cmake',
                    modules: 'Boost::ut',
                    fallback: ['boostut', 'boostut_dep'])

add_project_arguments('-DBOOST_UT_DISABLE_MODULE', language: 'cpp')

# PFR's C++26 path uses structured binding packs, which GCC 16.2 cannot
# stream under -flto: "tree code 'decltype_type' is not supported in LTO
# streams".
add_project_arguments('-DBOOST_PFR_USE_CPP26=0', language: 'cpp')

if get_option('buildtype') == 'debug'
  add_project_arguments('-DFETCHIP_JOURNAL_DEBUG', language: 'cpp')
endif

deps = [cxxopts_dep, sdjournal_dep, boost_dep, openssl_dep, enum_dep, blobify_dep, pcg_dep]

subdir('src')
subdir('tests')

install_man('fetchip.1')

bash_completion_dep = dependency('bash-completion', required: false)
if bash_completion_dep.found()
  bash_completion_dir = bash_completion_dep.get_variable(pkgconfig: 'completionsdir')
else
  bash_completion_dir = get_option('datadir') / 'bash-completion' / 'completions'
endif
install_data('completions/fetchip.bash', install_dir: bash_completion_dir, rename: 'fetchip')
