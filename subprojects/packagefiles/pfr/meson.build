project('PFR', ['cpp'])


pfr_inc = include_directories('include')
pfr_dep = declare_dependency(include_directories: pfr_inc)

meson.override_dependency('PFR', pfr_dep)
