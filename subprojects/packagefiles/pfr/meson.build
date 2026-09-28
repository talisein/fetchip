project('PFR', ['cpp'], license: 'BSL-1.0')


pfr_inc = include_directories('include', is_system: true)
pfr_dep = declare_dependency(include_directories: pfr_inc)

meson.override_dependency('PFR', pfr_dep)
