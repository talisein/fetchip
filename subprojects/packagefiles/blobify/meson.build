project('blobify', ['cpp'])

pfr_dep = dependency('PFR', fallback: ['PFR'])
magic_enum_dep = dependency('magic_enum', fallback: ['magic_enum'])

blobify_inc = include_directories('include')
blobify_dep = declare_dependency(
  link_args : [],
  compile_args : [],
  include_directories : blobify_inc,
  dependencies: [pfr_dep, magic_enum_dep]
)

meson.override_dependency('blobify', blobify_dep)
