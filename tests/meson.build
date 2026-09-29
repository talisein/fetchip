


dns_exe = executable('dns-test', 'dns.cpp', dependencies: [fetchip_deps, ut_dep])
test('dns', dns_exe)

consensus_exe = executable('consensus-test', 'consensus.cpp', dependencies: [fetchip_deps, ut_dep])
test('consensus', consensus_exe)

name_resolver_exe = executable('name-resolver-test', 'name_resolver.cpp', dependencies: [fetchip_deps, ut_dep])
test('name-resolver', name_resolver_exe)

dns_afl_exe = executable('dns-afl', 'dns_afl.cpp', dependencies: [fetchip_deps, ut_dep])
test('dns-fuzz', dns_afl_exe)
