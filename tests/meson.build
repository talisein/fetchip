


dns_exe = executable('dns-test', 'dns.cpp', dependencies: [fetchip_deps, ut_dep])
test('dns', dns_exe)

consensus_exe = executable('consensus-test', 'consensus.cpp', dependencies: [fetchip_deps, ut_dep])
test('consensus', consensus_exe)

dns_afl_exe = executable('dns-afl', 'dns_afl.cpp', dependencies: [fetchip_deps, ut_dep])
test('dns-fuzz', dns_afl_exe)
