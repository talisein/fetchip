


dns_exe = executable('dns-test', 'dns.cpp', dependencies: [fetchip_deps, ut_dep])
test('dns', dns_exe)

consensus_exe = executable('consensus-test', 'consensus.cpp', dependencies: [fetchip_deps, ut_dep])
test('consensus', consensus_exe)

name_resolver_exe = executable('name-resolver-test', 'name_resolver.cpp', dependencies: [fetchip_deps, ut_dep])
test('name-resolver', name_resolver_exe)

dns_afl_exe = executable('dns-afl', 'dns_afl.cpp', dependencies: [fetchip_deps, ut_dep])
test('dns-fuzz', dns_afl_exe)

sh = find_program('sh')
test('stdout-full-list', sh, args: ['-c', '"$1" --list name > /dev/full; [ $? -eq 1 ]', 'sh', fetchip_exe])
test('stdout-full-help', sh, args: ['-c', '"$1" --help > /dev/full; [ $? -eq 1 ]', 'sh', fetchip_exe])
test('stdout-ok-list', sh, args: ['-c', '"$1" --list name > /dev/null', 'sh', fetchip_exe])
