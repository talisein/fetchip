


dns_exe = executable('dns-test', 'dns.cpp', dependencies: [fetchip_deps, ut_dep])
test('dns', dns_exe)

consensus_exe = executable('consensus-test', 'consensus.cpp', dependencies: [fetchip_deps, ut_dep])
test('consensus', consensus_exe)

consensus_run_exe = executable('consensus-run-test', 'consensus_run.cpp', dependencies: [fetchip_deps, ut_dep])
test('consensus-run', consensus_run_exe)

services_exe = executable('services-test', 'services.cpp', dependencies: [fetchip_deps, ut_dep])
test('services', services_exe)

name_resolver_exe = executable('name-resolver-test', 'name_resolver.cpp', dependencies: [fetchip_deps, ut_dep])
test('name-resolver', name_resolver_exe)

log_exe = executable('log-test', 'log.cpp', dependencies: [fetchip_deps, ut_dep])
test('log', log_exe)

error_category_exe = executable('error-category-test', 'error_category.cpp', dependencies: [fetchip_deps, ut_dep])
test('error-category', error_category_exe)

dns_afl_exe = executable('dns-afl', 'dns_afl.cpp', dependencies: [fetchip_deps, ut_dep])
test('dns-fuzz', dns_afl_exe)

sh = find_program('sh')
test('stdout-full-list', sh, args: ['-c', '"$1" --list name > /dev/full; [ $? -eq 1 ]', 'sh', fetchip_exe])
test('stdout-full-help', sh, args: ['-c', '"$1" --help > /dev/full; [ $? -eq 1 ]', 'sh', fetchip_exe])
test('stdout-ok-list', sh, args: ['-c', '"$1" --list name > /dev/null', 'sh', fetchip_exe])
test('stray-arg-list', sh, args: ['-c', '"$1" --list name extra > /dev/null 2>&1; [ $? -eq 1 ]', 'sh', fetchip_exe])
test('stray-arg-bare', sh, args: ['-c', '"$1" 4 > /dev/null 2>&1; [ $? -eq 1 ]', 'sh', fetchip_exe])
test('stray-arg-after-dashdash', sh, args: ['-c', '"$1" -- -4 > /dev/null 2>&1; [ $? -eq 1 ]', 'sh', fetchip_exe])
