# acid

Redox general-purpose test suite.

It contains tests to detect regressions, race conditions, kernel faults, incorrect kernel behavior and others.

The following tests are allowed:

- Logic tests
- Stress tests
- Performance tests (mainly cost of operations)

## Tests

- `acid avx2` - TODO
- `acid create_test` - TODO
- `acid channel` - TODO
- `acid page_fault` - Not working
- `acid tcp_fin` - TODO
- `acid thread` - TODO
- `acid tls` - TODO
- `acid cross_scheme_link` - TODO
- `acid efault` - TODO
- `acid direction_flag_sc` - TODO
- `acid direction_flat_int` - TODO
- `acid pipe` - TODO
- `acid scheme_data_leak_proc` - TODO
- `acid scheme_data_leak_thread` - TODO
- `acid scheme_call` - TODO
- `acid relibc_leak` - TODO
- `acid clone_grant_using_fmap` - TODO
- `acid clone_grant_using_fmap_lazy` - TODO
- `acid anonymous_map_shared` - TODO
- `acid tlb` - TODO
- `acid file_mmap` - TODO
- `acid redoxfs_range_bookkeeping` - TODO
- `acid eintr` - TODO
- `acid syscall_bench` - TODO
- `acid filetable_leak` - TODO
- `acid pgrp_lifetime` - TODO
- `acid waitpid_transitive_queue` - TODO
- `acid waitpid_status_discard` - TODO
- `acid waitpid_esrch` - TODO
- `acid using_signal_hook` - TODO
- `acid wcontinued_sigcont_catching` - TODO
- `acid stop_orphan_pgrp` - TODO
- `acid orphan_exit_sighup` - TODO
- `acid orphan_exit_sighup_session` - TODO
- `acid wcontinued_sigcont_catching` - TODO
- `acid thread_reap` - TODO
- `acid waitpid_setpgid_echild` - TODO
- `acid setsid` - TODO
- `acid setpgid` - TODO
- `acid reparenting` - TODO
- `acid fork_tree_bench` - TODO
- `acid fork_serial_bench` - TODO
- `acid fork_exec_tree_bench` - TODO
- `acid fork_exec_serial_bench` - TODO
- `acid uds_dgram` - Test the Unix Domain Socket datagram protocol.
- `acid uds_stream` - Test the Unix Domain Socket stream protocol.
- `acid uds_dgram_msghdr` - Test the sendmsg/recvmsg functionality over Unix Domain Sockets datagram protocol.
- `acid uds_stream_msghdr` - Test the sendmsg/recvmsg functionality over Unix Domain Sockets stream protocol.
- `acid switch` - Test to measure the context switch time in nanoseconds (ns).

```
P - Parent context switch count (500 by deafult)
C - Child context switch count (500 by deafult)
T - Timestamp counter difference

(The timestamp counter is not reliable on every system)
```
