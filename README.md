# acid

Redox general-purpose test suite.

It contains tests to detect regressions, race conditions, kernel faults and incorrect kernel behavior.

## Tests

- `acid switch` - Test to see the context switch time in nanoseconds (ns).

```
P - Parent context switch count (500 by deafult)
C - Child context switch count (500 by deafult)
T - Timestamp counter difference

(timestamp counter is not reliable on every system)
```

- `acid avx2` - TODO
- `acid create_test` - TODO
- `acid channel` - TODO
- `acid page_fault` - TODO
- `acid tcp_fin` - TODO
- `acid thread` - TODO
- `acid tls` - TODO
- `acid cross_scheme_link` - TODO
- `acid efault` - TODO
- `acid direction_flag_sc` - TODO
- `acid direction_flat_int` - TODO
- `acid pipe` - TODO
- `acid scheme_data_leak` - TODO
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
