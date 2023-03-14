# acid

Tests to identify faults and incorrect behavior in the Redox microkernel.

### Tests

- `acid switch` - test to see the context switch time in nanoseconds (ns).

P - Parent context switch count (500 by deafult)

C - Child context switch count (500 by deafult)

T - Timestamp counter difference

(timestamp counter is not reliable on every system).
