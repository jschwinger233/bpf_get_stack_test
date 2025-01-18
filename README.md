# bpf_get_stack_test

TL;DR

* manual overhead: 32797.64 -> 26075.62, -20.5%
* helper overhead: 32797.64 -> 23512.82, -28.3%

Manual overhead is much less than helper.

What's more, the manual method also fetches the latest caller frames which are always missed by the helper method. Please refer to the following output.

Helper output:
```
    ip_rcv
    __netif_receive_skb
    process_backlog
    __napi_poll
    net_rx_action
```

Manual output:
```
    ip_rcv
->  __netif_receive_skb_one_core
    __netif_receive_skb
    process_backlog
    __napi_poll
    net_rx_action
```

Also, the manual mode can't lose backtrace data, unlike the helper mode which may suffer the BPF_MAP_TYPE_STACK_TRACE full issue under high load.

## 1. baseline

```shell
$ redis-benchmark -t set -n 100000
====== SET ======
  100000 requests completed in 3.05 seconds
  50 parallel clients
  3 bytes payload
  keep alive: 1
  host configuration "save": 3600 1 300 100 60 10000
  host configuration "appendonly": no
  multi-thread: no

0.00% <= 0.2 milliseconds
0.05% <= 0.3 milliseconds
2.21% <= 0.4 milliseconds
4.41% <= 0.5 milliseconds
5.66% <= 0.6 milliseconds
7.58% <= 0.7 milliseconds
30.03% <= 0.8 milliseconds
67.16% <= 0.9 milliseconds
82.19% <= 1.0 milliseconds
86.81% <= 1.1 milliseconds
89.34% <= 1.2 milliseconds
91.91% <= 1.3 milliseconds
94.75% <= 1.4 milliseconds
97.75% <= 1.5 milliseconds
98.80% <= 1.6 milliseconds
99.38% <= 1.7 milliseconds
99.62% <= 1.8 milliseconds
99.72% <= 1.9 milliseconds
99.75% <= 2 milliseconds
99.98% <= 3 milliseconds
100.00% <= 3 milliseconds
32797.64 requests per second
```

## 2. bpf_get_stack_test --helper ip_rcv

```shell
$ redis-benchmark -t set -n 100000
====== SET ======
  100000 requests completed in 4.25 seconds
  50 parallel clients
  3 bytes payload
  keep alive: 1
  host configuration "save": 3600 1 300 100 60 10000
  host configuration "appendonly": no
  multi-thread: no

0.00% <= 0.3 milliseconds
0.01% <= 0.4 milliseconds
0.12% <= 0.5 milliseconds
0.52% <= 0.6 milliseconds
1.03% <= 0.7 milliseconds
1.81% <= 0.8 milliseconds
3.85% <= 0.9 milliseconds
16.82% <= 1.0 milliseconds
38.33% <= 1.1 milliseconds
57.10% <= 1.2 milliseconds
68.29% <= 1.3 milliseconds
74.29% <= 1.4 milliseconds
78.10% <= 1.5 milliseconds
81.14% <= 1.6 milliseconds
84.06% <= 1.7 milliseconds
87.04% <= 1.8 milliseconds
89.54% <= 1.9 milliseconds
91.46% <= 2 milliseconds
97.67% <= 3 milliseconds
98.97% <= 4 milliseconds
99.48% <= 5 milliseconds
99.73% <= 6 milliseconds
99.87% <= 7 milliseconds
99.94% <= 8 milliseconds
99.99% <= 9 milliseconds
100.00% <= 10 milliseconds
23512.82 requests per second
```

## 3. bpf_get_stack_test --manual ip_rcv

```
$ redis-benchmark -t set -n 100000
====== SET ======
  100000 requests completed in 3.84 seconds
  50 parallel clients
  3 bytes payload
  keep alive: 1
  host configuration "save": 3600 1 300 100 60 10000
  host configuration "appendonly": no
  multi-thread: no

0.00% <= 0.3 milliseconds
0.01% <= 0.4 milliseconds
0.06% <= 0.5 milliseconds
0.19% <= 0.6 milliseconds
0.49% <= 0.7 milliseconds
1.55% <= 0.8 milliseconds
16.28% <= 0.9 milliseconds
48.35% <= 1.0 milliseconds
71.07% <= 1.1 milliseconds
81.82% <= 1.2 milliseconds
87.05% <= 1.3 milliseconds
90.06% <= 1.4 milliseconds
92.00% <= 1.5 milliseconds
93.67% <= 1.6 milliseconds
95.09% <= 1.7 milliseconds
96.19% <= 1.8 milliseconds
97.05% <= 1.9 milliseconds
97.65% <= 2 milliseconds
99.17% <= 3 milliseconds
99.61% <= 4 milliseconds
99.79% <= 5 milliseconds
99.85% <= 6 milliseconds
99.88% <= 7 milliseconds
99.91% <= 8 milliseconds
99.95% <= 9 milliseconds
99.99% <= 10 milliseconds
100.00% <= 10 milliseconds
26075.62 requests per second
```
