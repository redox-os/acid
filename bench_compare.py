#!/usr/bin/env python3
import numpy as np
import scipy.stats
import sys

if len(sys.argv) < 3:
    sys.exit("Usage: compare.py BEFORE_METRICS AFTER_METRICS METRIC_NAME")

def parse(filename):
    d = {}
    for line in open(filename):
        key, val = line.rstrip().split("=")
        d[key] = float(val)
    return d

def collect_samples(d, name):
    samples = []
    for k, v in d.items():
        if k.startswith(f"{name}_sample_"):
            samples.append(v)
    return np.array(samples)

before = parse(sys.argv[1])
after = parse(sys.argv[2])
metric = sys.argv[3]

before_samples = collect_samples(before, metric)
after_samples = collect_samples(after, metric)

before_mean = np.mean(before_samples)
before_std = np.std(before_samples)
after_mean = np.mean(after_samples)
after_std = np.std(after_samples)
change = (after_mean - before_mean)/before_mean*100

print(f"metric {metric}: {before_mean:.3f}±{before_std:.3f} vs {after_mean:.3f}±{after_std:.3f} ({change:.3f}%)")

test_res = scipy.stats.ttest_ind(before_samples, after_samples, equal_var=False)
print(f"P-value: {test_res.pvalue}")
