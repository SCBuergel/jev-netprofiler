"""Qubes OS net-qube traffic profiler.

Captures per-vif flow metadata with nfstream, reduces a rolling window into a
numbers-free description of traffic *shape*, and asks TypeSafe's Jev which
catalogued activity that shape most resembles. All arithmetic (bucketing,
entropy, smoothing, bit accounting) stays in Python; Jev only maps a described
shape onto an activity name.
"""

__version__ = "0.1.0"
