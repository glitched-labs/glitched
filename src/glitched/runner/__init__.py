"""
The on-site runner: pairs with a hosted console, takes jobs over an outbound
long-poll, and probes robots only as its own local policy allows (ADR 0002).
Standard library only - it runs without the rest of Glitched's dependencies.
"""

PROTOCOL = 1
