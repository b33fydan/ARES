"""ARES-Harness AgentDojo adapter package.

Import-light by contract: nothing in this package (or its modules) imports
``agentdojo``. The adapter elements are duck-typed against AgentDojo's pipeline
protocol so they unit-test offline in the main venv. See the design note §3
"Import isolation" and the guard in tests/harness/test_harness_import_isolation.py.
"""
