# Synthetic regression fixtures

These files are inputs for static analysis only. Never import, execute, compile into runnable programs, or deploy the vulnerable fixtures. They use invented symbols and placeholder secrets. Each vulnerable file contains one primary expected finding; its fixed counterpart removes the flow or guards the operation. Near-miss cases check that similarly named public variables do not inherit sensitive taint. The authorization fixture assumes a trusted authorization predicate; it is not an implementation of an authorization system.
