This repository contains my solutions, implementations, and write-ups for cryptography challenges from various Capture The Flag competitions.

The goal of this repository is not only to provide working solutions, but also to explain the mathematical ideas and cryptographic vulnerabilities behind each challenge.

Most implementations are written in SageMath and Python.



Each challenge generally contains:

challenge-name/
│
├── README.md      # Explanation of the vulnerability and attack
├── solve.sage     # SageMath implementation
├── solve.py       # Python implementation when relevant
└── challenge.py   # Original challenge file when redistribution is allowed

Write-up Structure

For each challenge, I try to separate the solution into three parts.

1. Mathematical background

Explanation of the mathematical objects and results involved in the challenge.

2. Vulnerability

Identification of the property that makes the cryptosystem vulnerable.

For example:

Elliptic Curve DLP
        ↓
special curve structure
        ↓
reduction to another group
        ↓
easier discrete logarithm
3. Implementation

Translation of the mathematical attack into an algorithm using SageMath or Python.

The objective is to understand why an attack works, rather than simply obtaining the flag.

Tools

Main tools used throughout this repository:

SageMath
Python
PyCryptodome
PARI/GP through SageMath
Git

Some challenges can be run using SageMath directly:

sage solve.sage

or with Python:

python3 solve.py

Example Topics
Singular elliptic curves

A singular cubic does not define an elliptic curve in the usual sense.

Its group of nonsingular points can sometimes be related to a much simpler algebraic group, allowing an elliptic-curve discrete logarithm problem to be transformed into a discrete logarithm in:

(\mathbb{F}_p,+)

or

\mathbb{F}_p^\times.
Pohlig–Hellman

When the order of a group factors into small prime powers,

|G| = \prod_i p_i^{e_i},

the discrete logarithm can be solved independently modulo each p_i^{e_i} and reconstructed using the Chinese Remainder Theorem.

This makes groups with smooth order particularly vulnerable to discrete-logarithm attacks.

Smart's Attack

For anomalous elliptic curves satisfying

#E(\mathbb{F}_p) = p,

Smart's attack uses a lift of the curve to the p-adic numbers to transform the elliptic-curve discrete logarithm problem into a much simpler computation.
