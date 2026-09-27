# Too Many Errors — Removing the noise from LWE with a resettable PRNG

An attack on a flawed LWE sample generator: by resetting the server's PRNG,
we obtain pairs of samples sharing **the same error**, which cancels out in
their difference. The noisy LWE problem collapses into a plain linear system
over `Z/127Z`.

## 1. Background: LWE in one paragraph

In **Learning With Errors**, the secret is a vector `s ∈ (Z/qZ)^n`. Each sample
is a pair `(a, b)` where `a` is uniformly random and

```
b = <a, s> + e   (mod q)
```

with `e` a small error. Without `e`, recovering `s` is just Gaussian elimination
on `n` samples. With `e`, the problem is believed to be hard. **The whole
security of LWE rests on the noise.**

Here, the secret is the flag itself (`s_i = FLAG[i]`), `q = 127` and
`e ∈ {-1, 0, 1}`.

## 2. The vulnerability: the noise is reproducible

The server draws `a` and `e` from a `random.Random` instance seeded with a
fixed `SEED`, and exposes a `reset` option that reseeds it with that same value:

```python
elif your_input["option"] == "reset":
    self.rand.seed(SEED)
```

Consequence: **the first sample after a reset always uses the same `a` and the
same `e`.**

Two details make it slightly less trivial:

- At the end of each `get_sample`, the PRNG is reseeded with a truly random
  value (`getrandbits(32)`). Only the **first** sample after a reset is
  deterministic; the 2nd, 3rd... are not.
- Before computing `b`, the server flips a coin and, with probability 1/2,
  replaces **one random coordinate** of `a` with a fresh random value.
  Crucially, `e` is drawn *before* this modification, so it is unaffected.

```
reset → same (a, e)
          ↓
random tweak of one coordinate of a
          ↓
b = <a', s> + e      (same e every time!)
```

## 3. Cancelling the error

Take two samples, each obtained right after a reset:

```
b1 = <a1, s> + e
b2 = <a2, s> + e
```

Subtracting:

```
b1 - b2 = <a1 - a2, s>   (mod q)
```

**The error is gone.** Each such pair gives an exact linear equation in the
flag bytes.

Since `a1` and `a2` are both "the original `a` plus at most one modified
coordinate", the difference `a1 - a2` has **one or two** non-zero coordinates.
If both modifications happened at the same index `k`:

```
b1 - b2 = (a1[k] - a2[k]) * FLAG[k]   (mod q)
```

and since `q = 127` is prime, `FLAG[k]` is obtained by a single modular
inversion.

## 4. Building the system

Rather than relying on "exactly one non-zero coordinate" (which fails when one
of the two samples was itself modified at another index), we collect rows
`a1 - a2` and keep one only if it **increases the rank** of the matrix. We stop
once the matrix `M` is of full rank `n = len(FLAG)`:

```
M · FLAG = B   (mod 127)
```

`M` is very sparse (one or two non-zero entries per row), and since the
modified index is chosen at random, covering all `n` positions is a
**coupon-collector** problem: expect around `n · ln(n)` useful pairs, not `n`.

Note: `n` does not need to be guessed; it is simply `len(a)`, since the server
generates one coefficient per flag byte.

## 5. Implementation (SageMath)

```python
from pwn import remote
import json

q = 127
Zn = Integers(q)

io = remote("socket.cryptohack.org", 13390)
io.recvline()  # welcome message

def send(obj):
    io.sendline(json.dumps(obj).encode())
    return json.loads(io.recvline().decode())

def reset_serv():
    return send({"option": "reset"})

def sample_serv():
    return send({"option": "get_sample"})

def first_sample():
    # only the first sample after a reset shares the fixed error e
    reset_serv()
    s = sample_serv()
    return vector(Zn, s["a"]), Zn(s["b"])

def find_row():
    a1, b1 = first_sample()
    a2, b2 = first_sample()
    while a1 == a2:            # no tweak on one side → no information
        a2, b2 = first_sample()
    return a1 - a2, b1 - b2    # the error cancels out

n = len(first_sample()[0])

M = matrix(Zn, 0, n)
vals = []
while M.rank() < n:
    row, val = find_row()
    candidate = M.stack(row)
    if candidate.rank() > M.rank():   # keep only new information
        M = candidate
        vals.append(val)

B = vector(Zn, vals)
f = M.solve_right(B)

print(bytes([int(x) for x in f]).decode())
```

## Summary table

| Step | What happens |
|---|---|
| Reset | The PRNG restarts from `SEED`: same `a`, same `e` |
| Take first sample | Only the first sample after a reset is deterministic |
| Pair two samples | `a1 ≠ a2` thanks to the random coordinate tweak |
| Subtract | `b1 - b2 = <a1 - a2, s>`: the error disappears |
| Rank filtering | Keep a row only if it increases `rank(M)` |
| Solve | `M · FLAG = B` over `Z/127Z`, then convert to bytes |

## Takeaways

- **LWE is only as strong as its noise.** If an attacker can obtain two
  equations with the same error, the difference is noise-free and the problem
  becomes linear algebra.
- Resetting a PRNG to a fixed seed replays *everything* drawn from it,
  including values meant to stay secret or independent across samples.
- The random tweak applied *after* drawing `e` does not help: it changes `a`
  but not `e`, which is precisely what lets the difference be informative.
- Each row costs two resets and two samples; keeping a fixed reference sample
  would halve the number of requests, at the cost of a slightly more careful
  analysis if that reference was itself tweaked.
