# CJLOSS Attack on Merkle-Hellman Knapsack Cryptosystem

A lattice-based attack that recovers the plaintext directly from a Merkle-Hellman
public key and ciphertext, without ever reconstructing the private key.

## Background: Merkle-Hellman in one paragraph

The public key is a list of integers `a = (a_1, ..., a_n)`, derived from a secret
**superincreasing sequence** `b` via `a_i = (r * b_i) mod q`. A message's bits
`m_i` are encrypted as a subset sum:

```
s = sum(m_i * a_i)
```

Decryption is easy with `(b, r, q)` because superincreasing sequences make subset-sum
trivial to invert. Without the private key, subset-sum is NP-hard in general —
but Merkle-Hellman's specific instances turn out to be breakable using lattice
reduction, because the "density" of the knapsack is low.

## What CJLOSS gives you

Instead of trying to recover `b`, `r`, and `q` (which requires knowing all three
consistently), CJLOSS attacks the **ciphertext directly** and outputs the message
bits themselves, using only `a` and `s`.

## Key idea

Recenter each bit: `m_i in {0,1}` becomes `eps_i = 2*m_i - 1 in {-1, +1}`.

This turns the subset-sum equation into:

```
sum(eps_i * a_i) = 2s - sum(a_i)
```

The vector `(eps_1, ..., eps_n)` has every coordinate equal to exactly `+1` or
`-1`, so its Euclidean norm is fixed and small (`sqrt(n)`). That's a lattice
vector that's *abnormally short* compared to a random lattice vector of the same
dimension — exactly the kind of anomaly LLL is good at finding.

## Building the lattice

Construct the following `(n+1) x (n+1)` integer matrix:

```
[ 2  0  0  ...  0   a_1 ]
[ 0  2  0  ...  0   a_2 ]
[ 0  0  2  ...  0   a_3 ]
[ ...                   ]
[ 0  0  0  ...  2   a_n ]
[ 1  1  1  ...  1   s   ]
```

The vector `(eps_1, ..., eps_n, 0)` is a genuine lattice point: it equals
`sum(m_i * row_i) - 1 * last_row`, and its last coordinate cancels out exactly
because `sum(m_i * a_i) = s`.

## Why LLL finds it

The lattice's determinant is large (roughly `2^n * s`), so a "typical" lattice
vector has a norm much bigger than `sqrt(n)`. This gap between the expected norm
and the actual norm of `(eps, 0)` is what guarantees LLL will surface it as one
of the first reduced basis vectors — provided the knapsack's **density**
(`n / log2(max(a_i))`) stays under roughly **0.9408** (the CJLOSS threshold,
improved from Lagarias-Odlyzko's ~0.6463 thanks to the `2` on the diagonal).

Merkle-Hellman's original superincreasing construction typically has low
density, which is exactly why it's breakable this way.

## Recovering the message

1. Run LLL on the matrix above.
2. Look for a reduced row whose last coordinate is `0` and whose other
   coordinates are all `+1` or `-1`.
3. Convert: `bit_i = (eps_i + 1) / 2` (or `(1 - eps_i) / 2` if the sign is
   flipped — LLL may return the vector or its negation).
4. Reassemble: `msg = sum(bit_i << i for i in range(n))`, then convert to bytes.

If no single row qualifies, try small integer combinations of two reduced rows
(`±row_i ± row_j`) — the target vector isn't always a raw basis row.

## Reference implementation (SageMath)

```python
from Crypto.Util.number import long_to_bytes

a = [...]   # public key, list of integers
s = ...     # ciphertext (integer)

n = len(a)

L = [[0]*(n+1) for _ in range(n+1)]
for i in range(n):
    L[i][i] = 2
    L[i][n] = a[i]
L[n] = [1]*n + [s]

M = Matrix(ZZ, L)
reduced = M.LLL()

def try_decode(eps):
    out = []
    for bits in ([(x+1)//2 for x in eps], [(1-x)//2 for x in eps]):
        try:
            msg_int = sum(bit << i for i, bit in enumerate(bits))
            out.append(long_to_bytes(msg_int))
        except Exception:
            pass
    return out

for row in reduced:
    *eps, last = row
    if last == 0 and all(x in (1, -1) for x in eps):
        for candidate in try_decode(eps):
            print(candidate)
```

## Summary table

| Step | What happens |
|---|---|
| Recenter bits | `m_i -> eps_i = ±1` gives a fixed, small target norm |
| Build lattice | Embed both the public key `a` and the ciphertext `s` |
| Run LLL | The short `(±1,...,±1, 0)` vector surfaces in the reduced basis |
| Filter candidates | Keep rows with last coord `0` and all other coords `±1` |
| Decode | `±1 -> bit -> integer -> bytes` |

## Limitations

- Works reliably only when the knapsack density is below ~0.9408.
- High-density knapsacks (later "improved" Merkle-Hellman variants, iterated
  modular transformations, etc.) are designed specifically to defeat this
  attack.
- LLL gives no absolute guarantee — it's a well-supported heuristic backed by
  a volume/density argument, not a proof that the short vector will always be
  found.
