# Collision on `cryptohash` — the math

## 1. The key observation: everything is affine

The hash only uses two operations: `xor` and rotations (`rotate_left`/`rotate_right`).

- **XOR with a constant**: `f(x) = c ⊕ x` is an *affine* function (linear + constant).
- **Rotation**: `rotate(x, n)` is a byte permutation, hence **linear** (`rotate` of `0` is the neutral element, and `rotate(a ⊕ b) = rotate(a) ⊕ rotate(b)`).

The composition of affine functions stays affine, **regardless of order** (XOR and rotation don't need to commute for this to hold). So `scramble_block` and the position loop are each of the form:

```
f(x) = L(x) ⊕ C
```

where `L` is linear (over GF(2)) and `C` is a fixed constant.

## 2. Isolating the linear part

For any affine function, `L(0) = 0`, so:

```
f(x) ⊕ f(0) = L(x)
```

→ `L` can be extracted without touching the code, just by evaluating `f` at two points.

The central property used throughout the attack:

```
f(a) ⊕ f(b) = L(a ⊕ b)
```

## 3. The hash is a sum (XOR) of per-block contributions

```
H(msg) = C ⊕ L_0(block_0) ⊕ L_1(block_1) ⊕ ... ⊕ L_{n-1}(block_{n-1})
```

`C` only depends on the number of blocks (not their content) → if two messages have **the same number of blocks**, `C` cancels out in the difference.

For two messages `m`, `m'` of the same length, with `Δ_i = block_i ⊕ block'_i`:

```
H(m) ⊕ H(m') = L_0(Δ_0) ⊕ L_1(Δ_1) ⊕ ... ⊕ L_{n-1}(Δ_{n-1})
```

## 4. Why a single block is not enough

If only one `Δ_i ≠ 0`: we'd need `L_i(Δ_i) = 0`. Since each `L_i` is **linear and bijective**, this forces `Δ_i = 0`. **No collision is possible by changing a single block.**

## 5. With two blocks, it becomes possible

If two blocks differ (positions `j` and `k`), the equation becomes:

```
L_j(Δ_j) ⊕ L_k(Δ_k) = 0
⟺ L_j(Δ_j) = L_k(Δ_k)
```

Since `L_j` and `L_k` are bijective (hence invertible), we can pick `Δ_j` freely and solve:

```
Δ_k = L_k⁻¹(L_j(Δ_j))
```

→ Two different messages, same hash.

## 6. Concrete case: `L_i` is just a byte rotation

Here, `xor` never moves bits around, and `rotate_left`/`rotate_right` only shift whole bytes as a block. So the linear part of each `L_i` **is not a general binary matrix** — it's just `rotate_right(x, shift_i)` for some shift that depends on the position `i`.

- `shift_i` can be found empirically by sending a single marker byte (`0xFF`) through `L_i` and checking where it ends up.
- Inverting `L_i` is then trivial: `L_i⁻¹(x) = rotate_left(x, shift_i)`.

## 7. Final recipe

```python
sh0 = find_shift(0)
sh1 = find_shift(1)

block0, block1 = os.urandom(32), os.urandom(32)
msg = block0 + block1                      # exactly 2 blocks

delta0 = os.urandom(32)                    # free Δ on block 0
delta1 = rotate_left(rotate_right(delta0, sh0), sh1)   # forced Δ on block 1

msgp = xor(block0, delta0) + xor(block1, delta1)

assert msg != msgp
assert cryptohash(msg) == cryptohash(msgp)  # collision confirmed
```

**One-sentence summary**: the hash is an affine, per-block function whose linear parts are simple invertible byte rotations; as soon as you have two blocks of freedom, you can pick the difference on one to exactly cancel out the difference on the other.
