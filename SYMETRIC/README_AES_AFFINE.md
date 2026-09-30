# AES — S-box affine

**Catégorie :** Crypto · **Type :** AES / cryptanalyse linéaire · **Flag :** `crypto{5b0x_l1n34r17y_15_d35457r0u5}`

> *"Welcome to my military grade encryption service! [...] you will not be able to decrypt it anyway..."*

Un service de chiffrement qui se présente comme de l'AES-128 « qualité militaire » : on peut chiffrer **un seul** bloc de son choix, ou demander le flag chiffré, mais jamais déchiffrer. Le titre du challenge vend la mèche — la S-box a été remplacée.

## Le service

Le serveur instancie un AES-128 avec une clé aléatoire (`urandom(16)`) et expose deux options :

- `encrypt_message` : chiffre un bloc de 16 octets fourni par le joueur. **Limité à un seul appel** par session (compteur `nb_encryptions`).
- `encrypt_flag` : chiffre le flag, paddé en PKCS#7, bloc par bloc en **ECB**.

L'implémentation d'AES est complète et correcte (KeyExpansion, AddRoundKey, SubBytes, ShiftRows, MixColumns, 10 tours). Un seul élément a été modifié : la table `sbox`.

## La faille : une S-box affine

Dans le vrai AES, la S-box est le **seul composant non-linéaire** du chiffrement. C'est elle qui garantit la résistance aux cryptanalyses linéaire et différentielle. Toutes les autres opérations (ShiftRows, MixColumns, AddRoundKey) sont déjà linéaires sur GF(2).

Ici, la S-box fournie est **affine** : il existe une matrice binaire 8×8 `M` et une constante `c` telles que

```
sbox(x) = M · x ⊕ c     avec c = sbox(0) = 0x2a
```

Vérification : on pose `L(x) = sbox(x) ⊕ 0x2a` et on teste `L(a ⊕ b) == L(a) ⊕ L(b)` pour tous les couples — c'est vrai. La S-box est donc affine, et la reconstruction à partir de `M` et `c` seuls redonne la table entière.

### Conséquence

Si SubBytes devient affine, alors **toute** la primitive devient affine. La composition d'opérations affines reste affine, donc le chiffrement d'un bloc s'écrit :

```
E(p) = A · p ⊕ b
```

où :

- `A` est une matrice binaire **128×128** qui ne dépend **que** de la structure (SubBytes/ShiftRows/MixColumns, qui sont fixes) — **pas de la clé** ;
- `b` est un vecteur 128 bits qui absorbe toutes les constantes, y compris les clés de tour ; `b` dépend donc de la clé, mais reste **constant** pour une session donnée.

C'est ce qui rend le « tu ne pourras pas déchiffrer » faux : une fois `A` connue (calculée hors-ligne) et `b` récupérée (une seule paire clair/chiffré suffit), on inverse `E` trivialement.

## L'attaque

**1. Isoler la partie linéaire `A`.** On réécrit le chiffrement en retirant toutes les constantes : on ne fait jamais `AddRoundKey` (retire les clés de tour), et on XOR `0x2a` sur chaque octet après chaque `SubBytes` (retire la constante affine de la S-box). La fonction obtenue, `linear_part`, calcule exactement `A · p`. On vérifie que `E(x) ⊕ E(0) == linear_part(x)` pour tout `x`.

**2. Construire la matrice `A`.** Colonne `i` = `linear_part(eᵢ)`, où `eᵢ` est le bloc n'ayant que le bit `i` à 1. On obtient une matrice 128×128 sur GF(2), **inversible** (rang 128).

**3. Récupérer `b`.** Avec l'unique requête `encrypt_message(p)`, on a `E(p)` et donc
```
b = E(p) ⊕ A · p
```
(en prenant `p = 0`, on a directement `b = E(0)`, puisque `A · 0 = 0`).

**4. Déchiffrer le flag.** Pour chaque bloc chiffré `cᵢ` renvoyé par `encrypt_flag` :
```
A · pᵢ = cᵢ ⊕ b   →   pᵢ = A⁻¹ · (cᵢ ⊕ b)
```
On recolle les blocs, on retire le padding PKCS#7, et on lit le flag.

## Résolution

Dialogue avec le serveur (deux requêtes JSON) :

```json
{"option": "encrypt_message", "message": "00000000000000000000000000000000"}
{"option": "encrypt_flag"}
```

Solveur (Python + `galois` pour l'algèbre linéaire sur GF(2)) :

```python
import numpy as np, galois
from chal import AES          # la classe AES du challenge, en Python pur

GF = galois.GF(2)
C  = [0x2a] * 16

# chiffrement "dé-constanté" => partie purement linéaire  A·p
def linear_part(pt):
    M = AES(b'\x00' * 16)
    M._state = M._transpose(list(pt))
    for i in range(1, 10):
        M._sub_bytes(); M._state = M._xor(C, M._state)
        M._shift_rows(); M._mix_columns()
    M._sub_bytes(); M._state = M._xor(C, M._state)   # stripper AUSSI le dernier tour
    M._shift_rows()
    return bytes(M._transpose(M._state))

# bloc 16 octets <-> vecteur GF(2)^128  (bit k = octet k//8, poids k%8)
def bits(b):   return GF([(b[k//8] >> (k % 8)) & 1 for k in range(128)])
def unbits(v):
    out = bytearray(16)
    for k in range(128):
        if int(v[k]): out[k//8] |= 1 << (k % 8)
    return bytes(out)
def e(i):
    b = bytearray(16); b[i//8] |= 1 << (i % 8); return bytes(b)

# matrice A (colonne i = A·e_i) et son inverse
A = GF(np.zeros((128, 128), dtype=int))
for i in range(128):
    A[:, i] = bits(linear_part(e(i)))
Ainv = np.linalg.inv(A)

# b = E(0)  (p = 0  =>  linear_part(p) = 0  =>  K = E(0))
Ep = bytes.fromhex('ed512426b15168b45745e12a06ab983a')   # reponse encrypt_message(0)
K  = bits(Ep)

# dechiffrement : p = A^-1 (c XOR b)
ct  = bytes.fromhex("4246f968288e99d75975155fba3753d6"
                    "20b70d7a699063d78251ed3e33b72653"
                    "8bc6fd7a26f5347d09986d7aa4277c64")   # encrypt_flag
out = b''
for i in range(0, len(ct), 16):
    out += unbits(Ainv @ (bits(ct[i:i+16]) + K))          # '+' = XOR sur GF(2)

print(out[:-out[-1]])    # retrait du padding
```

Sortie :

```
b'crypto{5b0x_l1n34r17y_15_d35457r0u5}'
```

## Notes de mise en œuvre

- **La classe `AES` doit être en Python pur.** Sous SageMath, l'opérateur `^` signifie *puissance* (le XOR y est `^^`) : le préparseur transforme tous les XOR du code AES en exponentiations et casse tout (`IndexError`). Mettre la classe dans un fichier `.py` importé évite le préparsing ; les `^` y gardent leur sens Python.
- **Convention de bits.** Le mapping octet↔bit de `bits`/`unbits` doit être identique partout, sinon `A` n'est qu'une permutation de la vraie et le flag sort en bouillie (sans erreur visible).
- **`b` dépend de la clé.** Recalculé à chaque session (la clé change à chaque connexion) ; `A`, elle, est fixe et peut être précalculée une fois pour toutes.
- **Padding.** Flag de 40 octets → `40 mod 16 = 8` → 8 octets de padding `\x08`. Ici le flag récupéré faisait 36 octets utiles, d'où un padding `\x0c` (12) — retiré par `out[:-out[-1]]`.

## Leçon

Une S-box qui *a l'air* aléatoire n'est pas sûre pour autant. La sécurité d'AES ne tient pas à l'apparence désordonnée de la table, mais à sa **non-linéarité**, qui se démontre mathématiquement. Remplacer la S-box par une fonction affine — même avec 256 valeurs qui « ressemblent » à une vraie S-box — réduit tout le chiffrement à un système linéaire de 128 équations, résolu en une poignée de requêtes.
