# Twist and Shout — ECSC 2023 (CryptoHack CTF Archive)

## Le service

Le serveur expose une courbe elliptique de Weierstrass court :

```
E: y² = x³ + x + 1494   (mod q),   q = 2^128 - 159
```

`E` a un ordre premier `n`, et le serveur accepte n'importe quelle abscisse `x`,
calcule `d·(x, 1)` avec un algorithme d'échelle de Montgomery « x-only »
(`xDBLADD` / `xMUL`), et renvoie l'abscisse du résultat. `d` est dérivé
directement des octets du flag et reste fixe pour toute la connexion.

## La faille

L'échelle de Montgomery `xDBLADD` ne manipule que des abscisses (et un
dénominateur projectif `Z`) — elle ne calcule jamais `y` et ne vérifie donc
jamais que le `x` envoyé correspond à un point réel de `E`. Or ces formules
ne dépendent que de `a`, `b` et `q`, pas de la courbe précise : elles sont
tout aussi valides pour un point de la **twist quadratique** de `E`.

Concrètement, pour un `x` donné, il y a deux cas :

- si `f(x) = x³ + ax + b` est un carré mod `q`, alors `x` est l'abscisse d'un
  point réel de `E` (avec `y = √f(x)` dans `F_q`) ;
- sinon, `x` n'a pas de `y` dans `F_q` — mais il est *exactement* l'abscisse
  d'un point sur la twist `E'`, dont l'équation est `y² = f(x)` **sur
  l'extension quadratique** `F_{q²}`.

Comme le serveur ne fait cette distinction nulle part, on peut lui envoyer
des abscisses de la twist. Il va bêtement leur appliquer `xMUL(x, d)` et nous
renvoyer l'abscisse de `d·P` — sur la twist cette fois.

L'intérêt : l'ordre de `E` est premier (`n`), donc inattaquable directement,
mais l'ordre de la twist,

```
n' = 2(q+1) - n
```

est **friable** (produit de petits facteurs premiers). C'est la porte
d'entrée classique du *twist attack*.

## L'attaque

Pour chaque facteur premier `l | n'` :

1. On construit un point `P` de la twist d'ordre exactement `l` (on prend un
   point aléatoire de la twist, on le multiplie par le cofacteur `n'/l`).
2. On envoie l'abscisse de `P` au serveur, qui répond l'abscisse de `d·P`.
3. Comme `P` est d'ordre `l`, ce résultat ne dépend que de `d mod l` : on
   résout ce logarithme discret (petit groupe, donc facile — Sage s'en
   charge via `discrete_log`, qui fait du Pohlig-Hellman/BSGS en interne).

Une fois qu'on a `d mod l` pour tous les facteurs de `n'`, le théorème des
restes chinois (CRT) reconstruit `d mod n'` — donc `d` en entier, tant que
le flag est assez court pour que `d < n'` (~128 bits ici).

### L'arithmétique se fait sur `F_{q²}`, pas `F_q`

On ne peut pas manipuler un point de la twist directement dans `F_q` (il n'a
pas de `y` réel, par définition). Astuce : au lieu de recoder à la main
l'arithmétique de la twist, on construit la **même courbe** `E` mais sur le
corps étendu `GF(q²)`. Tout `x ∈ F_q` s'y relève en un point valide
(`E2.lift_x`), et le sous-groupe des points de `E(F_{q²})` dont l'abscisse
est réelle (dans `F_q`) est exactement isomorphe à la twist `E'(F_q)`,
d'ordre `n'`. Ça permet d'utiliser toute l'arithmétique de courbe elliptique
native de Sage (addition, ordre, `discrete_log`) sans rien réimplémenter.

### L'ambiguïté de signe

L'échelle x-only ne renvoie qu'une abscisse, jamais un signe : elle ne fait
donc jamais la différence entre `d·P` et `-d·P` (même abscisse). Résultat :
chaque `d mod l` récupéré est en fait connu **à ± près**, donc en combinant
par CRT on obtient deux candidats possibles pour `d` (`d` et `n' - d`), pas
un seul.

Pour trancher, une requête supplémentaire suffit : on prédit localement
(sans repasser par le réseau — `local_shout`, une copie de l'échelle du
serveur) l'abscisse attendue pour chaque candidat sur un point de test, et on
compare à la vraie réponse du serveur. Le bon candidat matche ; l'autre non
(ou les deux matchent — dans ce cas c'est le décodage ASCII du flag qui
tranche).

### Un détail pratique : les crashs serveur

Si `d ≡ 0 (mod l)` pour un facteur donné, le serveur calcule un point à
l'infini et plante en interne (division par zéro dans son code, non gérée).
La connexion meurt sans réponse exploitable. Comme `d` est fixe, retenter la
même requête plante identiquement à chaque fois — le script détecte ce
crash répété et l'interprète directement comme `d mod l = 0`, plutôt que de
boucler indéfiniment.

## Utilisation

```
sage solve_twist_and_shout.sage archive.cryptohack.org 11718
```

Le script affiche `d mod l` facteur par facteur, puis le ou les candidats
finaux avec leur décodage en flag.
