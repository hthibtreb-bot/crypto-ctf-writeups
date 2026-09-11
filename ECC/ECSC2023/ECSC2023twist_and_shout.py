import sys, socket

q = 2**128 - 159
a = 1
b = 1494
n = 340282366920938463465004184633952524077

Fq  = GF(q)
Fq2 = GF(q**2)
E2  = EllipticCurve(Fq2, [a, b])          # same equation, extension field

n_twist = 2 * (q + 1) - n
fac = factor(n_twist)
print("factorisation de l'ordre de twist:", fac)


# ---------------- network oracle ----------------CLAUDE Code

PROMPT = b"x-coordinate: "

class Oracle:
    def __init__(self, host, port):
        self.host, self.port = host, port
        self.buf = b""
        self._connect()

    def _connect(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=15)
        self.buf = b""
        self._read_until(PROMPT)   # drain banner + first prompt

    def _read_until(self, delim):
        while delim not in self.buf:
            data = self.sock.recv(4096)
            if not data:
                raise EOFError
            self.buf += data
        idx = self.buf.index(delim) + len(delim)
        chunk, self.buf = self.buf[:idx], self.buf[idx:]
        return chunk

    def query(self, x, retries=3):
        saw_eof = False
        for _ in range(retries):
            try:
                self.sock.sendall((str(x) + "\n").encode())
                chunk = self._read_until(PROMPT)
                resp = chunk[:-len(PROMPT)].strip()
                if resp == b"":
                    return None
                return int(resp)
            except EOFError:
                # server crashed computing shout(x,d) -> almost always means the
                # result was the point at infinity (division by zero). d is fixed,
                # so retrying the same x crashes identically every time; after
                # retries are exhausted, infer "point at infinity" instead of raising.
                saw_eof = True
                self._connect()
            except (ConnectionResetError, ValueError, OSError):
                self._connect()
        if saw_eof:
            return None
        raise RuntimeError(f"oracle failed for x={x} after {retries} retries")


# ---------------- attack ----------------
def twist_point_of_order(l):
    cofactor = n_twist // l
    while True:
        x = Fq.random_element()
        fx = x**3 + a * x + b
        if fx == 0 or fx.is_square():
            continue                       
        Q = cofactor * E2.lift_x(Fq2(x))
        if Q != E2(0):
            return Q

def solve(oracle):
    per_factor = []
    for l, e in fac:
        l_full = l**e
        P = twist_point_of_order(l_full)
        r_x = oracle.query(ZZ(Fq(P[0])))
        if r_x is None:
            per_factor.append((l_full, 0))
            print(f"[*] l={l_full}")
            continue
        R = E2.lift_x(Fq2(r_x))
        k = P.discrete_log(R)             
        per_factor.append((l_full, k))
        print(f"[*] l={l_full}: d = {k}")

    moduli  = [l for l, k in per_factor]
    options = [(k, (l - k) % l) if k != 0 else (0,) for l, k in per_factor]

    while True:
        tx = Fq.random_element()
        ftx = tx**3 + a * tx + b
        if ftx != 0 and not ftx.is_square():
            break
    test_r = oracle.query(ZZ(tx))

    hits = []
    for combo in cartesian_product(options):
        d_candidate = CRT_list(list(combo), moduli)
        pred = local_shout(tx, d_candidate)     
        if pred == test_r:
            hits.append(Integer(d_candidate))
    return hits


# code fourni CTF
def xDBLADD(P, Q, PQ):
    (X1, Z1), (X2, Z2), (X3, Z3) = PQ, P, Q
    X4 = (X2**2 - a * Z2**2)**2 - 8 * b * X2 * Z2**3
    Z4 = 4 * (X2 * Z2 * (X2**2 + a * Z2**2) + b * Z2**4)
    X5 = Z1 * ((X2 * X3 - a * Z2 * Z3)**2 - 4 * b * Z2 * Z3 * (X2 * Z3 + X3 * Z2))
    Z5 = X1 * (X2 * Z3 - X3 * Z2)**2
    return (X4 % q, Z4 % q), (X5 % q, Z5 % q)

def local_shout(x, d):
    x, d = ZZ(x), ZZ(d)
    Qp, R = (1, 0), (x, 1)
    for i in reversed(range(d.nbits() + 1)):
        if d >> i & 1:
            R, Qp = Qp, R
        Qp, R = xDBLADD(Qp, R, (x, 1))
        if d >> i & 1:
            R, Qp = Qp, R
    X, Z = Qp
    return None if Z % q == 0 else (X * pow(Z, -1, q)) % q


if __name__ == "__main__":
    host, port = sys.argv[1], int(sys.argv[2])
    oracle = Oracle(host, port)

    hits = solve(oracle)
    for h in hits:
        nb = (h.nbits() + 7) // 8
        raw = int(h).to_bytes(nb, "big")
        try:
            print(f"[+] candidate {h} -> ECSC{{{raw.decode()}}}")
        except UnicodeDecodeError:
            print(f"[-] candidate {h} -> not printable, skipping")
