from hashlib import sha256 as H
from Crypto.Util.number import bytes_to_long
nbit = 1024



def keygen(nbit):
    p = random_prime(2^nbit,lbound= 2^(nbit-1))
    x = randint(1,p-1)
    y =1
    while gcd(x,p-1) != 1 or y==1:
        x = randint(1,p-1)
        if gcd(x,p-1) ==1:
            y = lift(Mod(x,p)^lift(-Mod(x,p-1)^-1))
    sk = x
    pk = (y,p)
    return sk,pk

def sign(m, sk,pk): 
    y,p = pk
    x = sk
    n = p*(p-1)
    k =   2 
    while gcd(k,p-1)!=1:
        k =   (randint(2,(p-1)) )
    h = H(str(m).encode()).digest()
    h = NN(bytes_to_long(h))

    r = lift(Mod(x,p) ^( lift(  (Mod(x,p-1)^-1   * h+k) * Mod(x,p-1)^-k * Mod(k, p-1)^-h  ))*\
        Mod(k,p) ^lift(h*Mod(x,p-1)^-k * Mod(k,p-1)^(-h)))
    s = r* Mod(x,n)^k *Mod(k,n)^h
    sig = (r,s)
    return sig
    
def Verify(m,sig,pk):
    (r,s) = sig
    y,p  =pk
    h = H(str(m).encode()).digest()
    h = NN(bytes_to_long(h))
    a = Mod(y,p)^(r*h) * Mod(r,p)^(s+r)
    b = Mod(s,p)^r 
    return a == b
    

sk,pk = keygen(nbit)
m = b"11341"
sig = sign(m,sk,pk)

print("real",Verify(m,sig,pk))

#generating a fake secret key
(y,p) = pk
fx = crt([1,lift(Mod(y,p)^-1)],[p-1,p])
fx_sig = sign(m,fx,pk)
print("Checking correctness for forged signature")

print("Forget signature: ",Verify(m,sig,pk))

print("Checking correctness for forged secret key")
print(y==(lift(Mod(fx,p)^lift(-Mod(fx,p-1)^-1))))



