# SekaiCTF24

### Some Trick

```
import random
from secrets import randbelow, randbits
from flag import FLAG

CIPHER_SUITE = randbelow(2**256)
print(f"oPUN_SASS_SASS_l version 4.0.{CIPHER_SUITE}")
random.seed(CIPHER_SUITE)

GSIZE = 8209
GNUM = 79

LIM = GSIZE**GNUM


def gen(n):
    p, i = [0] * n, 0
    for j in random.sample(range(1, n), n - 1):
        p[i], i = j, j
    return tuple(p)


def gexp(g, e):
    res = tuple(g)
    while e:
        if e & 1:
            res = tuple(res[i] for i in g)
        e >>= 1
        g = tuple(g[i] for i in g)
    return res


def enc(k, m, G):
    if not G:
        return m
    mod = len(G[0])
    return gexp(G[0], k % mod)[m % mod] + enc(k // mod, m // mod, G[1:]) * mod


def inverse(perm):
    res = list(perm)
    for i, v in enumerate(perm):
        res[v] = i
    return res


G = [gen(GSIZE) for i in range(GNUM)]


FLAG = int.from_bytes(FLAG, 'big')
left_pad = randbits(randbelow(LIM.bit_length() - FLAG.bit_length()))
FLAG = (FLAG << left_pad.bit_length()) + left_pad
FLAG = (randbits(randbelow(LIM.bit_length() - FLAG.bit_length()))
        << FLAG.bit_length()) + FLAG

bob_key = randbelow(LIM)
bob_encr = enc(FLAG, bob_key, G)
print("bob says", bob_encr)
alice_key = randbelow(LIM)
alice_encr = enc(bob_encr, alice_key, G)
print("alice says", alice_encr)
bob_decr = enc(alice_encr, bob_key, [inverse(i) for i in G])
print("bob says", bob_decr)
```      

The flag exists both on the left and the right.      
3 cipher texts are generated which are bob_encr ,alice_encr and bob decr     
These are encrypted using the enc function, which is a recursive function. The base case of this function returns nothing.     
`return gexp(G[0], k % mod)[m % mod] + enc(k // mod, m // mod, G[1:]) * mod` 
This is the recursive condition for the enc function.

The gexp function shuffles the input we give and returns it back to us         
The gen function is a shuffling function for numbers from 1 to n-1     
`bob_encr = enc(FLAG, bob_key, G)` 
This then returns something in the format `((((((x*8209)+y)*8209)+y)*8209)+y)……….)*8209+y`     
The value of G can be received each time as it is decreasing on each instance. We can reverse it and get the key  
```
def key_mod_8029(res):
    s=[]
    while (res):
        s.append(res%8209)
        res//=8209
    return s
```
 The reverse for the enc function   
```
def dec(k, res, G):
    if not G:
        return [0]
    mod = len(G[0])
    return dec(k // mod, res[1:], G[1:])+[gexp(G[0], k % mod).index(res[0])]
```
```
def key_replay(res):
    a=0
    for i in res:
        a=a*8209+i
    return a
```
We can then find alice_key , and  then the bob_key.    
So we have both the keys used and we use bob_decr to get plaintext   
```
def dec1(res,key,G):
    a=[]
    if not G:
        return [0]
    for i in range(8209):
        if gexp(G[0],i)[key%8209]==res[0]:
            print(i)
            a.append(i)
    return dec1(res[1:],key//8209 ,G[1:])
```
We should then reverse the array back.   
We need to find the flag using brutforcing  

The final solve is:
```
import random
from secrets import randbelow, randbits
from Cryptodome.Util.number import *

CIPHER_SUITE =5856735718192672966225212630546045665679020834917236661169743409360745081692
b1 =934535015385784972098018441829301227888268300482554572889937663972835689477317906590269550483816058279675056740632836110427165342116825918458562882459952965524045087097428340305468008069307089535207656651490741013829130388943184449967876591696491662942908809195857190028729699667883172408778919813286215678587

a1 =1200023343219513263382590595000530709398044680494887232151068706332454900457993992785528158990834544878450058108341045830600802696148032561205251770283666006973167393948548197072049425715808993347674584378538883200268601390915839644385525216204736891481357328537881870321049952052453132654798693784947466776387

b2 =1272441200473454987001701625665347128998267676768270586334850447786321082063417203439895347670890554611411858488237562330644466912578982684875984076535384996939506416271097344882332314135242565253987938022938597663163369675849841691494448925864719322424546037485802787986584090093449519504693373904532207187504

'''
bob says 934535015385784972098018441829301227888268300482554572889937663972835689477317906590269550483816058279675056740632836110427165342116825918458562882459952965524045087097428340305468008069307089535207656651490741013829130388943184449967876591696491662942908809195857190028729699667883172408778919813286215678587
alice says 1200023343219513263382590595000530709398044680494887232151068706332454900457993992785528158990834544878450058108341045830600802696148032561205251770283666006973167393948548197072049425715808993347674584378538883200268601390915839644385525216204736891481357328537881870321049952052453132654798693784947466776387
bob says 1272441200473454987001701625665347128998267676768270586334850447786321082063417203439895347670890554611411858488237562330644466912578982684875984076535384996939506416271097344882332314135242565253987938022938597663163369675849841691494448925864719322424546037485802787986584090093449519504693373904532207187504
'''
random.seed(CIPHER_SUITE)
GSIZE = 8209
GNUM = 79
LIM = GSIZE ** GNUM


def gen(n):
    p, i = [0] * n, 0
    for j in random.sample(range(1, n), n - 1):
        p[i], i = j, j
    return tuple(p)


def gexp(g, e):
    res = tuple(g)
    while e:
        if e & 1:
            res = tuple(res[i] for i in g)
        e >>= 1
        g = tuple(g[i] for i in g)
    return res


def dec(k, res, G):
    if not G:
        return [0]
    mod = len(G[0])
    return dec(k // mod, res[1:], G[1:])+[gexp(G[0], k % mod).index(res[0])]


def inverse(perm):
    res = list(perm)
    for i, v in enumerate(perm):
        res[v] = i
    return res


G = [gen(GSIZE) for i in range(GNUM)]


def key_mod_8029(res):
    a=[]
    while (res):
        a.append(res%8209)
        res//=8209
    return a


def key_replay(res):
    a=0
    for i in res:
        a=a*8209+i
    return a

def dec1(res,key,G):
    a=[]
    if not G:
        return [0]
    for i in range(8209):
        if gexp(G[0],i)[key%8209]==res[0]:
            print(i)
            a.append(i)
    return dec1(res[1:],key//8209 ,G[1:])

res = key_mod_8029(a1)
alice_key = key_replay(dec(b1, res, G))
res = key_mod_8029(b2)
bob_key = key_replay(dec(a1, res, [inverse(i) for i in G]))
res = key_mod_8029(b1)
dec1(res, bob_key, G)
a=(1936, 714, 7902, 2862, 958, 7, 4555, 5113, 5926, 3030, 2805, 6103, 3321, 7057, 2739, 2296, 6778, 5992, 2412, 5540, 7484, 5352, 6431, 2590, 6637, 4527, 4162, 5863, 1497, 2802, 4281, 4730, 7675, 1481, 6999, 6708, 1748, 3712, 126, 8111, 8071, 3535, 6725, 6717, 2231, 3087, 6844, 2080, 7716, 3681, 5834, 5903, 5666, 7767, 1112, 4696, 4728, 4675, 4655, 3456, 5558, 3019, 908, 7959, 5845, 2384, 4362, 2173, 5657, 604, 7247, 6713, 307, 5, 0, 0, 0, 0, 0)
FLAG = key_replay(reversed(a))
print(FLAG)
print(long_to_bytes(FLAG))
for i in range(20):
    print(long_to_bytes(FLAG>>i))
```

`Flag - SEKAI{7c124c1b2aebfd9e439ca1c742d26b9577924b5a1823378028c3ed59d7ad92d1}`
