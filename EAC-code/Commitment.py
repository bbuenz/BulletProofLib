from petlib.ec import EcGroup,EcPt
from petlib.ec import _FFI,_C
from petlib.bn import Bn
from hashlib import sha256
#from memory_profiler import profile

def commitment_key_gen(n, trap=None,nid=714):  #713 std, 415/714
    '''Generates a key for a pedersen-like multicommitment. 
    It outputs a ECgroup specified by nid and n points on the curve. 
    If Trap is set the discrete log of all the points is also returned.'''
    G = EcGroup(nid)
    commitment_key=[]
    trapdoor=[]        
    for i in xrange(n+1):
        #priv = G.order().random()
        #pub = priv * G.generator()
        #commitment_key+=[pub]
        #trapdoor+=[priv]
        trapdoor+=[G.order().random()]
        commitment_key+=[trapdoor[-1]*G.generator()]
    if trap!=None:
        return (G,commitment_key,tuple(trapdoor))
    return (G,commitment_key)

def mult_prod(G,key,elements):
    #G,key=ck
    
    bvec=_FFI.new("EC_POINT * []",len(elements))
    for i in xrange(len(elements)): bvec[i]=key[i].pt
    evec=_FFI.new("BIGNUM * []",len(elements))
    for i in xrange(len(elements)):
        try:
            evec[i]=elements[i].bn
        except AttributeError:
            #does this even work properly?
            evec[i]=Bn(elements[i]).bn
        
    
    comm = EcPt(G)
    _C.EC_POINTs_mul(G.ecg, comm.pt, _FFI.NULL,len(elements), bvec, evec, _FFI.NULL)
    return comm

def mult_prod_str(G,key,elements):#not actually used in commit_str, but could be potentially useful. Be careful that it was potentially causing segmentation fault.
    #G,key=ck
    bvec=_FFI.new("EC_POINT * []",len(elements))
    for i in xrange(len(elements)): bvec[i]=key[i].pt
    evec=_FFI.new("BIGNUM * []",len(elements))
    for i in xrange(len(elements)): evec[i]=Bn.from_decimal(str(elements[i])).bn
    comm = EcPt(G)
    _C.EC_POINTs_mul(G.ecg, comm.pt, _FFI.NULL,len(elements), bvec, evec, _FFI.NULL)

     
    return comm

def commit(ck,elements, rand=None):
    '''Computes vector commitment to elements using ck
     (and optionally using a given randomness). 
     Outputs a point on the curve and the randomness used (if not given as input)'''
    G,key=ck
    
    if len(elements)>=len(key):
        raise Exception('Too many elements!Longer key required')
    #term=(elements[i]*key[i] for i in xrange(len(elements)))
    #term=[elements[i]*key[i] for i in xrange(len(elements))]

    #bvec=_FFI.new("EC_POINT * []",len(elements))
    #for i in xrange(len(elements)): bvec[i]=key[i].pt
    #evec=_FFI.new("BIGNUM * []",len(elements))
    #for i in xrange(len(elements)):
    #    try:
    #        evec[i]=elements[i].bn
    #    except AttributeError:
     #       evec[i]=Bn(elements[i]).bn
        
    
    #comm = EcPt(G)
    #_C.EC_POINTs_mul(G.ecg, comm.pt, _FFI.NULL,len(elements), bvec, evec, _FFI.NULL)
    #comm=mult_prod(ck,elements)
    #comm=reduce(lambda x, y : x + y,term) #apparently Reduce is more efficient than For loop
    if rand==None:
        rand=G.order().random()
        #print elements
        
        #print elements
        #random_point=rand*key[-1]
        #comm=comm+random_point
        elements=list(elements)+[rand]
        comm=mult_prod(G,key[:len(elements)-1]+[key[-1]],elements)
        return comm,rand
    #random_point=rand*key[-1]
    #comm=comm+random_point
    #print elements
    elements=list(elements)+[rand]
    #print elements
    comm=mult_prod(G,key[:len(elements)-1]+[key[-1]],elements)
    return comm 

def commit_str(ck,elements_str, rand=None):
    '''Computes vector commitment to elements using ck
     (and optionally using a given randomness). 
     Outputs a point on the curve and the randomness used (if not given as input)'''
    G,key=ck
    #print 'test', len(key),len(elements)
    if len(elements_str)>=len(key):
        raise Exception('Too many elements!Longer key required')
    #term=(Bn.from_decimal(str(elements[i]))*key[i] for i in xrange(len(elements)))
    
    
    #bvec=_FFI.new("EC_POINT * []",len(elements))
    #for i in xrange(len(elements)): bvec[i]=key[i].pt
    #evec=_FFI.new("BIGNUM * []",len(elements))
    #for i in xrange(len(elements)): evec[i]=Bn.from_decimal(str(elements[i])).bn
    
    #comm = EcPt(G)
    #_C.EC_POINTs_mul(G.ecg, comm.pt, _FFI.NULL,len(elements), bvec, evec, _FFI.NULL)

    
    
    
    
    #comm=reduce(lambda x, y : x + y,term)
    #comm=mult_prod_str(ck,elements)
    if rand==None:
        rand=G.order().random()
        #random_point=rand*key[-1]
        #comm=comm+random_point
        #elements_str=list(elements_str)+[rand]
        elements=[Bn.from_decimal(str(int(x))) for x in elements_str]+[Bn.from_decimal(str(rand))]
        comm=mult_prod(G,key[:len(elements)-1]+[key[-1]],elements)
        return comm,long(rand)
        
    #random_point=Bn.from_decimal(str(rand))*key[-1]
    #comm=comm+random_point
    #elements_str=list(elements_str)+[rand]
    elements=[Bn.from_decimal(str(x)) for x in elements_str]+[Bn.from_decimal(str(rand))]
    comm=mult_prod(G,key[:len(elements)-1]+[key[-1]],elements)
    return comm 

def check_open_commit(ck,comm,elements,rand):
    #Verifies that (element,rand) is an opening to comm
    #G,key=ck
    commitment=commit(ck,elements,rand)
    return comm==commitment

def check_open_commit_str(ck,comm,elements,rand):
    #Verifies that (element,rand) is an opening to comm
    #G,key=ck
    commitment=commit_str(ck,elements,rand)
    return comm==commitment

def challenge(elements):
    """Packages a challenge in a bijective way"""
    elem = [len(elements)] + elements
    elem_str = map(str, elem)
    elem_len = map(lambda x: "%s||%s" % (len(x) , x), elem_str)
    state = "|".join(elem_len)
    H = sha256()
    H.update(state.encode("utf8"))
    return H.digest()


def pok_open_comm_prove(public_key,A,opening,rand):
    #ZKProof of knowledge of opening (opening,rand) to a commitment A 
    G,commitment_key=public_key
    assert check_open_commit(public_key,A,opening,rand)
    p = G.order()
    blinder =[p.random() for i in xrange(len(opening))]
    B,B_rand=commit(public_key,blinder)
    state = ['Opening', G.nid(),list(commitment_key),A, B]#add a optional message
    hash_x = challenge(state)
    x = Bn.from_binary(hash_x) % p
    f = [(blinder[i] - x*opening[i]) % p for i in xrange(len(opening)) ]
    z = B_rand - x*rand % p
    return (x, f, z)
    
 
def pok_open_comm_verify(public_key, A, proof):
    #Verifies the ZKproof of knowledge of opening to a commitment A
    G,commitment_key=public_key
    x,f,z = proof
    C=commit(public_key,f,z)+x*A
    p = G.order()
    state = ['Opening', G.nid(),list(commitment_key),A, C]
    hash_x = challenge(state)
    y = Bn.from_binary(hash_x) % p
    return x == y

