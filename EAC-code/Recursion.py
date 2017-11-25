from petlib.ec import *
from petlib.bn import *
from hashlib import sha256
from Commitment import *
from LPoly import*
import numpy as np
import math

def bigint(x): 
    return Bn.from_decimal(str(x))
def parse_vector(V,m,zero=0):
    V+=[zero]*(-len(V)%m)
    V_parsed=[[V[i+k*(m)]for i in xrange(m)]for k in xrange(len(V)/m)]
    return V_parsed  

  
def weighted_sum(L,Z,x):
    #Weighted sum of vectors in L by x^i (i=[1..]) , where Z is the neutral element of the relevant group.
    X=Ve([x]*len(L[0]))
    V=Ve([Z]*len(L[0]))
    for i in reversed(range(len(L))):
        V=X*V+ L[i]  
    return X*V
def summ(a,b):
    return a+b


def recursive_prover(public_key,A,Aopen,Arand,B,Bopen,Brand,z,N,mu=0,T=[],usesmallints=0,comcost=[0,0]):
    
    G,ck_A,ck_B=public_key
    pk_A=G,ck_A
    pk_B=G,ck_B
    
    p=G.order()
    '''
    if len(ck_A)!=len(ck_B): raise Exception('commitment keys must have same length') 
    if usesmallints:
        if not check_open_commit_str(pk_A,A,Aopen,Arand):raise Exception('invalid witness')
        if not check_open_commit_str(pk_B,B,Bopen,Brand):raise Exception('invalid witness')
        for i in xrange(len(Aopen)): Aopen[i]=bigint(Aopen[i])
        for i in xrange(len(Bopen)): Bopen[i]=bigint(Bopen[i])
        if bigint(z)%p!=dotprod(Aopen,Bopen)%p: raise Exception('invalid witness')
    else:
        if not check_open_commit(pk_A,A,Aopen,Arand):raise Exception('invalid witness')
        if not check_open_commit(pk_B,B,Bopen,Brand):raise Exception('invalid witness')
        if z%p!=dotprod(Aopen,Bopen)%p: raise Exception('invalid witness')
    '''
    if usesmallints:
        for i in xrange(len(Aopen)): Aopen[i]=bigint(Aopen[i])
        for i in xrange(len(Bopen)): Bopen[i]=bigint(Bopen[i])
    #final step
    if mu==0:
	comcost[1]+=2*(len(Aopen)+1)
	#print '*** Comcost (log):',comcost
        return (A,Aopen,Arand,B,Bopen,Brand, z,T),comcost
    
    #recursion
    print 'Enter the recursion!'
    
    n=len(ck_A)-1
    m=n/mu #mu is the lenght of the new vectors, m is the number of new vectors
    #print n,m


    #Parse vectors into vectors of smaller size

    ck_A_vec=parse_vector(list(ck_A[:-1]),mu,G.infinite())
    ck_B_vec=parse_vector(list(ck_B[:-1]),mu,G.infinite())
    Aopen_vec=parse_vector(Aopen,mu)
    Bopen_vec=parse_vector(Bopen,mu)
    #print type(ck_A_vec[0])
    
    #first message
      
    #print 'start first message'
    #A_K=[reduce(summ,[dotprod(Aopen_vec[i+k],ck_A_vec[i]) for i in xrange(max(0,-k),min(m,m-k))]) for k in xrange(1-m,m)]
    #B_K=[reduce(summ,[dotprod(Bopen_vec[i+k],ck_B_vec[i]) for i in xrange(max(0,-k),min(m,m-k))])for k in xrange(1-m,m)

    A_K=[mult_prod(G,reduce( summ, (ck_A_vec[i] for i in xrange(max(0,-k),min(m,m-k)))),reduce(summ, [Aopen_vec[i+k] for i in xrange(max(0,-k),min(m,m-k))])) for k in xrange(1-m,m)]
    #print 'A_k computed'
    
    B_K=[mult_prod(G,reduce( summ, (ck_B_vec[i] for i in xrange(max(0,-k),min(m,m-k)))),reduce(summ, [Bopen_vec[i+k] for i in xrange(max(0,-k),min(m,m-k))])) for k in xrange(1-m,m)]
    z_K=[sum([dotprod(Aopen_vec[i],Bopen_vec[i+k]) for i in xrange(max(0,-k),min(m,m-k))])%p for k in xrange(1-m,m)]
    
    #print 'message computed'
    
    #Challenge
    
    state=[A_K[:m-1]+A_K[m:],B_K[:m-1]+B_K[m:],z_K[:m-1]+z_K[m:]]

    comcost[0]+=len(state[0])
    comcost[0]+=len(state[1])
    comcost[1]+=len(state[2])


    challenge=G.order().random() #to do: hash of the current state
    Challenge=[challenge.mod_pow(i,p) for i in xrange(1,m+1)]
    Challenge_inv=[ch.mod_inverse(p) for ch in Challenge]
    #challenge_inv=challenge.mod_inverse(G.order())
    T+=[state+[challenge]] 
    
    #New statement
    
    
    #sprint 'start new key'
    #ck_A_new= weighted_sum(ck_A_vec,G.infinite(),challenge_inv) 
    #ck_B_new= weighted_sum(ck_B_vec,G.infinite(),challenge)
    
    ck_A_new=[mult_prod(G,[ck_A_vec[i][j] for i in xrange(m)],Challenge_inv) for j in xrange(mu)]
    ck_B_new=[mult_prod(G,[ck_B_vec[i][j] for i in xrange(m)],Challenge) for j in xrange(mu)]

    
    
    #challenge_vector2=Ve([Challenge_inv[0].mod_pow(i,p) for i in xrange(1-m,0) ]+[challenge.mod_pow(i,p) for i in xrange(0,m) ])
    
   
    #print 'start new statement'
    #A_new=reduce(summ,challenge_vector2*A_K)
    #B_new=reduce(summ,Ve(reversed(challenge_vector))*B_K)
    #z_new=reduce(summ,Ve(reversed(challenge_vector))*z_K)%p
    challenge_vector=list(reversed(Challenge[:-1]))+ [Bn(1)]+Challenge_inv[:-1]
    #print 'boom?'
    #print len(A_K)
    #print len(B_K)
    #print len(challenge_vector)
    lt=list(reversed(challenge_vector))
    #print 'here?'
    #print A_K
    #print lt
    #print n,mu,m
    A_new=mult_prod(G,A_K,lt)    
    #print 'bang?'

    B_new=mult_prod(G,B_K,challenge_vector)
    #print 'splat?'

    z_new=reduce(summ,[v*w%p for v,w in zip(challenge_vector,z_K)])%p  
    
    #print 'start new witness'
    #new witness
    #Aopen_new=weighted_sum(Aopen_vec,0,challenge)
    #Bopen_new=weighted_sum(Bopen_vec,0,Challenge_inv[0])

    Aopen_new=[reduce(summ,[v*w%p for v,w in zip(t,Challenge)])%p for t in zip(*Aopen_vec)]
    Bopen_new=[reduce(summ,[v*w%p for v,w in zip(t,Challenge_inv)])%p for t in zip(*Bopen_vec)]
    


    #Recursive call
    #if mu<=int(math.log(N,2)): mu=0
    if mu<=2: mu=0
    else: mu=mu/2

    ck_A_new.append(ck_A[-1])
    ck_B_new.append(ck_B[-1])
    pk=G,ck_A_new,ck_B_new
    
    return recursive_prover(pk,A_new,Aopen_new,0,B_new,Bopen_new,0,z_new,N,mu,T,comcost)
      
    

def recursive_verifier(public_key,A_state,B_state,z_state,proof):
    #summ=lambda x,y:x+y
    print 'rec ver '
    G,ck_A,ck_B=public_key
    p=G.order()
    A,A_open,A_rand,B,B_open,B_rand,z,T = proof
    
    if T==[]:
        print 'rec ver bottomed out'

        pk_A=G,ck_A
        pk_B=G,ck_B
        print check_open_commit_str(pk_A,A,A_open,A_rand) #:return False
        print 'A ok'
        if not check_open_commit_str(pk_B,B,B_open,B_rand):return False
        print 'B ok'
        if z%p!=dotprod(A_open,B_open)%p: return False
        print 'prod ok'
        return True
    
    A_K,B_K,z_K,challenge=T[0]
    m=(len(A_K)+2)/2 # to be changed with input param
    n=len(ck_A)-1
    mu=n/m 
    
    A_K.insert(m-1,A_state)
    B_K.insert(m-1,B_state)
    z_K.insert(m-1,z_state)

    Challenge=[challenge.mod_pow(i,p) for i in xrange(1,m+1)]
    Challenge_inv=[ch.mod_inverse(p) for ch in Challenge]    
    #if A_state==A_K[m-1]: print 'errorA'
    #if B_state==B_K[m-1]: print 'errorB'
    #parse current key
    ck_A_vec=parse_vector(list(ck_A[:-1]),mu,G.infinite())
    ck_B_vec=parse_vector(list(ck_B[:-1]),mu,G.infinite())
    #derive new key
    ck_A_new=[mult_prod(G,[ck_A_vec[i][j] for i in xrange(m)],Challenge_inv) for j in xrange(mu)]
    ck_B_new=[mult_prod(G,[ck_B_vec[i][j] for i in xrange(m)],Challenge) for j in xrange(mu)]

    #ck_A_new=weighted_sum(ck_A_vec,G.infinite(),challenge_inv) 
    #ck_B_new=weighted_sum(ck_B_vec,G.infinite(),challenge)
    ck_A_new+=[ck_A[-1]]
    ck_B_new+=[ck_B[-1]]    
    #new statement:
    
    challenge_vector=list(reversed(Challenge[:-1]))+ [Bn(1)]+Challenge_inv[:-1]
    A_new=mult_prod(G,A_K,list(reversed(challenge_vector)))
    B_new=mult_prod(G,B_K,challenge_vector)
  
    z_new=reduce(summ,[v*w%p for v,w in zip(challenge_vector,z_K)])%p


    #challenge_vector=Ve([Challenge_inv[0].mod_pow(i,p) for i in xrange(1-m,0) ]+[challenge.mod_pow(i,p) for i in xrange(0,m) ])
    #A_new=reduce(summ,challenge_vector*A_K)
    #B_new=reduce(summ,Ve(reversed(challenge_vector))*B_K)
    #z_new=reduce(summ,Ve(reversed(challenge_vector))*z_K)%p 

    public_key=G,ck_A_new,ck_B_new
    #remove first element from T
    del T[0]
    proof=A,A_open,A_rand,B,B_open,B_rand,z,T


    return recursive_verifier(public_key,A_new,B_new,z_new,proof)
    
    
    '''while T!=[]:
        
        A_K,B_K,Z_K,challenge=T[0]
        m=(len(A_K)+1)/2
        n=len(ck_A)-1
        mu=n/m
        
        challenge_inv=challenge.mod_inverse(G.order())
        print 'test',A_state==A_K[m-1]
        
        #parse current key
        ck_A_vec=parse_vector(list(ck_A[:-1]),mu)
        ck_B_vec=parse_vector(list(ck_B[:-1]),mu)
        #derive new key
        ck_A_new= weighted_sum(ck_A_vec,G.infinite(),challenge_inv) 
        ck_B_new= weighted_sum(ck_B_vec,G.infinite(),challenge)
        ck_A_new.append(ck_A[-1])
        ck_B_new.append(ck_B[-1])
        ck_A=ck_A_new
        ck_B=ck_B_new
        #remove first element from T
        del T[0]'''
    
   

def recursive_verifier2(public_key,A_state,B_state,z_state,proof,aexp=-1,bexp=-1,mcom=-1):
    #summ=lambda x,y:x+y
    print 'rec ver 2'
    G,ck_A,ck_B=public_key
    p=G.order()
    A,A_open,A_rand,B,B_open,B_rand,z,T = proof
    if aexp==-1:
        print 'rec init'
        aexp=[1]*(len(ck_A)-1)
        bexp=[1]*(len(ck_B)-1)
        mcom=1
        
    
    if T==[]:
        print 'rec ver 2bottomed out'

        pk_A=G,ck_A
        pk_B=G,ck_B
        
        
        for j in xrange(mcom):
            for i in xrange(len(A_open)):
                aexp[i*mcom+j]*=A_open[i]
                bexp[i*mcom+j]*=B_open[i]

        print check_open_commit_str(pk_A,A,aexp[:mcom*len(A_open)],A_rand) #:return False
        print 'A ok'
        if not check_open_commit_str(pk_B,B,bexp[:mcom*len(B_open)],B_rand):return False
        print 'B ok'
        if z%p!=dotprod(A_open,B_open)%p: return False
        print 'prod ok'
        return True
    
    A_K,B_K,z_K,challenge=T[0]
    m=(len(A_K)+2)/2 # to be changed with input param
    n=(len(ck_A)-1)/mcom
    mu=n/m 
    
    A_K.insert(m-1,A_state)
    B_K.insert(m-1,B_state)
    z_K.insert(m-1,z_state)

    Challenge=[challenge.mod_pow(i,p) for i in xrange(1,m+1)]
    Challenge_inv=[ch.mod_inverse(p) for ch in Challenge]    
    #if A_state==A_K[m-1]: print 'errorA'
    #if B_state==B_K[m-1]: print 'errorB'
    #parse current key
    
    ####ck_A_vec=parse_vector(list(ck_A[:-1]),mu,G.infinite())
    #####ck_B_vec=parse_vector(list(ck_B[:-1]),mu,G.infinite())
    
    #derive new key

    print 'm=',m,len(aexp),n,mu
    print mcom
    print m*mu

    for j in xrange(mu*mcom):
        for i in xrange(m):
            #print '*',i*mu*mcom+j
            aexp[i*mu*mcom+j]*=Challenge_inv[i]
            bexp[i*mu*mcom+j]*=Challenge[i]
    ####ck_A_new=[mult_prod(G,[ck_A_vec[i][j] for i in xrange(m)],Challenge_inv) for j in xrange(mu)]
    ####ck_B_new=[mult_prod(G,[ck_B_vec[i][j] for i in xrange(m)],Challenge) for j in xrange(mu)]
    mcom*=m

    #ck_A_new+=[ck_A[-1]]
    #ck_B_new+=[ck_B[-1]] 
       
    #new statement:
    
    challenge_vector=list(reversed(Challenge[:-1]))+ [Bn(1)]+Challenge_inv[:-1]
    A_new=mult_prod(G,A_K,list(reversed(challenge_vector)))
    B_new=mult_prod(G,B_K,challenge_vector)
  
    z_new=reduce(summ,[v*w%p for v,w in zip(challenge_vector,z_K)])%p



    #public_key=G,ck_A_new,ck_B_new
    #remove first element from T
    del T[0]
    proof=A,A_open,A_rand,B,B_open,B_rand,z,T


    return recursive_verifier(public_key,A_new,B_new,z_new,proof,aexp,bexp,mcom)
