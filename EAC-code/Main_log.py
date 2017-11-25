from petlib.ec import *
from petlib.bn import *
from hashlib import sha256
from Commitment import *
from LPoly import*
from PolyCommit import *
from Recursion import *
import os,ast
import subprocess
import gc
import time
#import nump

def dense(d,maxitems):
    return[d[x] for x in xrange(maxitems)]
def bigint(x): 
    return Bn.from_decimal(str(x))

def prover_sat_log(ck,m,n,N,m1,n1,n2,Q,state,W,index,C,usesmallints=1,mu=-1):
    if len(state)!=3*N:
        raise Exception('Input size do no match with number of gates -1')
    if len(W)!=Q:
        raise Exception('Input size do no match with number of gates -2')
    if len(C)!=Q:
        raise Exception('Input size do no match with number of gates -3')
    if m*n<N:
        raise Exception('(m,n) Does not match with N='+str(N))      
    
    if m*n>N:
        #state.resize(m*n,refcheck=False) #yolo
        print 'resizing'
        state+=[0]*(3*(m*n-N))
        N=m*n
    if mu==-1: mu=n/2
    def shortint(x): 
        return long(int(x))

    comcost=[0,0]
    
    commitf=commit
    
    G,key=ck
    p=G.order()
    pp=p
    #ROUND 1: Initial commitments
    Lopen=[state[i*3*n:(i+1)*3*n:3] for i in range(m)] 
    Ropen=[state[i*3*n+1:(i+1)*3*n:3] for i in range(m)] 
    Popen=[state[i*3*n+2:(i+1)*3*n:3] for i in range(m)]
    del state
    

    if usesmallints==0:
        Lopen=[[bigint(x%p) for x in xi] for xi in Lopen] 
        Ropen=[[bigint(x%p) for x in xi] for xi in Ropen]
        Popen=[[bigint(x%p) for x in xi] for xi in Popen]
    else:
        commitf=commit_str

         
    print "Starting Commitments"
    tcom=time.time()
    L=[commitf(ck,v) for v in Lopen]
    Lcomm=[v[0] for v in L]#try *zipped_list
    Lrand=[v[1] for v in L]
    del L

    R=[commitf(ck,v) for v in Ropen]
    Rcomm=[v[0] for v in R]
    Rrand=[v[1] for v in R]
    del R
    
    P=[commitf(ck,v) for v in Popen]
    Pcomm=[v[0] for v in P]
    Prand=[v[1] for v in P]
    del P
    
    Bopen=[p.random() for i in range(n)]
    #Bopen=[bigint(0) for i in range(n)]
    Bcomm,Brand= commitf(ck,Bopen)
    tcom=time.time()-tcom

    print("Commitments done: "+str(tcom)+"s")
    #ROUND 2: define challenge y

    y=p.random()
    
    #ROUND 3: Compute polynomials f,g,h, and commit to h

    
    
    Y=Ve([y.mod_pow(i,p) for i in range(n)])
    #yN=y.mod_pow(N+1,p)          #
    yn=Y[-1]*y%p
    yN=(yn).mod_pow(m,p)*y%p #y^(N+1)
    YN=[yn.mod_pow(i,p) for i in range(m)]
    YInv=[v.mod_inverse(p) for v in YN]
    YInv_n=[v.mod_inverse(p) for v in Y]

   
    if usesmallints==1:
        print "Smallnumming"
        #y,Y,yn,yN,YN,YINV
        p=shortint(p)
        y=shortint(y)
        yn=shortint(yn)
        yN=shortint(yN)

        for i in xrange(len(YN)): YN[i]=shortint(YN[i])
        for i in xrange(len(YInv)): YInv[i]=shortint(YInv[i])
        for i in xrange(len(Y)): Y[i]=shortint(Y[i])
        for i in xrange(len(Rrand)): Rrand[i]=shortint(Rrand[i])
        for i in xrange(len(Lrand)): Lrand[i]=shortint(Lrand[i])
        for i in xrange(len(Prand)): Prand[i]=shortint(Prand[i])
        for i in xrange(len(Bopen)): Bopen[i]=shortint(Bopen[i])

        Brand=shortint(Brand)    
        print "trying small"

    
    null_vec=LPoly([Ve([0 for i in range(n)])],0,p) #null vector

    print "Powers of y Done"
    #    Polynomial f:

    f_L=LPoly([Ve(v) for v in Lopen],1,p)
    f_R=LPoly([Ve(Ropen[i])*YN[i] for i in range(m-1,-1,-1)],-m,p) 
    f_P=LPoly([Ve(v) for v in Popen],m+1,p)
    f_B=LPoly([Ve(Bopen)],2*m+1,p)
    f=f_L + f_R + f_P +  f_B + null_vec #sometimes dot_mul uses 0X^0 if the constant term is missing, null_vec avoids problems
    del f_L,f_R,f_P,f_B,Lopen,Ropen,Popen,Bopen
    z_L=LPoly([v for v in Lrand],1,p)
    z_R=LPoly([Rrand[i]*YN[i] for i in range(m-1,-1,-1)],-m,p) 
    z_P=LPoly([v for v in Prand],m+1,p)
    z_B=LPoly([Brand],2*m+1,p)
    z=z_L+z_R+z_P+z_B
    del z_L,z_R,z_P,z_B,Lrand,Rrand,Prand,Brand
    
    #print 'f=',f.pp()
    
    

    #    Polynomial g:
  
    c=reduce(lambda x,z:(x*y+z)%p,[v*yN for v in C[::-1]])
    del C
    
    print 'c=',c

     

    #		Derive a single constraint out of Q by randomizing with y
    print "starting W"
    tfft=time.time()
    #w_L=reduce((lambda x,z:(x*y+z)%p),(Ve(dense(v,3*N)[::3])*yN%p for v in reversed(W)))

    ynq=[1]*Q
    t=yN
    for i in xrange(Q):
        ynq[i]=t
        t=t*y%p   #in paper, q starts from 1

    w_L=[0]*N
    w_R=[0]*N
    w_P=[0]*N
    #print index[0],index[-1]
    for i in xrange(N):
        ii=3*i
        if i%100000==0 : print i
        #for j in index[ii] : print W[j][ii]!=0
        w_L[i]=sum((W[j])[ii]*ynq[j]%p for j in index[ii])%p
        w_R[i]=sum((W[j])[ii+1]*ynq[j]%p for j in index[ii+1])%p
        w_P[i]=sum((W[j])[ii+2]*ynq[j]%p for j in index[ii+2])%p
    del index
    
    tfft=time.time()-tfft

    print "*Prover W done in ",tfft,' sec'

    #		Parse into m vectors of size n
    ww_L=[w_L[i*n:(i+1)*n:1] for i in range(m)]
    ww_R=[w_R[i*n:(i+1)*n:1] for i in range(m)]
    ww_P=[w_P[i*n:(i+1)*n:1] for i in range(m)]
    del w_L,w_R,w_P
    print "Parsing W done, starting g"

    g_L=LPoly([Ve(v)%p for v in ww_L[::-1]],-m,p)
    g_R=LPoly([Ve(ww_R[i])*YInv[i] for i in range(m)],1,p)
    g_P=LPoly([Ve(ww_P[i])-Y*YN[i] for i in range(m-1,-1,-1)],-2*m,p)
    
    g=g_L+g_R+g_P+null_vec
    #print g
    del ww_L,ww_R,ww_P,g_L,g_R,g_P



    if usesmallints==999:
        print "Smallnumming"
        f,Y,c,g,p
        #shortint=long
        for i in xrange(len(Y)): Y[i]=shortint(Y[i])
        c=shortint(c)
        pp=p
    
        p=shortint(p)
  
    
        f.setmodulus(shortint(f.modulus))
        for i in xrange(len(f)):
            for j in xrange (len(f[i])):
                f[i][j]=shortint(f[i][j])
            
        g.setmodulus(shortint(g.modulus))
        for i in xrange(len(g)):
            for j in xrange (len(g[i])):
                g[i][j]=shortint(g[i][j])
            
        print "trying small"
    
    #deleting stuff
    del YN,YInv
    #gc.collect


    #Output commitments to a file and f,pt,ck,usesmallints into another       
    print "g done, starting h"

    #    Polynomial h:
    print "f,g:",f.ldegree,g.ldegree
    pt=f*Y+2*g
    print "pt:",pt.ldegree
    #print f
    #print pt
    tfft=time.time() 
 
    polyfile= open('polyfile_before.txt', 'w',buffering=4096*1000)
    polyfile.write(str(p)+'\n')
    polyfile.write(str(len(f))+'\n')
    polyfile.write(str(len(pt))+'\n')
    polyfile.write(str(len(f[0]))+'\n')
    vsize=len(f[0])

    for i in xrange(vsize):
        polyfile.write('['+' '.join((str(cf[i]) for cf in f))+']\n')
        polyfile.write('['+' '.join((str(cg[i]) for cg in pt))+']\n')
    polyfile.close()
    tfft=time.time()-tfft

    print '*File out took '+str(tfft)+' seconds.'
    tfft=time.time() 
    deg=pt.ldegree
    del pt
    #gc.collect()
    #subprocess.call('./polyhelper')
    os.system('./polyhelper')    
    tfft=time.time()-tfft
    print '*FFT took '+str(tfft)+' seconds.'

    polyfile= open('polyfile_after.txt', 'r')
    tfft=time.time() 

    hvec=ast.literal_eval(polyfile.read()) #fills hvec
    tfft=time.time()-tfft
    polyfile.close()

    print 'File in out took '+str(tfft)+' seconds.'
    tfft=time.time() 

    hh2=LPoly(hvec,f.ldegree+deg,p)-2*c
    #1:-1 drop [ ] from ntl



    
    #h1= f.fft_mul(pt)-2*c #dot_mul does not reduce after sum
    h=hh2
    tfft=time.time()-tfft
    #print '*sub took '+str(tfft)+' seconds.'
    print "Commiting to h"
    print h.getcoeff(0),h.getcoeff(0)==0
    #print hh2-h%p

    #if usesmallints==1:
    if 1:
        for i in xrange(len(h)): h[i]=Bn.from_decimal(str(h[i]%p))
        #print h
        h.setmodulus(Bn.from_decimal(str(p)))
        p=pp
    #print "sum of coeff 0",sum(h.getcoeff(0))%p

    #	Commit to h
    tfft=time.time() 

    pk,sk=PolyCommit(ck,m1,n1,n2,h,commitf)
    
    print "Message done"
    tfft=time.time()-tfft
    print '*PolyCommit out took '+str(tfft)+' seconds.'


    # Challenge x
    x=pp.random()
    xx=x    
    
    if usesmallints==1:
        x=shortint(x)
    # evaluate commitment to generate first part of the proof
    
    print "Starting PolyEval"
    print type(xx)
    v,pi=PolyEval(ck,sk,xx)
    
    
    f_x=f.eval(x)
    z_x=z.eval(x)
    g_x=g.eval(x)

    #print f_x,v
    #print z_x
    print "PolyEval done"
        
    # call recursive prover to generate proof and append trascript to proof.
    #	compute A,B
    
    key_1=[key[i] for i in xrange(n)]+[key[-1]]
    #print key_1,len(key_1),key[-1]==key_1[-1]
    key_2=[YInv_n[i]*key_1[i] for i in range(n)] +[key[-1]]
    #print key_2,len(key_2),key[-1]==key_2[-1],Y[2]*key_2[2]==key[2]
    ck_1=G,key_1
    ck_2=G,key_2
    c_f1=commitf(ck_1,f_x,0) # the verifier can compute it given z and initial commitments.
    #print c_f1
    c_f2=c_f1+commitf(ck_2,2*g_x,0) # the verifier can compute it given z and initial commitments.
    #print c_f2

    pub_key=G,key_1,key_2
    #print '---',f_x*2,'---',f_x,'---',(f_x*Y+2*g_x)%p
    proof,comcost=recursive_prover(pub_key,c_f1,f_x,       0,c_f2 ,f_x*Y+2*g_x,0, v-2*c,N,mu,[],usesmallints)
          #recursive_prover(public_key,A,Aopen ,Arand,B,Bopen,Brand      ,z,    N,mu=0,T=[],usesmallints=0)

    comcost[0]+=3*len(Lcomm)+1+(m1+1)
    
    comcost[1]+=2 +n1+n2+2
    #print '*** Comcost (log):',comcost
    return (Lcomm,Rcomm,Pcomm,Bcomm,y,pk,x,v,pi,z_x,proof),comcost


def verifier_sat_log(ck,m,n,N,m1,n1,n2,Q,W,index,C,Trans,usesmallints=0):
    G,key=ck
    p=G.order()
    Lcomm,Rcomm,Pcomm,Bcomm,y,pk,x,V,pi,z_x,proof=Trans
    commitf=commit

    def shortint(x): 
        return long(int(x))


    if usesmallints==1:
        y=Bn.from_decimal(str(y))
        xs=x
        xx=Bn.from_decimal(str(x))
        commitf=commit_str
    else:
        commitf=commit
        xx=x
        xs=x
    if m*n>N:
        #print 'N'
        #state.resize(m*n,refcheck=False) #yolo
        N=m*n    


    if not PolyVerify(ck,pk,m1,n1,n2,xx,V,pi,commitf): return False
    
    #A,A_open,A_rand,B,B_open,B_rand,z,T = proof

    Y=Ve([y.mod_pow(i,p) for i in range(n)])
    #yN=y.mod_pow(N+1,p)          
    yn=Y[-1]*y%p
    yN=(yn).mod_pow(m,p)*y%p #y^(N+1)
    YN=[yn.mod_pow(i,p) for i in range(m)]
    YInv=[v.mod_inverse(p) for v in YN]
    YInv_n=[v.mod_inverse(p) for v in Y]
    if usesmallints==1:
        #print "Smallnumming"
        #y,Y,yn,yN,YN,YINV
        pp=p
        p=shortint(p)
        y=shortint(y)
        yn=shortint(yn)
        yN=shortint(yN)
        YNN=[i for i in YN] #backup
        for i in xrange(len(YN)): YN[i]=shortint(YN[i])
        for i in xrange(len(YInv)): YInv[i]=shortint(YInv[i])
        for i in xrange(len(Y)): Y[i]=shortint(Y[i])
        
        #print "trying small"
    else:
        YNN=YN  #ref copy
    
    null_vec=LPoly([Ve([0 for i in range(n)])],0,p) #null vector 
    #    Polynomial g:
  
    c=reduce(lambda x,z:(x*y+z)%p,[v*yN for v in C[::-1]])
    ynq=[1]*Q
    t=yN
    for i in xrange(Q):
        ynq[i]=t
        t=t*y%p   #in paper, q starts from 1

    w_L=[0]*N
    w_R=[0]*N
    w_P=[0]*N

    for i in xrange(N):
        ii=3*i
        if i%50000==0 : print i
        #for j in index[ii] : print W[j][ii]!=0
        w_L[i]=sum((W[j])[ii]*ynq[j] for j in index[ii])%p
        w_R[i]=sum((W[j])[ii+1]*ynq[j] for j in index[ii+1])%p
        w_P[i]=sum((W[j])[ii+2]*ynq[j] for j in index[ii+2])%p
        

    
    ww_L=[w_L[i*n:(i+1)*n:1] for i in range(m)]
    ww_R=[w_R[i*n:(i+1)*n:1] for i in range(m)]
    ww_P=[w_P[i*n:(i+1)*n:1] for i in range(m)]
    
    g_L=LPoly([Ve(v)%p for v in ww_L[::-1]],-m,p)
    g_R=LPoly([Ve(ww_R[i])*YInv[i] for i in range(m)],1,p)
    g_P=LPoly([Ve(ww_P[i])-Y*YN[i] for i in range(m-1,-1,-1)],-2*m,p)
    
    g=(g_L+g_R+g_P)
    
    g_x=g.eval(xs)
    
    if usesmallints: p=pp
    
    xinv=xx.mod_inverse(p)
    #print x,xinv
    X=[xx.mod_pow(i+1,p) for i in range(m)]
    XInv=[xinv.mod_pow(i+1,p)*YNN[i]%p for i in range(m)]#XInv=[X[i].mod_inverse(p)*YN[i]%p for i in range(m)]
    #Xm=[x.mod_pow(i+1+m,p) for i in range(m)]
    Xm=[X[i]*X[-1]%p for i in range(m)]
    
    xm=Xm[-1]*xx%p#xm=x.mod_pow(2*m+1,p)#xm=Xm[-1]*x%p
    D=reduce(lambda a,b:a+b,[X[i]*Lcomm[i]+XInv[i]*Rcomm[i]+Xm[i]*Pcomm[i] for i in range(m)])    
    BB=xm*Bcomm
    
    #compute c_f1,c_f2 and abort if different form the proof
      
    key_1=[key[i] for i in range(n)]+[key[-1]]
    key_2=[YInv_n[i]*key_1[i] for i in range(n)] +[key[-1]]
    
    ck_1=G,key_1
    ck_2=G,key_2
    c_f1=D+BB+commitf(ck_1,[0],-z_x) # the verifier can compute it given z and initial commitments.
    #print c_f1
    c_f2=c_f1+commitf(ck_2,2*g_x,0) # the verifier can compute it given z and initial commitments.
   

    pub_key=G,key_1,key_2
    print 'Ok so far...'
    return recursive_verifier(pub_key,c_f1,c_f2,V,proof)













