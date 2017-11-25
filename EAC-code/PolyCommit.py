from LPoly import *
from LPoly import _invert
import petlib
import Commitment
from petlib.ec import EcGroup
from petlib.bn import Bn
from Commitment import commitment_key_gen
import operator
import math
def PolyCommit(ck,m,n1,n2,h,commitfunction=Commitment.commit):
    '''
    Beware: currently the table is pos|neg rather than neg|pos 
    as in the paper. Operations and coeffs are adjusted to match
    but care should be taken.
    '''
    G,key=ck
    g=G.generator()
    p=G.order()
    #print h.getcoeff(0),(h.getcoeff(0)%p)
    assert h.getcoeff(0)==0

    
    #blinders
    b=[p.random() for i in xrange(1,n1)]    
    bneg=[p.random() for i in xrange(1,n2)]
    bb=p.random()
    bbneg=p.random()
    
    #rands
    r=[p.random() for i in xrange(0,m+1)]
    rr=p.random()
    rrneg=p.random()
    
    #ezmode
    #b=[0]*(n1-1)
    #bneg=[0]*(n2-1)
    #bb=0
    #bbneg=5
    #r=[0]*(m+1)
    #rr=0
    #rrneg=0
    
    
    h=h+LPoly([0],mod=p) #force 0 to actually be present
    #print h.pp()
    maxdeg=h.ldegree+len(h)
    mindeg=h.ldegree
    
    assert mindeg <= 0
    assert maxdeg >=0
    
    
    hneg=h[:max(0,-mindeg)]
    hneg.reverse()  #yes, but re-reverse later
    hpos=h[max(0,-mindeg+1):]
    
    assert len(hpos)<=n1*m+1
    assert len(hneg)<=n2*m+1
    
    hpos+=[0]*(n1*m+1-len(hpos)) #list operations, not polynomial
    hneg+=[0]*(n2*m+1-len(hneg))
    hneg.reverse()  #re-reverse

    bh=[0]*(m+1)
    bh[0]=hpos[0:1]+b+hneg[0:1]+bneg
    for i in xrange(1,m+1):
        bh[i]=[hpos[j*m+i] for j in xrange(n1)]
        bh[i]+=[hneg[j*m+i] for j in xrange(n2)]
    bh[m]=map(lambda x,y:x-y,bh[m],b+[0]+bneg+[0])
    
    bh[0][0]+=bb
    bh[m][-1]-=bbneg
    #print 'bh=',bh
    assert len(bh)==m+1
    assert len(bh)==len(r)
    for x in bh: 
        assert len(x)==n1+n2
        
    #print len(bh)
    #print len(zip(bh,r)),len(ck[1])    
    H=[commitfunction(ck,x,rand) for x,rand in zip(bh,r)]
    BP=commitfunction(ck,[bb],rr)
    BPP=commitfunction(ck,[bbneg],rrneg)
    pk=H,BP,BPP
    sk=h,b,bb,bneg,bbneg,r,rr,rrneg,bh
    #print h.pp()
    return pk,sk 

def PolyEval(ck,sk,x):
    G,key=ck
    g=G.generator()
    p=G.order()
    h,b,bb,bneg,bbneg,r,rr,rrneg,bh=sk
    v=h.eval(x)
    #Hscale=[[elem*pow(x,i,p) for elem in bh[i]] for i in xrange(len(bh))] #wrong
    Hscale=LPoly([Ve(hi) for hi in bh],mod=p).eval(x)
    Zh= sum([r[i]*pow(x,i,p) for i in xrange(len(r))])
    try:
        xi=x.mod_inverse(p)
        #print 'Bn path succeeded' 
    except AttributeError: 
        #print 'Generic path'
        xi=_invert(x,p)
    Zb=rr*x-rrneg*xi
    pi=(Hscale,Zh,Zb)
    return v,pi

def PolyVerify(ck,pk,m,n1,n2,x,v,pi,commitfunction=Commitment.commit):
    G,key=ck
    g=G.generator()
    p=G.order()
    H,BP,BPP=pk
    Hscale,Zh,Zb=pi
    try:
        xi=x.mod_inverse(p)
        #print 'Bn path succeeded' 
    except AttributeError: 
        #print 'Generic path'
        xi=_invert(x,p)

    
    Cleft=reduce(operator.add,[pow(x,i,p)*H[i] for i in xrange(len(H))])
    #print 'x=',x
    #print Hscale
    #print v
    #print [xss%p for xss in Hscale]
    Cright=commitfunction(ck,Hscale,Zh)
    if not Cleft==Cright:
        print 'Verification Failed (1)'
        return 0
    Cleft2=x*BP-xi*BPP
    ppoly=LPoly(Hscale[:n1],mod=p)
    npoly=LPoly(Hscale[-n2:],mod=p)
    assert len(ppoly)==n1
    assert len(npoly)==n2
    rv1=ppoly.eval(pow(x,m,p))*x
    
    #print 'rv1sc',x
    #print 'rv1e ',ppoly.eval(pow(x,m,p))
    rv2=npoly.eval(pow(x,m,p))*pow(xi,m*n2+1,p)
    #print 'rv2sc',pow(xi,m*n2+1,p)
    #print 'rv2e ',npoly.eval(pow(xi,m,p))

    rval2=(rv1+rv2-v)%p
    #print 'diff==',(rv1+rv2-v)%p
    #print 'rval2=',rval2,ppoly,'=',rv1,npoly,'=',rv2
    Cright2=commitfunction(ck,[rval2],Zb)
    if not Cleft2==Cright2:
        print 'Verification Failed (2)'
        return 0
    print 'Verification successful'
    return 1
        
