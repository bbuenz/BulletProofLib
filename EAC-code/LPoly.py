from petlib.bn import Bn
from convolution import convolution
from convolution_scalar import convolution_scalar


#fft ideas from https://gist.github.com/onkursen/5453573
#from numpy import fft
#import numpy as np


def dotprod(a,b):
    mul=lambda x:x[0]*x[1]
    summ=lambda x,y:x+y
    c=reduce(summ,map(mul,zip(a,b)))
    return c
 
def _offsetadd(a,b):
    #print a,b
    
    r=a[:-len(b)+1]+[a[len(a)-len(b)+i+1]+b[i] for i in xrange(len(b)-1)]
    if len(b)==1 : r=a[:]
    r.append(b[-1])
    #print r
    return r

def _conv(x,y,m):
    #r=[ [c*z for z in y] for c in x ]
    #print '----------'
    if m: return reduce(_offsetadd,([(c*z)%m for z in y] for c in x ))
    return reduce(_offsetadd,( [c*z for z in y] for c in x ))
    
def _conv_dot(x,y,m):
    #should be same as _conv, but does dotprod instead of whatever * happens to be
    #print '----------'
    if m: return (reduce(_offsetadd,( [dotprod(c,z)%m for z in y] for c in x )))
    return reduce(_offsetadd,( [dotprod(c,z) for z in y] for c in x ))
    

def _invert(a,n):
    '''Code is ancient, beware'''
    a=a%n
    if a==1 : return 1
    #a=1 does not invert properly
    #as it is a border case
    
    #n=a*p[1]+y[1]
    #coefn[1]=1
    #coefa[1]=-p[1]
    #y[1]=n*coefn[1]+a*coefa[1]
    p=[]
    y=[]
    y.append(a)
    p.append(n//a)
    y.append(n%a)
    #print '%s=(%s) x %s + %s' % (n,p[-1],y[-2],y[-1])
    while y[-1]:
        y.append(y[-2]%y[-1])
        p.append(y[-3]//y[-2]) #allaje amesws prin, opote pame ena offset pera
        #print '%s=(%s) x %s + %s' % (y[-3],p[-1],y[-2],y[-1])
    #print ('mkd= %s') % y[-2],
    if not y[-2]==1: return None
    s=[]
    s.append((0,1))
    s.append((1,-p[0]))
    i=1
    while i<len(y)-2:
        #print( (y[i]-p[i]*s[-1][0],y[i]-p[i]*s[-1][1] ))
        s.append( (s[-2][0]-p[i]*s[-1][0],s[-2][1]-p[i]*s[-1][1] ))
        i=i+1
    #print s
    #(n,a)*(s[-1])=1 ara a*[s-1][1]=1 mod n
    return s[-1][1]

def Ve2(x):
    return np.array(x,dtype=object)



class Ve(list):
    def __neg__(self):
        return Ve([-x for x in self])
    def __mod__(self,other):
        return Ve([x%other for x in self])
    def __sub__(self,other):
        try:
            if len(self)==len(other): return Ve([x-y for (x,y) in zip(self,other)])
            if len(other)==1: return Ve([x-other for x in self])
            if len(self)==1: return Ve([self-y for y in other])
            print 'Vector addition failed: length mismatch'
            return None
        except (AttributeError,TypeError):
            return Ve([x-other for x in self])
    def __add__(self,other):
        try:
            if len(self)==len(other): return Ve([x+y for (x,y) in zip(self,other)])
            if len(other)==1: return Ve([x+other for x in self])
            if len(self)==1: return Ve([self+y for y in other])
            #print 'Vector addition failed: length mismatch'
            return None
        except (AttributeError,TypeError):
            return Ve([x+other for x in self])
    def __mul__(self,other):
        try:
            if len(self)==len(other): return Ve([x*y for (x,y) in zip(self,other)])
            if len(other)==1: return Ve([x*other for x in self])
            if len(self)==1: return Ve([self*y for y in other])
            #print 'Vector multiplication failed: length mismatch'
            return None
        except (AttributeError,TypeError):
            return Ve([x*other for x in self])
    def __div__(self,other):
        try:
            if len(self)==len(other): return Ve([x//y for (x,y) in zip(self,other)])
            if len(other)==1: return Ve([x//other for x in self])
            if len(self)==1: return Ve([self//y for y in other])
            #print 'Vector division failed: length mismatch'
            return None
        except (AttributeError,TypeError):
            return Ve([x//other for x in self])
    __rmul__=__mul__
    __radd__=__add__
 
class LPoly(list):
    '''Basic Laurent polynomials. Coefficients are stored as a dense list. ldegree is the degree of the first coefficient.
    Programming-wise our polynomials are lists with extra attributes (ldegree,mod) and +,* operations that make sense. 
    A modulus is optional. As of right now, it is buggy: operations use the modulus of the first operand and disregard the second, 
    except when they don't because addition can flip the order. Also, addition with modulus does not reduce copied parts.
    '''
    
    def __init__(self, li,deg=0,mod=None):
        list.__init__(self, li)
        self.ldegree=deg
        self.modulus=mod
    def settop(self,newdeg):
        self.ldegree = newdeg-len(self)+1
        return self
    def setbot(self,newdeg):
        self.ldegree = newdeg
        return self
    def setmodulus(self,mod):
        self.modulus=mod
        return self
    def pp(self):
        '''
        Returns pretty print version of polynomial
        '''
        return reduce((lambda x,y: x+' +'+y),[str(self[d])+'X^'+str((d+self.ldegree)) for d in xrange(len(self))])
    def __mod__(self,other):
        self.modulus=other
        return self
    def __mul__(self, other):
        
        try:
            dnew=self.ldegree+other.ldegree
            pnew=LPoly(_conv(self, other,self.modulus))
        except AttributeError:
            dnew=self.ldegree
            if self.modulus : 
                #print 'branch'
                pnew=LPoly([other*c % self.modulus for c in self])
            else:
                pnew=LPoly([other*c for c in self])
        pnew.setbot(dnew)
        if self.modulus:
            pnew.setmodulus(self.modulus)
            pnew.reduce(self.modulus)
        return pnew

    def fft_mul_np(self,other):# This is the numpy version of FFT. It works over the complex, map back the result over the integer and reduce it mod self.modulus if present. Cannot get arbitrary precision
        dnew=self.ldegree+other.ldegree
        sizenew=len(self)+len(other)-1
        
        if isinstance(self[0],list):
            vectorsize=len(self[0])
            #s=[e[0] for e in self]
            #o=[e[0] for e in other]
            #A=fft.fft(s,sizenew)
            #B=fft.fft(o,sizenew)
            #C=A*B
            #c=LPoly([int(round(x)) for x in fft.ifft(C,sizenew)])
            #print "c=",c
            
            #for i in xrange(0,vectorsize):
                #print i," of ",vectorsize
            s=[[e[i] for e in self] for i in xrange(vectorsize)]
            o=[[e[i] for e in other] for i in xrange(vectorsize)]
            t=[e[0] for e in self]
            
            A=[fft.fft(l,sizenew) for l in s]
            
            #print A, len(A)
            B=[fft.fft(l,sizenew) for l in s]
            C=[x*y for x,y in zip(A,B)]
            #print C, len(C)
            CC=[[int(round(x)) for x in fft.ifft(t,sizenew)] for t in C]
            print CC
            c=LPoly([Ve([e[i] for e in CC]) for i in xrange(len(CC[0]))])
            #c=LPoly(zip(c,[int(round(x)) for x in fft.ifft(C,sizenew)]))     
            c.setbot(dnew)
                    
            
        else:
            s=[e for e in self]
            o=[e for e in other]
            A=fft.fft(s,sizenew)
            B=fft.fft(o,sizenew)
            C=A*B
            c=LPoly([int(round(x)) for x in fft.ifft(C,sizenew)])
            print "c=",c
            c.setbot(dnew)

        if self.modulus:
                c.setmodulus(self.modulus)
                c.reduce()  
        return c
 
    def fft_mul(self,other):
        dnew=self.ldegree+other.ldegree
        sizenew=len(self)+len(other)
        
        c=LPoly(convolution(self,other))
        #print c[0][0]
        #print "c=",c
        c.setbot(dnew)
        m=self.modulus
        if m:
            c.setmodulus(m)
            for i in xrange(len(c)):
                #print sum(c[i]) 
                c[i]=sum(c[i]) % m

        else:
            for i in xrange(len(c)): c[i]=sum(c[i])
        return c

    def fft_mul_slice(self,other):
        SLICES=222
        vsize=len(self[0])
        for i in xrange(1+(vsize-1)/SLICES):
            if SLICES==1:
                if (i%50)==0 : print i," of ",1+(vsize-1)/SLICES            
                otherslice=[si[i] for si in other]
                selfslice=[si[i] for si in self]
            else:
                if (i%10)==0 : print i," of ",1+(vsize-1)/SLICES
                otherslice=[Ve(si[i*SLICES:(i+1)*SLICES]) for si in other]
                selfslice=[Ve(si[i*SLICES:(i+1)*SLICES]) for si in self]
            #selfslice.ldegree=self.ldegree
            #if self.modulus: selfslice.modulus=self.modulus
            #otherslice.ldegree=self.ldegree
            #if other.modulus: otherslice.modulus=self.modulus
            if SLICES==1:
                ct=LPoly(convolution_scalar(selfslice,otherslice))   
                ct.setmodulus(self.modulus)         
            else:
                ct=LPoly(convolution(selfslice,otherslice))
            if i==0:
                c=ct
                #c.setmodulus(self.modulus)
            else:            
                c=c+ct % self.modulus
        dnew=self.ldegree+other.ldegree
        c.setbot(dnew)
        m=self.modulus
        if SLICES!=1:
            c.setmodulus(m)
            for i in xrange(len(c)):
                #if SLICES==1:
                #    c[i]=c[i]%m
                #else:
                c[i]=sum(c[i]) % self.modulus
        return c
    
            
    def dot_mul(self, other):
        
        try:
            dnew=self.ldegree+other.ldegree
            pnew=LPoly(_conv_dot(self, other,self.modulus))
        except AttributeError:
            print "Undefined Operation"
            exit(-1)
        pnew.setbot(dnew)
        pnew.setmodulus(self.modulus)
        return pnew
    __rmul__=__mul__
    def reduce(self,mod=None):
        if not mod : mod=self.modulus
        assert mod
        for i,c in enumerate(self):  self[i]=c%mod 
        return self
    def __add__(self,other):
        from operator import add
        try:
            if self.ldegree<=other.ldegree:
                #print 'go'
                dnew=self.ldegree
                d=other.ldegree-self.ldegree
                #print self.pp()
                #print other.pp()
                #print 'd=',d
                pnew=self[0:d]                     #init (1/5)
                #print 'gap:',max(0,d-len(self))
                pnew+=[0]*max(0,d-len(self))       #gap (2/5)
                r=self[d:min(len(self),len(other)+d)]
                l=other[0:max(0,min(len(other),len(self)-d))]
                #print r
                #print l
                if self.modulus>0 :
                    #print 'using modular addition mod', self.modulus 
                    addop = (lambda x,y: (x+y)%self.modulus)
                else:
                    addop = (lambda x,y: x+y)
                pnew+=map(addop,r,l)              #common (3/5)
                pnew+=other[max(0,min(len(other),len(self)-d)):]    #tail--other (4/5)
                pnew+=self[len(pnew):]    #tail--self (5/5)
                
            else:
                return other+self
        except AttributeError:
            return self+LPoly([other])
        pnew=LPoly(pnew)
        pnew.setbot(dnew)
        pnew.setmodulus(self.modulus)
        return pnew
    def __sub__(self,other):
        return self+(-1)*other

    def getcoeff(self,exp):
        if self.ldegree<=exp and exp<=(len(self)-1+self.ldegree): return self[exp-self.ldegree]
        return 0
    def __eq__(self,other):
        if self.modulus and other.modulus and self.modulus!=other.modulus: return 0
        if self.modulus: mod=self.modulus
        else: mod=other.modulus
        imin=min(self.ldegree,other.ldegree)
        imax=max(self.ldegree+len(self),other.ldegree+len(other))
        if mod:
            for i in xrange(imin,imax+1):
                if ((self.getcoeff(i)-other.getcoeff(i))% mod)!=0 : return 0
        else:
            for i in xrange(imin,imax+1):
                if self.getcoeff(i)!=other.getcoeff(i) : return 0
        
        return 1
    def eval(self,x):

        r=0
        if self.modulus:
            if self.ldegree>=0:
                x0=pow(x,self.ldegree,self.modulus)
            else:
                try:
                    #print self.modulus
                    xi=x.mod_inverse(self.modulus)
                    #print 'Bn path succeeded' 
                except AttributeError: 
                    #print 'Generic path'
                    xi=_invert(x,self.modulus)
                x0=pow(xi,-self.ldegree,self.modulus)
                
            for c in self:
                #print 'Mod eval' 
                r=(r+ (c*x0%self.modulus))%self.modulus
                x0=(x0*x) % self.modulus
                #print r,x0,x
        else:
            x0=pow(x,self.ldegree)
            for c in self:
                #print 'NonMod eval'
                r=r+(c*x0)
                x0=x0*x
                #print r,x0,x
        return r
