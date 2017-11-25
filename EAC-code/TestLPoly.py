import pytest
from LPoly import *    

@pytest.mark.task1
def test_petlib_present():
    """
    Try to import Petlib and pytest to ensure they are 
    present on the system, and accessible to the python 
    environment
    """
    import petlib 
    import pytest
    assert True
@pytest.mark.task1
def test_code_present():
    """
    Try to import the library. 
    """
    import LPoly
    assert True

@pytest.mark.task2
def test_gen_eq():
    a=LPoly([0,1,2,3])
    b=LPoly([1,2,3],deg=1)
    c=LPoly([0,1,2,Bn(3)])
    assert a==b
    assert a==c
    assert LPoly([0])==LPoly([0,0],-5,Bn(3))

@pytest.mark.task2
def test_add_mul():
    a=LPoly([0,1,Bn(2),3])
    b=LPoly([1,2,3],deg=1)
    c=LPoly([0,1,2,Bn(3)],mod=3,deg=4)
    assert a+b==b+a
    assert 2*a==a+a
    assert 5*c==c+c+c+c+c
    x=LPoly([1],1)
    y=LPoly([0,1])
    assert x==y
    assert x.setbot(2)==y*y
    m=Bn.from_binary(b"10000adadadadadad000001").random()
    p=LPoly([1,1],mod=m)
    q=LPoly([1,1])
    q5=q*q*q*q*q
    p5=p*p*p*p*p
    assert p5==q5 #only for small coeffs
    assert (p*p*p).modulus==m
    assert (q-q)==LPoly([0])
    assert LPoly([0])+p==(q-q)+p
    assert LPoly([0],mod=m)==p-p
    print (-1*p).modulus
    print (p-p).pp(),(p-p).modulus
    assert (p-p).reduce()==LPoly([0],mod=m)
    assert (p-p)==LPoly([0],mod=m)
    assert (q-q)+p==LPoly([0])+p
    
    pstride=LPoly([3,2,1,0,1,2,3],deg=-3)
    assert pstride+LPoly([0])==pstride
    
    

    #assert 0
    
@pytest.mark.task3
def test_eval():
    from numpy import fft
    x=LPoly([1],1)
    y=LPoly([0,1])
    assert (y*y).eval(1)==1
    assert x.eval(0)==0
    x=Bn.from_binary(b"10000adadadadada000001").random()
    print x
    #x=Bn(1)
    m=Bn.from_binary(b"10000adadadadadad000001").random()
    p=LPoly([1,1],mod=m)
    q=LPoly([1,1])
    q5=q*q*q*q*q
    p5=p*p*p*p*p
    rh=p*p
    assert rh==p.fft_mul(p)
    assert p5==q5 #only for small coeffs
    assert q5.eval(x)%m==pow(x+1,5,m)
    assert (p*p*p*p*p).eval(x)%m==pow(x+1,5,m) #this should not be needed but it might help pin down bugs
    assert (p*p*p*p*p).eval(x)==pow(x+1,5,m)
    assert LPoly([1],-1,13).eval(5)==8
    assert LPoly([1],-1,13).eval(Bn(5))==8

@pytest.mark.task4
def test_vectors():
    a=Ve([1,2,3,4,5])
    b=Ve([6,7,8,9,0])
    assert a+b==b+a
    assert a+a==2*a
    assert 2*a==a*2
    assert len(a)==len(a+b)
    assert len(b)==len(5*b)
    assert a-b+b==a
    assert a+2==2+a
    assert a*5==5*a

from petlib.ec import *
import numpy as np
G=EcGroup() 
a=np.array([G.order(),G.order().random()])
x=[1,2,3,4,G.order().random()]
y=Ve2(x)
print x,x+x,y+y,y//y
print a, a*a,a*a%G.order()-G.order(),a+a,a*2,2*a,a%2
G=EcGroup()   
p1=LPoly([[Bn(1),int(2)],[3,4]],0,7)
p2=LPoly([Ve([10000000000000000000,2]),Ve([3,4])],0)
print p2,p2.fft_mul_np(p2), (p2*p2)
assert False

print p
print p.ldegree
print p.pp()
p.settop(5)
print p.ldegree
p.pp()
p.setbot(-4)
p.pp()
q=LPoly([3,4])
print q.pp()
r= p*q
print r.pp()
print p.ldegree
print LPoly(p)
print LPoly([5])
print p*5,(p*5).ldegree
print '----'

print (p*5).pp()

print '---'
print 5*p
p=LPoly([1,2],mod=2)
p.setbot(-3)
q=LPoly([3,4])
print p.ldegree,q.ldegree
print (p+q).pp()
print (q+p).pp()
print (p+5).reduce(4).pp()
t=LPoly([Bn(7),0,Bn(5)])
print (t+p).pp()
