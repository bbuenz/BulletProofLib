import pytest
from LPoly import *
from PolyCommit import *    

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
    import PolyCommit
    assert True

@pytest.mark.task1
def test_aio():
    nn2=Bn(50000).random()+10
    nn1=Bn(50000).random()+10
    m=int(math.sqrt(int(max(nn1,nn2))))
    n1=int(math.ceil(int(nn1/m)))+1
    n2=int(math.ceil(int(nn2/m)))+1

    assert m*n1>=nn1
    assert m*n2>=nn2


    ck= commitment_key_gen(n1+n2)
    G,key=ck
    g=G.generator()
    p=G.order()

    np=[Bn(2**20).random() for c in xrange(nn2)]
    h=LPoly(np,deg=-len(np),mod=p)
    h.append(0)
    np=[Bn(2**20).random() for c in xrange(nn1)]
    h=h+LPoly(np,deg=1,mod=p)


    #h=LPoly([-3,-2,-1,0,1,2,3,4,5,6,7,8],deg=-3,mod=p)
    #h=LPoly([3,0,5],deg=-1,mod=23)
    #h=LPoly([100,-10,4,5],deg=8,mod=p)
    #h=LPoly([100],deg=1,mod=p)

    x0=p.random()
    #print h.pp()
    pk,sk=PolyCommit(ck,m,n1,n2,h)
    print 'Commit Ok'

    v,pi=PolyEval(ck,sk,x0)
    #print  v,h.eval(x0)
    assert v==h.eval(x0)
    print 'Eval Ok'

    ver=PolyVerify(ck,pk,m,n1,n2,x0,v,pi)
    assert ver==1
    #print 'h(x)=',h.pp()
    print 'x0=',x0
    print 'p=',p
