import pytest
from pytest import raises


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
    import Recursion
    assert True

@pytest.mark.task2
def test_prover_final_step():
    from petlib.bn import *
    
    from Commitment import *
    from Recursion import *
    pk=commitment_key_gen(1)
    G,ck=pk
    pk2=G,ck,ck
    Aopen=[G.order().random() for i in range(1)]
    print 'Aopen=',Aopen
    Bopen=[G.order().random() for i in range(1)]
    print 'Bopen=',Bopen
    A=commit(pk,Aopen,0)
    B=commit(pk,Bopen,0)
    print 'A=',A,'B=',B
    z=dotprod(Aopen,Bopen)
    print 'z=',z
    proof=recursive_prover(pk2,A,Aopen,0,B,Bopen,0,z)
    A_p,Aopen_p,Arand_p,B_p,Bopen_p,Brand_p, z_p,T=proof
    assert check_open_commit(pk,A_p,Aopen_p,Arand_p)
    assert check_open_commit(pk,B_p,Bopen_p,Brand_p)
    assert commit(pk,Aopen_p,Arand_p)==A
    assert commit(pk,Bopen_p,Brand_p)==B
    assert z==z_p
    assert z_p==dotprod(Aopen_p,Bopen_p)
    #print proof
    pk3=G,ck,[]
    with raises(Exception) as excinfo:
        recursive_prover(pk3,A,Aopen,0,B,Bopen,0,z)
    assert 'commitment keys must have same length' in str(excinfo.value)
    t=G.order().random()
    with raises(Exception) as excinfo:
        recursive_prover(pk2,A,Aopen,0,B,Bopen,0,t)
    assert 'invalid witness' in str(excinfo.value)

    with raises(Exception) as excinfo:
        recursive_prover(pk2,A,Aopen,0,A,Bopen,0,z)
    assert 'invalid witness' in str(excinfo.value)

    with raises(Exception) as excinfo:
        recursive_prover(pk2,B,Aopen,0,B,Bopen,0,z)
    assert 'invalid witness' in str(excinfo.value)
    
@pytest.mark.task3
def test_recursion_prover():
    from petlib.bn import *
    
    from Commitment import *
    from Recursion import *
    pk=commitment_key_gen(2**12)
    G,ck=pk
    pk2=G,ck,ck
    Aopen=[G.order().random() for i in range(2**12)]
    print 'Aopen=',Aopen
    Bopen=[G.order().random() for i in range(2**12)]
    print 'Bopen=',Bopen
    A=commit(pk,Aopen,0)
    B=commit(pk,Bopen,0)
    print 'A=',A,'B=',B
    z=dotprod(Aopen,Bopen)
    print 'z=',z    
    proof=recursive_prover(pk2,A,Aopen,0,B,Bopen,0,z,2**12)
    assert recursive_verifier(pk2,A,B,z,proof)
    assert False
    
