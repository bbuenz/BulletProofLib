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
    import Main
    assert True

@pytest.mark.task2
def test_square_root():
    from Main import*
    ck=commitment_key_gen(N)
    m=8
    n=10
    m1=int(math.sqrt(int(m)))
    n1=int(math.ceil(int(4*m+2/m1)))+1
    n2=int(math.ceil(int(3*m/m1)))+1
    

    Trans=prover_sat(ck,m,n,N,m1,n1,n2,Q,state,W,C)
    
    print  verifier_sat(ck,m,n,N,m1,n1,n2,Q,state,W,C,Trans)
    assert True

@pytest.mark.task3
def test_log():
    from Main import*
    ck=commitment_key_gen(N)
    m=10
    n=8
    mu=2
    m1=int(math.sqrt(int(m)))
    n1=int(math.ceil(int(4*m+2/m1)))+1
    n2=int(math.ceil(int(3*m/m1)))+1
    

    Trans=prover_sat_log(ck,m,n,N,m1,n1,n2,mu,Q,state,W,C)
    
    print  verifier_sat_log(ck,m,n,N,m1,n1,n2,Q,state,W,C,Trans)
    assert False
