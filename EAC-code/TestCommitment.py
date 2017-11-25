import pytest
import petlib

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
    Try to import the code file. 
    This is where the lab answers will be.
    """
    import Commitment
    assert True

@pytest.mark.task2
def test_keygen():
    from petlib.ec import EcGroup
    from petlib.bn import Bn
    from Commitment import commitment_key_gen
    #test keygen for one element
    G,commitment_key= commitment_key_gen(1)
    assert len(commitment_key)==2
    for i in range(len(commitment_key)):
        assert G.check_point(commitment_key[i])
    # Test keygen for vector commitments
    n=100
    G,commitment_key= commitment_key_gen(n)
    assert len(commitment_key)==n+1
    for i in range(Bn(len(commitment_key))):
        assert G.check_point(commitment_key[i])
    #Test trapdoor
    n=Bn(100).random()
    G,commitment_key,trapdoor= commitment_key_gen(n,True)
    assert len(commitment_key)==n+1
    assert len(trapdoor)==n+1
    for i in range(Bn(len(commitment_key))):
        assert commitment_key[i]==trapdoor[i]*G.generator()

@pytest.mark.task3
def test_commit():
    from pytest import raises
    from petlib.ec import EcGroup
    from petlib.bn import Bn
    from Commitment import *
    #Test exceeding vectors
    public_key=commitment_key_gen(1)
    G,commitment_key=public_key
    elements=[G.order().random(),G.order().random()]
    with raises(Exception) as excinfo:
        commit(public_key,elements)
    assert 'Too many elements!Longer key required' in str(excinfo.value)
    #test correctness
    elements=[G.order().random() for i in range(len(commitment_key)-1)]
    comm,rand=commit(public_key,elements)
    
    assert comm==elements[0]*commitment_key[0]+rand*commitment_key[1]
    #test opening of a commitment
    assert check_open_commit(public_key,comm,elements,rand)

@pytest.mark.task4
def test_pok():
    from pytest import raises
    from petlib.ec import EcGroup
    from petlib.bn import Bn
    from Commitment import *
    n=Bn(1000).random()
    public_key= commitment_key_gen(n)
    G,commitment_key=public_key
    p=G.order()
    elements=[p.random()for i in range(n-1)]
    A,rand=commit(public_key,elements)
    proof=pok_open_comm_prove(public_key,A,elements,rand)
    assert pok_open_comm_verify(public_key,A,proof)
    









