package edu.stanford.cs.crypto.efficientct.innerproduct;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.VectorBase;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Test;

import java.math.BigInteger;
import java.util.Random;
import java.util.stream.Collectors;

/**
 * Created by buenz on 6/29/17.
 */
public class InnerProductVerifierTest {
    @Test
    public void testCompletness() throws Exception {
        InnerProductProofSystem system = new InnerProductProofSystem();
        VectorBase parameters = system.generatePublicParams(16);
        Random random = new Random();

        FieldVector as = FieldVector.from(VectorX.generate(16,()->new BigInteger(4,random)).materialize());
        FieldVector bs = FieldVector.from(VectorX.generate(16,()->new BigInteger(4,random)).materialize());
        BigInteger c = as.innerPoduct(bs);
        ECPoint vTot = parameters.commit(as, bs, c);
        System.out.println(vTot.normalize());
        InnerProductWitness witness = new InnerProductWitness(as, bs);
        InnerProductProver prover = system.getProver();
        System.out.println(as);
        System.out.println(bs);
        System.out.println(c);
        InnerProductProof proof = prover.generateProof(parameters, vTot, witness);
        InnerProductVerifier verifier = new InnerProductVerifier();
        verifier.verify(parameters, vTot, proof);

    }

    @Test(expected = VerificationFailedException.class)
    public void testSoundness() throws Exception {
        InnerProductProofSystem system = new InnerProductProofSystem();
        VectorBase parameters = system.generatePublicParams(16);
        Random random = new Random();

        FieldVector as = FieldVector.from(random.ints(16,0,20).mapToObj(BigInteger::valueOf).collect(Collectors.toList()));
        FieldVector bs = FieldVector.from(random.ints(16,0,20).mapToObj(BigInteger::valueOf).collect(Collectors.toList()));
        System.out.println(as);
        System.out.println(bs);
        BigInteger c = as.innerPoduct(bs).add(BigInteger.ONE);
        ECPoint vTot = parameters.commit(as, bs, c);
        System.out.println(vTot.normalize());
        InnerProductWitness witness = new InnerProductWitness(as, bs);
        InnerProductProver prover = system.getProver();
        System.out.println(as);
        System.out.println(bs);
        System.out.println(c);
        InnerProductProof proof = prover.generateProof(parameters, vTot, witness);
        InnerProductVerifier verifier = new InnerProductVerifier();
        verifier.verify(parameters, vTot, proof);

    }


}
