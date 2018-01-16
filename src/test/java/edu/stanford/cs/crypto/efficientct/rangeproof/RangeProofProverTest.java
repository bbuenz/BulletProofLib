package edu.stanford.cs.crypto.efficientct.rangeproof;

import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.circuit.groups.*;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;
import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.commitments.PeddersenCommitment;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.math.BigInteger;
import java.util.Arrays;


/**
 * Created by buenz on 7/1/17.
 */
@RunWith(Parameterized.class)
public class RangeProofProverTest<T extends GroupElement<T>> {
    @Parameterized.Parameters
    public static Object[] data() {
        return new Object[] { new Secp256k1(),new BN128Group()};
    }
    @Parameterized.Parameter
    public Group<?> curve;

    @Test
    public void testCompletness() throws VerificationFailedException {
        BigInteger number = BigInteger.valueOf(5);
        BigInteger randomness = ProofUtils.randomNumber();

        GeneratorParams parameters = GeneratorParams.generateParams(256,curve);
        GroupElement v = parameters.getBase().commit(number, randomness);
        PeddersenCommitment<BouncyCastleECPoint> witness = new PeddersenCommitment(parameters.getBase(),number, randomness);
        BouncyCastleECPoint.addCount=0;
        BouncyCastleECPoint.expCount=0;
        RangeProof proof = new RangeProofProver().generateProof(parameters, v, witness);
        System.out.println(BouncyCastleECPoint.expCount);
        System.out.println(BouncyCastleECPoint.addCount);
        RangeProofVerifier verifier = new RangeProofVerifier();
        verifier.verify(parameters, v, proof);

    }
    @Test
    public void testCompletness2() throws VerificationFailedException {
        BigInteger number = BigInteger.valueOf(100);
        BigInteger randomness = ProofUtils.randomNumber();

        GeneratorParams parameters = GeneratorParams.generateParams(256,curve);
        GroupElement v = parameters.getBase().commit(number, randomness);
        PeddersenCommitment witness = new PeddersenCommitment(parameters.getBase(),number, randomness);
        RangeProof proof = new RangeProofProver().generateProof(parameters, v, witness);
        RangeProofVerifier verifier = new RangeProofVerifier();
        verifier.verify(parameters, v, proof);
    }

    @Test(expected = VerificationFailedException.class)
    public void testSoundness() throws VerificationFailedException {
        BigInteger number = BigInteger.valueOf(70000);
        BigInteger randomness = ProofUtils.randomNumber();

        GeneratorParams parameters = GeneratorParams.generateParams(16,curve);
        GroupElement v = parameters.getBase().commit(number, randomness);
        PeddersenCommitment witness = new PeddersenCommitment(parameters.getBase(),number, randomness);
        RangeProof proof = new RangeProofProver().generateProof(parameters, v, witness);
        RangeProofVerifier verifier = new RangeProofVerifier();
        verifier.verify(parameters, v, proof);
    }


}