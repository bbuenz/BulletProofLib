package edu.stanford.cs.crypto.efficientct.rangeproof;

import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;
import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.commitments.PeddersenCommitment;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Test;

import java.math.BigInteger;


/**
 * Created by buenz on 7/1/17.
 */
public class RangeProofProverTest {
    @Test
    public void testCompletness() throws VerificationFailedException {
        BigInteger number = BigInteger.valueOf(5);
        BigInteger randomness = ProofUtils.randomNumber();

        GeneratorParams parameters = GeneratorParams.generateParams(128);
        ECPoint v = parameters.getBase().commit(number, randomness);
        PeddersenCommitment witness = new PeddersenCommitment(parameters.getBase(),number, randomness);
        RangeProof proof = new RangeProofProver().generateProof(parameters, v, witness);
        RangeProofVerifier verifier = new RangeProofVerifier();
        verifier.verify(parameters, v, proof);
    }
    @Test
    public void testCompletness2() throws VerificationFailedException {
        BigInteger number = BigInteger.valueOf(100);
        BigInteger randomness = ProofUtils.randomNumber();

        GeneratorParams parameters = GeneratorParams.generateParams(256);
        ECPoint v = parameters.getBase().commit(number, randomness);
        PeddersenCommitment witness = new PeddersenCommitment(parameters.getBase(),number, randomness);
        RangeProof proof = new RangeProofProver().generateProof(parameters, v, witness);
        RangeProofVerifier verifier = new RangeProofVerifier();
        verifier.verify(parameters, v, proof);
    }

    @Test(expected = VerificationFailedException.class)
    public void testSoundness() throws VerificationFailedException {
        BigInteger number = BigInteger.valueOf(70000);
        BigInteger randomness = ProofUtils.randomNumber();

        GeneratorParams parameters = GeneratorParams.generateParams(16);
        ECPoint v = parameters.getBase().commit(number, randomness);
        PeddersenCommitment witness = new PeddersenCommitment(parameters.getBase(),number, randomness);
        RangeProof proof = new RangeProofProver().generateProof(parameters, v, witness);
        RangeProofVerifier verifier = new RangeProofVerifier();
        verifier.verify(parameters, v, proof);
    }


}