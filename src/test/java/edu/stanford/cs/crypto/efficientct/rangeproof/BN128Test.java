package edu.stanford.cs.crypto.efficientct.rangeproof;

import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.algebra.BN128Group;
import edu.stanford.cs.crypto.efficientct.algebra.BN128Point;
import edu.stanford.cs.crypto.efficientct.algebra.BouncyCastleECPoint;
import edu.stanford.cs.crypto.efficientct.algebra.Group;
import edu.stanford.cs.crypto.efficientct.commitments.PeddersenCommitment;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;
import org.junit.Test;

import java.math.BigInteger;


/**
 * Created by buenz on 7/1/17.
 */
public class BN128Test {
    private Group<BN128Point> group = new BN128Group();

    @Test
    public void testCompletness() throws VerificationFailedException {
        BigInteger number = BigInteger.valueOf(5);
        BigInteger randomness = ProofUtils.randomNumber();

        GeneratorParams<BN128Point> parameters = GeneratorParams.generateParams(128,group);
        BN128Point v = parameters.getBase().commit(number, randomness);
        PeddersenCommitment<BN128Point> witness = new PeddersenCommitment<>(parameters.getBase(),number, randomness);
        RangeProofProver<BN128Point> prover = new RangeProofProver<>();
        RangeProof<BN128Point> proof = prover.generateProof(parameters, v, witness);
        RangeProofVerifier<BN128Point> verifier = new RangeProofVerifier<>();
        verifier.verify(parameters, v, proof);
    }
    @Test
    public void testCompletness2() throws VerificationFailedException {
        BigInteger number = BigInteger.valueOf(100);
        BigInteger randomness = ProofUtils.randomNumber();

        GeneratorParams<BN128Point> parameters = GeneratorParams.generateParams(256,group);
        BN128Point v = parameters.getBase().commit(number, randomness);
        PeddersenCommitment<BN128Point> witness = new PeddersenCommitment<>(parameters.getBase(),number, randomness);
        RangeProofProver<BN128Point> prover = new RangeProofProver<>();
        RangeProof<BN128Point> proof = prover.generateProof(parameters, v, witness);
        RangeProofVerifier<BN128Point> verifier = new RangeProofVerifier<>();
        verifier.verify(parameters, v, proof);
    }

    @Test(expected = VerificationFailedException.class)
    public void testSoundness() throws VerificationFailedException {
        BigInteger number = BigInteger.valueOf(70000);
        BigInteger randomness = ProofUtils.randomNumber();

        GeneratorParams<BN128Point> parameters = GeneratorParams.generateParams(16,group);
        BN128Point v = parameters.getBase().commit(number, randomness);
        PeddersenCommitment<BN128Point> witness = new PeddersenCommitment<>(parameters.getBase(),number, randomness);
        RangeProofProver<BN128Point> prover = new RangeProofProver<>();
        RangeProof<BN128Point> proof = prover.generateProof(parameters, v, witness);
        RangeProofVerifier<BN128Point> verifier = new RangeProofVerifier<>();
        verifier.verify(parameters, v, proof);
    }


}