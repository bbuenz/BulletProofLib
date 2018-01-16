package edu.stanford.cs.crypto.efficientct.rangeproof;

import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.circuit.groups.BN128Group;
import edu.stanford.cs.crypto.efficientct.circuit.groups.BouncyCastleECPoint;
import edu.stanford.cs.crypto.efficientct.circuit.groups.Group;
import edu.stanford.cs.crypto.efficientct.commitments.PeddersenCommitment;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;
import org.junit.Test;

import java.math.BigInteger;


/**
 * Created by buenz on 7/1/17.
 */
public class BN128Test {
    private Group<BouncyCastleECPoint> group = new BN128Group();

    @Test
    public void testCompletness() throws VerificationFailedException {
        BigInteger number = BigInteger.valueOf(5);
        BigInteger randomness = ProofUtils.randomNumber();

        GeneratorParams<BouncyCastleECPoint> parameters = GeneratorParams.generateParams(128,group);
        BouncyCastleECPoint v = parameters.getBase().commit(number, randomness);
        PeddersenCommitment<BouncyCastleECPoint> witness = new PeddersenCommitment<>(parameters.getBase(),number, randomness);
        RangeProofProver<BouncyCastleECPoint> prover = new RangeProofProver<>();
        RangeProof<BouncyCastleECPoint> proof = prover.generateProof(parameters, v, witness);
        RangeProofVerifier<BouncyCastleECPoint> verifier = new RangeProofVerifier<>();
        verifier.verify(parameters, v, proof);
    }
    @Test
    public void testCompletness2() throws VerificationFailedException {
        BigInteger number = BigInteger.valueOf(100);
        BigInteger randomness = ProofUtils.randomNumber();

        GeneratorParams<BouncyCastleECPoint> parameters = GeneratorParams.generateParams(256,group);
        BouncyCastleECPoint v = parameters.getBase().commit(number, randomness);
        PeddersenCommitment<BouncyCastleECPoint> witness = new PeddersenCommitment<>(parameters.getBase(),number, randomness);
        RangeProofProver<BouncyCastleECPoint> prover = new RangeProofProver<>();
        RangeProof<BouncyCastleECPoint> proof = prover.generateProof(parameters, v, witness);
        RangeProofVerifier<BouncyCastleECPoint> verifier = new RangeProofVerifier<>();
        verifier.verify(parameters, v, proof);
    }

    @Test(expected = VerificationFailedException.class)
    public void testSoundness() throws VerificationFailedException {
        BigInteger number = BigInteger.valueOf(70000);
        BigInteger randomness = ProofUtils.randomNumber();

        GeneratorParams<BouncyCastleECPoint> parameters = GeneratorParams.generateParams(16,group);
        BouncyCastleECPoint v = parameters.getBase().commit(number, randomness);
        PeddersenCommitment<BouncyCastleECPoint> witness = new PeddersenCommitment<>(parameters.getBase(),number, randomness);
        RangeProofProver<BouncyCastleECPoint> prover = new RangeProofProver<>();
        RangeProof<BouncyCastleECPoint> proof = prover.generateProof(parameters, v, witness);
        RangeProofVerifier<BouncyCastleECPoint> verifier = new RangeProofVerifier<>();
        verifier.verify(parameters, v, proof);
    }


}