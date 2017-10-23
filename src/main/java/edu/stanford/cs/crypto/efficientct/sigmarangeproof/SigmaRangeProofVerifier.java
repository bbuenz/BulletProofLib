package edu.stanford.cs.crypto.efficientct.sigmarangeproof;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.VerificationFailedException;
import edu.stanford.cs.crypto.efficientct.Verifier;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.PeddersenBase;
import edu.stanford.cs.crypto.efficientct.rangeproof.RangeProof;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public class SigmaRangeProofVerifier implements Verifier<PeddersenBase, ECPoint, SigmaRangeProof> {
    @Override
    public void verify(PeddersenBase params, ECPoint input, SigmaRangeProof proof) throws VerificationFailedException {
        equal(input, proof.getBitCommitments().sum(), "Bit commitments are wrong");
        GeneratorVector a0s = proof.getBitCommitments().haddamard(proof.getChallenges().times(BigInteger.ONE.negate())).add(proof.getZeroResponses().getVector().map(params.g::multiply));
        GeneratorVector a1s = proof.getBitCommitments().haddamard(proof.getChallenges().add(proof.getX().negate())).add(proof.getOneResponses().getVector().map(params.g::multiply));
        BigInteger xPrime = ProofUtils.computeChallenge(a0s.getVector().plusAll(a1s.getVector()).materialize());
        equal(proof.getX(), xPrime, "Challenge not equal");
    }
}
