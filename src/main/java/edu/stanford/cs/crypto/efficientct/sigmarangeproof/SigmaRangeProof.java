package edu.stanford.cs.crypto.efficientct.sigmarangeproof;

import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;

import java.math.BigInteger;

public class SigmaRangeProof {
    private final BigInteger x;
    private final GeneratorVector bitCommitments;
    private final FieldVector challenges;
    private final FieldVector zeroResponses;
    private final FieldVector oneResponses;

    public SigmaRangeProof(BigInteger x, GeneratorVector bitCommitments, FieldVector challenges, FieldVector zeroResponses, FieldVector oneResponses) {
        this.x = x;
        this.bitCommitments = bitCommitments;
        this.challenges = challenges;
        this.zeroResponses = zeroResponses;
        this.oneResponses = oneResponses;
    }

    public BigInteger getX() {
        return x;
    }

    public GeneratorVector getBitCommitments() {
        return bitCommitments;
    }

    public FieldVector getChallenges() {
        return challenges;
    }

    public FieldVector getZeroResponses() {
        return zeroResponses;
    }

    public FieldVector getOneResponses() {
        return oneResponses;
    }
}
