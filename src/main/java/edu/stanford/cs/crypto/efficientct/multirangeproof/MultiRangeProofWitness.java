package edu.stanford.cs.crypto.efficientct.multirangeproof;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.commitments.PeddersenCommitment;

import java.math.BigInteger;

/**
 * Created by buenz on 7/1/17.
 */
public class MultiRangeProofWitness {
    private final VectorX<PeddersenCommitment> commitments;


    public MultiRangeProofWitness(VectorX<PeddersenCommitment> commitments) {

        this.commitments = commitments;
    }

    public VectorX<PeddersenCommitment> getCommitments() {
        return commitments;
    }
}
