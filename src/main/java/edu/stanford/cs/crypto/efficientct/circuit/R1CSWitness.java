package edu.stanford.cs.crypto.efficientct.circuit;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.commitments.PeddersenCommitment;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;

/**
 * Created by buenz on 7/6/17.
 */
public class R1CSWitness {
    private final FieldVector w;
    private final VectorX<PeddersenCommitment> commitments;

    public R1CSWitness(FieldVector w, VectorX<PeddersenCommitment> commitments) {
        this.w = w;
        this.commitments = commitments;
    }


    public FieldVector getW() {
        return w;
    }


    public VectorX<PeddersenCommitment> getCommitments() {
        return commitments;
    }
}
