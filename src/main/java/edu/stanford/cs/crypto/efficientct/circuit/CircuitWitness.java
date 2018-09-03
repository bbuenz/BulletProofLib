package edu.stanford.cs.crypto.efficientct.circuit;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.algebra.GroupElement;
import edu.stanford.cs.crypto.efficientct.commitments.PeddersenCommitment;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;

/**
 * Created by buenz on 7/6/17.
 */
public class CircuitWitness<T extends GroupElement<T>> {
    private final FieldVector l;
    private final FieldVector r;
    private final FieldVector o;
    private final VectorX<PeddersenCommitment<T>> commitments;

    public CircuitWitness(FieldVector l, FieldVector r, FieldVector o, VectorX<PeddersenCommitment<T>> commitments) {
        this.l = l;
        this.r = r;
        this.o = o;
        this.commitments = commitments;
    }


    public FieldVector getL() {
        return l;
    }

    public FieldVector getR() {
        return r;
    }

    public FieldVector getO() {
        return o;
    }

    public VectorX<PeddersenCommitment<T>> getCommitments() {
        return commitments;
    }
}
