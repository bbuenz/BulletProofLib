package edu.stanford.cs.crypto.efficientct.circuit;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;

public class R1CS {


    private final VectorX<FieldVector> a;
    private final VectorX<FieldVector> b;
    private final VectorX<FieldVector> c;

    public R1CS(VectorX<FieldVector> a, VectorX<FieldVector> b, VectorX<FieldVector> c) {
        this.a = a;
        this.b = b;
        this.c = c;
    }
    public VectorX<FieldVector> getA() {
        return a;
    }

    public VectorX<FieldVector> getB() {
        return b;
    }

    public VectorX<FieldVector> getC() {
        return c;
    }

}
