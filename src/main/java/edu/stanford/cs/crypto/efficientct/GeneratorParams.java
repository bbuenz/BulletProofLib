package edu.stanford.cs.crypto.efficientct;

import edu.stanford.cs.crypto.efficientct.PublicParameter;
import edu.stanford.cs.crypto.efficientct.linearalgebra.PeddersenBase;
import edu.stanford.cs.crypto.efficientct.linearalgebra.VectorBase;

/**
 * Created by buenz on 7/1/17.
 */
public class GeneratorParams implements PublicParameter {
    private final VectorBase vectorBase;
    private final PeddersenBase base;

    public GeneratorParams(VectorBase vectorBase, PeddersenBase base) {
        this.vectorBase = vectorBase;
        this.base = base;
    }

    public VectorBase getVectorBase() {
        return vectorBase;
    }

    public PeddersenBase getBase() {
        return base;
    }
}
