package edu.stanford.cs.crypto.efficientct;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.PeddersenBase;
import edu.stanford.cs.crypto.efficientct.linearalgebra.VectorBase;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;
import org.bouncycastle.math.ec.ECPoint;

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

    public static GeneratorParams generateParams(int size) {
        VectorX<ECPoint> gs = VectorX.range(0,size).map(i -> "G" + i).map(ProofUtils::hash).map(ProofUtils::fromSeed);
        VectorX<ECPoint> hs = VectorX.range(0,size).map(i -> "H" + i).map(ProofUtils::hash).map(ProofUtils::fromSeed);
        ECPoint g = ProofUtils.fromSeed(ProofUtils.hash("G"));
        ECPoint h = ProofUtils.fromSeed(ProofUtils.hash("H"));
        VectorBase vectorBase=new VectorBase(GeneratorVector.from(gs),GeneratorVector.from(hs), h);
        PeddersenBase base=new PeddersenBase(g,h);
        return new GeneratorParams(vectorBase,base);

    }
}
