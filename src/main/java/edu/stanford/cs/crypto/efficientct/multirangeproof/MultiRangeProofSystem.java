package edu.stanford.cs.crypto.efficientct.multirangeproof;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.ProofSystem;
import edu.stanford.cs.crypto.efficientct.ProofUtils;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.PeddersenBase;
import edu.stanford.cs.crypto.efficientct.linearalgebra.VectorBase;
import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.rangeproof.RangeProof;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Created by buenz on 7/1/17.
 */
public class MultiRangeProofSystem implements ProofSystem<GeneratorParams,GeneratorVector,MultiRangeProofWitness,RangeProof,MultiRangeProofProver, MultiRangeProofVerifier> {
    @Override
    public MultiRangeProofProver getProver() {
        return new MultiRangeProofProver();
    }

    @Override
    public MultiRangeProofVerifier getVerifier() {
        return new MultiRangeProofVerifier();
    }


    public GeneratorParams generateParams(int size) {
        VectorX<ECPoint> gs = VectorX.range(0,size).map(i -> "G" + i).map(ProofUtils::hash).map(ProofUtils::fromSeed);
        VectorX<ECPoint> hs = VectorX.range(0,size).map(i -> "H" + i).map(ProofUtils::hash).map(ProofUtils::fromSeed);
        ECPoint g = ProofUtils.fromSeed(ProofUtils.hash("G"));
        ECPoint h = ProofUtils.fromSeed(ProofUtils.hash("H"));
        VectorBase vectorBase=new VectorBase(GeneratorVector.from(gs),GeneratorVector.from(hs), h);
        PeddersenBase base=new PeddersenBase(g,h);
        return new GeneratorParams(vectorBase,base);

    }
}
