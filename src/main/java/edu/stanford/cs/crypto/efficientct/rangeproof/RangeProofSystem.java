package edu.stanford.cs.crypto.efficientct.rangeproof;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.ProofSystem;
import edu.stanford.cs.crypto.efficientct.ProofUtils;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.PeddersenBase;
import edu.stanford.cs.crypto.efficientct.linearalgebra.VectorBase;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Created by buenz on 7/1/17.
 */
public class RangeProofSystem implements ProofSystem<GeneratorParams,ECPoint,RangeProofWitness,RangeProof, RangeProofProver, RangeProofVerifier> {
    @Override
    public RangeProofProver getProver() {
        return new RangeProofProver();
    }

    @Override
    public RangeProofVerifier getVerifier() {
        return new RangeProofVerifier();
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
