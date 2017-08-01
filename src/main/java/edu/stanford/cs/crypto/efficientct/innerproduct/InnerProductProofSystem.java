package edu.stanford.cs.crypto.efficientct.innerproduct;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.ProofSystem;
import edu.stanford.cs.crypto.efficientct.ProofUtils;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.VectorBase;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Created by buenz on 6/28/17.
 */
public class InnerProductProofSystem implements ProofSystem<VectorBase,ECPoint,InnerProductWitness, InnerProductProof,InnerProductProver, EfficientInnerProductVerifier> {


    @Override
    public InnerProductProver getProver() {
        return new InnerProductProver();
    }

    @Override
    public EfficientInnerProductVerifier getVerifier() {
        return new EfficientInnerProductVerifier();
    }

    public VectorBase generatePublicParams(int size) {

        GeneratorVector gs = GeneratorVector.from(VectorX.range(0, size).map(i -> "G" + i).map(ProofUtils::hash).map(ProofUtils::fromSeed));
        GeneratorVector hs = GeneratorVector.from(VectorX.range(0, size).map(i -> "H" + i).map(ProofUtils::hash).map(ProofUtils::fromSeed));
        ECPoint v = ProofUtils.fromSeed(ProofUtils.hash("V"));
        return new VectorBase(gs, hs, v);
    }
}