package edu.stanford.cs.crypto.efficientct.innerproduct;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.ProofSystem;
import edu.stanford.cs.crypto.efficientct.circuit.groups.Group;
import edu.stanford.cs.crypto.efficientct.circuit.groups.GroupElement;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.VectorBase;

/**
 * Created by buenz on 6/28/17.
 */
public class InnerProductProofSystem<T extends GroupElement<T>> implements ProofSystem<VectorBase<T>, T, InnerProductWitness, InnerProductProof<T>, InnerProductProver<T>, EfficientInnerProductVerifier<T>> {


    @Override
    public InnerProductProver<T> getProver() {
        return new InnerProductProver<>();
    }

    @Override
    public EfficientInnerProductVerifier<T> getVerifier() {
        return new EfficientInnerProductVerifier<>();
    }

    public <T extends GroupElement<T>> VectorBase<T> generatePublicParams(int size, Group<T> group) {

        GeneratorVector<T> gs = new GeneratorVector<>(VectorX.range(0, size).map(i -> "G" + i).map(ProofUtils::hash).map(group::hashInto),group);
        GeneratorVector<T> hs = new GeneratorVector<>(VectorX.range(0, size).map(i -> "H" + i).map(ProofUtils::hash).map(group::hashInto),group);
        T v = group.hashInto(ProofUtils.hash("V"));
        //TODO: This setup has a trapdoor. Just use it for testing. The previous setup is secure.
        // GeneratorVector gs = GeneratorVector.from(VectorX.generate(size, ProofUtils::randomNumber).map(ECConstants.G::multiply));
        // GeneratorVector hs = GeneratorVector.from(VectorX.generate(size, ProofUtils::randomNumber).map(ECConstants.G::multiply));
        // ECPoint v=ECConstants.G.multiply(ProofUtils.randomNumber());
        return new VectorBase<>(gs, hs, v);
    }
}