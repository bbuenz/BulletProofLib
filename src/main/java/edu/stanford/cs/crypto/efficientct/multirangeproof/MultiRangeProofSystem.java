package edu.stanford.cs.crypto.efficientct.multirangeproof;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.ProofSystem;
import edu.stanford.cs.crypto.efficientct.algebra.GroupElement;
import edu.stanford.cs.crypto.efficientct.commitments.PeddersenCommitment;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;
import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.rangeproof.RangeProof;

/**
 * Created by buenz on 7/1/17.
 */
public class MultiRangeProofSystem<T extends GroupElement<T>> implements ProofSystem<GeneratorParams<T>, GeneratorVector<T>, VectorX<PeddersenCommitment<T>>, RangeProof<T>, MultiRangeProofProver<T>, MultiRangeProofVerifier<T>> {
    @Override
    public MultiRangeProofProver<T> getProver() {
        return new MultiRangeProofProver<>();
    }

    @Override
    public MultiRangeProofVerifier<T> getVerifier() {
        return new MultiRangeProofVerifier<>();
    }


}
