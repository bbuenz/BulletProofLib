package edu.stanford.cs.crypto.efficientct.multirangeproof;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.ProofSystem;
import edu.stanford.cs.crypto.efficientct.commitments.PeddersenCommitment;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;
import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.rangeproof.RangeProof;

/**
 * Created by buenz on 7/1/17.
 */
public class MultiRangeProofSystem implements ProofSystem<GeneratorParams,GeneratorVector,VectorX<PeddersenCommitment>,RangeProof,MultiRangeProofProver, MultiRangeProofVerifier> {
    @Override
    public MultiRangeProofProver getProver() {
        return new MultiRangeProofProver();
    }

    @Override
    public MultiRangeProofVerifier getVerifier() {
        return new MultiRangeProofVerifier();
    }


}
