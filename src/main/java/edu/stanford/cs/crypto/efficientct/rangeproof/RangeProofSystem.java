package edu.stanford.cs.crypto.efficientct.rangeproof;

import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.ProofSystem;
import edu.stanford.cs.crypto.efficientct.commitments.PeddersenCommitment;
import edu.stanford.cs.crypto.efficientct.algebra.GroupElement;

/**
 * Created by buenz on 7/1/17.
 */
public class RangeProofSystem<T extends GroupElement<T>> implements ProofSystem<GeneratorParams<T>, T, PeddersenCommitment<T>, RangeProof<T>, RangeProofProver<T>, RangeProofVerifier<T>> {
    @Override
    public RangeProofProver<T> getProver() {

        return new RangeProofProver<>();
    }

    @Override
    public RangeProofVerifier<T> getVerifier() {
        return new RangeProofVerifier<>();
    }


}
