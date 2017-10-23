package edu.stanford.cs.crypto.efficientct.rangeproof;

import edu.stanford.cs.crypto.efficientct.GeneratorParams;
import edu.stanford.cs.crypto.efficientct.ProofSystem;
import edu.stanford.cs.crypto.efficientct.commitments.PeddersenCommitment;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Created by buenz on 7/1/17.
 */
public class RangeProofSystem implements ProofSystem<GeneratorParams, ECPoint, PeddersenCommitment, RangeProof, RangeProofProver, RangeProofVerifier> {
    @Override
    public RangeProofProver getProver() {

        return new RangeProofProver();
    }

    @Override
    public RangeProofVerifier getVerifier() {
        return new RangeProofVerifier();
    }


}
