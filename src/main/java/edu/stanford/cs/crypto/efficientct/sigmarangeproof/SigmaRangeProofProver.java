package edu.stanford.cs.crypto.efficientct.sigmarangeproof;

import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.Prover;
import edu.stanford.cs.crypto.efficientct.commitments.PeddersenCommitment;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.PeddersenBase;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public class SigmaRangeProofProver implements Prover<PeddersenBase, ECPoint, PeddersenCommitment, SigmaRangeProof> {
    private final int n;

    public SigmaRangeProofProver(int n) {
        this.n = n;
    }

    @Override
    public SigmaRangeProof generateProof(PeddersenBase parameter, ECPoint input, PeddersenCommitment witness) {
        FieldVector bits = FieldVector.from(VectorX.range(0, n).map(i -> witness.getX().testBit(i) ? BigInteger.ONE : BigInteger.ZERO));
        VectorX<PeddersenCommitment> commitments = bits.getVector().map(bit -> new PeddersenCommitment(parameter, bit));
        throw new UnsupportedOperationException("Not yet implemented");
    }
}
