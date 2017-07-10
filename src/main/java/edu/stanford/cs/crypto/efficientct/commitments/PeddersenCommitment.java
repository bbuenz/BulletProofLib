package edu.stanford.cs.crypto.efficientct.commitments;

import edu.stanford.cs.crypto.efficientct.ECConstants;
import edu.stanford.cs.crypto.efficientct.linearalgebra.PeddersenBase;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

/**
 * Created by buenz on 7/6/17.
 */
public class PeddersenCommitment implements HomomorphicCommitment<PeddersenCommitment> {
    private final PeddersenBase base;
    private final BigInteger x;
    private final BigInteger r;
    private final BigInteger q = ECConstants.P;
    private ECPoint commitment;
    public PeddersenCommitment(PeddersenBase base, BigInteger x, BigInteger r) {
        this.base = base;
        this.x = x;
        this.r = r;
    }

    @Override
    public <C2 extends PeddersenCommitment> PeddersenCommitment add(C2 other) {
        return new PeddersenCommitment(base, x.add(other.getX()), r.add(other.getR()));
    }

    @Override
    public PeddersenCommitment times(BigInteger exponent) {
        return new PeddersenCommitment(base, x.multiply(exponent).mod(q), r.multiply(exponent).mod(q));
    }

    @Override
    public PeddersenCommitment addConstant(BigInteger constant) {
        return new PeddersenCommitment(base, x.add(constant), r);
    }

    public BigInteger getX() {
        return x;
    }

    public BigInteger getR() {
        return r;
    }
    public ECPoint getCommitment(){
        if(commitment==null){
            commitment=base.commit(x,r);
        }
        return commitment;
    }
}
