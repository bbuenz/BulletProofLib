package edu.stanford.cs.crypto.efficientct.innerproduct;

import cyclops.collections.mutable.ListX;
import edu.stanford.cs.crypto.efficientct.util.ECConstants;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;
import edu.stanford.cs.crypto.efficientct.Prover;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.VectorBase;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by buenz on 6/29/17.
 */
public class InnerProductProver implements Prover<VectorBase, ECPoint, InnerProductWitness, InnerProductProof> {

    @Override
    public InnerProductProof generateProof(VectorBase base, ECPoint c, InnerProductWitness witness) {
        int n = base.getGs().size();
        return generateProof(base, c, witness.getA(), witness.getB(), new ArrayList<>(Integer.bitCount(n)), new ArrayList<>(Integer.bitCount(n)));
    }

    private InnerProductProof generateProof(VectorBase base, ECPoint P, FieldVector as, FieldVector bs, List<ECPoint> ls, List<ECPoint> rs) {
        int n = as.size();
        if (n == 1) {
            return new InnerProductProof(ls, rs, as.firstValue(), bs.firstValue());
        }
        int nPrime = n / 2;
        FieldVector asLeft = as.subVector(0, nPrime);
        FieldVector asRight = as.subVector(nPrime, nPrime * 2);
        FieldVector bsLeft = bs.subVector(0, nPrime);
        FieldVector bsRight = bs.subVector(nPrime, nPrime * 2);

        GeneratorVector gs = base.getGs();
        GeneratorVector gLeft = gs.subVector(0, nPrime);
        GeneratorVector gRight = gs.subVector(nPrime, nPrime * 2);

        GeneratorVector hs = base.getHs();
        GeneratorVector hLeft = hs.subVector(0, nPrime);
        GeneratorVector hRight = hs.subVector(nPrime, nPrime * 2);

        BigInteger cL = asLeft.innerPoduct(bsRight);
        BigInteger cR = asRight.innerPoduct(bsLeft);
        ECPoint L = gRight.commit(asLeft).add(hLeft.commit(bsRight));
        ECPoint R = gLeft.commit(asRight).add(hRight.commit(bsLeft));

        ECPoint u = base.getH();
        L = L.add(u.multiply(cL));
        ls.add(L);
        R = R.add(u.multiply(cR));
        rs.add(R);

        BigInteger x = ProofUtils.computeChallenge(L, P, R);
        BigInteger xInv = x.modInverse(ECConstants.P);
        BigInteger xSquare = x.pow(2).mod(ECConstants.P);
        BigInteger xInvSquare = xInv.pow(2).mod(ECConstants.P);
        ListX<BigInteger> xs = ListX.fill(nPrime, x);
        ListX<BigInteger> xInverse = ListX.fill(nPrime, xInv);
        GeneratorVector gPrime = gLeft.haddamard(xInverse).add(gRight.haddamard(xs));
        GeneratorVector hPrime = hLeft.haddamard(xs).add(hRight.haddamard(xInverse));
        FieldVector aPrime = asLeft.times(x).add(asRight.times(xInv));
        FieldVector bPrime = bsLeft.times(xInv).add(bsRight.times(x));
        if (n % 2 == 1) {
            gPrime = gPrime.plus(gs.get(n - 1));
            hPrime = hPrime.plus(hs.get(n - 1));
            aPrime = aPrime.plus(as.get(n - 1));
            bPrime = bPrime.plus(bs.get(n - 1));

        }
        System.out.println("P " + P.normalize());
        System.out.println("PAlt "+gs.commit(as).add(hs.commit(bs)).add(u.multiply(as.innerPoduct(bs))).normalize());
        ECPoint PPrime = L.multiply(xSquare).add(R.multiply(xInvSquare)).add(P);
        VectorBase basePrime = new VectorBase(gPrime, hPrime, u);
        System.out.println("c "+ aPrime.innerPoduct(bPrime).mod(ECConstants.P));
        System.out.println("calt "+asLeft.innerPoduct(bsRight).multiply(xSquare).add(asRight.innerPoduct(bsLeft).multiply(xInvSquare)).add(as.innerPoduct(bs)).mod(ECConstants.P));
        System.out.println("X " + x);
        //System.out.println("Xinv " + xInv);
        System.out.println("C " +PPrime.normalize());
        ECPoint pPrimeAlt = gPrime.commit(aPrime).add(hPrime.commit(bPrime).add(u.multiply(aPrime.innerPoduct(bPrime)))).normalize();
        System.out.println("C alt" + pPrimeAlt);
        System.out.println(PPrime.equals(pPrimeAlt));
        return generateProof(basePrime, PPrime, aPrime, bPrime, ls, rs);
    }

}
