package edu.stanford.cs.crypto.efficientct.innerproduct;

import cyclops.collections.mutable.ListX;
import edu.stanford.cs.crypto.efficientct.circuit.groups.GroupElement;
import edu.stanford.cs.crypto.efficientct.util.ProofUtils;
import edu.stanford.cs.crypto.efficientct.Prover;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.VectorBase;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by buenz on 6/29/17.
 */
public class InnerProductProver<T extends GroupElement<T>> implements Prover<VectorBase<T>, T, InnerProductWitness, InnerProductProof<T>> {

    @Override
    public InnerProductProof<T> generateProof(VectorBase<T> base, T c, InnerProductWitness witness) {
        int n = base.getGs().size();
        return generateProof(base, c, witness.getA(), witness.getB(), new ArrayList<>(Integer.bitCount(n)), new ArrayList<>(Integer.bitCount(n)));
    }

    private InnerProductProof<T> generateProof(VectorBase<T> base, T P, FieldVector as, FieldVector bs, List<T> ls, List<T> rs) {
        int n = as.size();
        if (n == 1) {
            return new InnerProductProof<>(ls, rs, as.firstValue(), bs.firstValue());
        }
        int nPrime = n / 2;
        FieldVector asLeft = as.subVector(0, nPrime);
        FieldVector asRight = as.subVector(nPrime, nPrime * 2);
        FieldVector bsLeft = bs.subVector(0, nPrime);
        FieldVector bsRight = bs.subVector(nPrime, nPrime * 2);

        GeneratorVector<T> gs = base.getGs();
        GeneratorVector<T> gLeft = gs.subVector(0, nPrime);
        GeneratorVector<T> gRight = gs.subVector(nPrime, nPrime * 2);

        GeneratorVector<T> hs = base.getHs();
        GeneratorVector<T> hLeft = hs.subVector(0, nPrime);
        GeneratorVector<T> hRight = hs.subVector(nPrime, nPrime * 2);

        BigInteger cL = asLeft.innerPoduct(bsRight);
        BigInteger cR = asRight.innerPoduct(bsLeft);
        T L = gRight.commit(asLeft).add(hLeft.commit(bsRight));
        T R = gLeft.commit(asRight).add(hRight.commit(bsLeft));

        T u = base.getH();
        L = L.add(u.multiply(cL));
        ls.add(L);
        R = R.add(u.multiply(cR));
        rs.add(R);
        BigInteger q=gs.getGroup().groupOrder();
        BigInteger x = ProofUtils.computeChallenge(q,L, P, R);
        BigInteger xInv = x.modInverse(q);
        BigInteger xSquare = x.pow(2).mod(q);
        BigInteger xInvSquare = xInv.pow(2).mod(q);
        ListX<BigInteger> xs = ListX.fill(nPrime, x);
        ListX<BigInteger> xInverse = ListX.fill(nPrime, xInv);
        GeneratorVector<T> gPrime = gLeft.haddamard(xInverse).add(gRight.haddamard(xs));
        GeneratorVector<T> hPrime = hLeft.haddamard(xs).add(hRight.haddamard(xInverse));
        FieldVector aPrime = asLeft.times(x).add(asRight.times(xInv));
        FieldVector bPrime = bsLeft.times(xInv).add(bsRight.times(x));
        if (n % 2 == 1) {
            gPrime = gPrime.plus(gs.get(n - 1));
            hPrime = hPrime.plus(hs.get(n - 1));
            aPrime = aPrime.plus(as.get(n - 1));
            bPrime = bPrime.plus(bs.get(n - 1));

        }
       System.out.println("P " + P.stringRepresentation());
       System.out.println("PAlt "+gs.commit(as).add(hs.commit(bs)).add(u.multiply(as.innerPoduct(bs))).stringRepresentation());
        T PPrime = L.multiply(xSquare).add(R.multiply(xInvSquare)).add(P);
        VectorBase<T> basePrime = new VectorBase<>(gPrime, hPrime, u);
        System.out.println("c "+ aPrime.innerPoduct(bPrime).mod(q));
        System.out.println("calt "+asLeft.innerPoduct(bsRight).multiply(xSquare).add(asRight.innerPoduct(bsLeft).multiply(xInvSquare)).add(as.innerPoduct(bs)).mod(q));
        System.out.println("X " + x);
        System.out.println("Xinv " + xInv);
        System.out.println("C " +PPrime.stringRepresentation());
        T pPrimeAlt = gPrime.commit(aPrime).add(hPrime.commit(bPrime).add(u.multiply(aPrime.innerPoduct(bPrime))));
        System.out.println("C alt" + pPrimeAlt);
        System.out.println(PPrime.equals(pPrimeAlt));
        return generateProof(basePrime, PPrime, aPrime, bPrime, ls, rs);
    }

}
