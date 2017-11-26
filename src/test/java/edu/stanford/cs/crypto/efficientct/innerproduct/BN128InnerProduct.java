package edu.stanford.cs.crypto.efficientct.innerproduct;

import edu.stanford.cs.crypto.efficientct.circuit.groups.BN128Group;
import edu.stanford.cs.crypto.efficientct.circuit.groups.BouncyCastleECPoint;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.VectorBase;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Test;

import java.math.BigInteger;

public class BN128InnerProduct {
    @Test
    public void createInnerProductProof() {
        InnerProductProofSystem<BouncyCastleECPoint> system = new InnerProductProofSystem<>();
        BN128Group group = new BN128Group();
        VectorBase<BouncyCastleECPoint> base = system.generatePublicParams(32, group);
        base.getGs().getVector().map(BouncyCastleECPoint::getPoint).map(ECPoint::normalize).map(p -> "=EC.Point(0x" + p.getXCoord() + " , 0x" + p.getYCoord() + ");").zipWithIndex().map(t -> "garr[" + t.v2 + "]" + t.v1).printOut();
        base.getHs().getVector().map(BouncyCastleECPoint::getPoint).map(ECPoint::normalize).map(p -> "=EC.Point(0x" + p.getXCoord() + " , 0x" + p.getYCoord() + ");").zipWithIndex().map(t -> "harr[" + t.v2 + "]" + t.v1).printOut();
        System.out.println(base.getH());
        FieldVector as = FieldVector.pow(BigInteger.TWO, 32, group.groupOrder());
        //  System.out.println(as);
        FieldVector bs = FieldVector.pow(BigInteger.ONE, 32, group.groupOrder());
        //  System.out.println(bs);
        InnerProductWitness witness = new InnerProductWitness(as, bs);
        BouncyCastleECPoint point = base.commit(as, bs, as.innerPoduct(bs));
        InnerProductProof<BouncyCastleECPoint> productProof = system.getProver().generateProof(base, point, witness);
        productProof.getL().forEach(p -> System.out.println(p.stringRepresentation()));

        productProof.getR().forEach(p -> System.out.println(p.stringRepresentation()));
        System.out.println(productProof.getA().toString(16));
        System.out.println(productProof.getB().toString(16));
    }
}
