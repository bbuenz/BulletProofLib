package edu.stanford.cs.crypto.efficientct.innerproduct;

import edu.stanford.cs.crypto.efficientct.circuit.groups.BN128Group;
import edu.stanford.cs.crypto.efficientct.circuit.groups.BouncyCastleECPoint;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.VectorBase;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Test;

import java.math.BigInteger;
import java.util.stream.Collectors;

public class BN128InnerProduct {
    @Test
    public void createInnerProductProof() {
        InnerProductProofSystem<BouncyCastleECPoint> system = new InnerProductProofSystem<>();
        BN128Group group = new BN128Group();
        VectorBase<BouncyCastleECPoint> base = system.generatePublicParams(256, group);
        base.getGs().getVector().map(BouncyCastleECPoint::getPoint).map(ECPoint::normalize).map(p -> "=[0x" + p.getXCoord() + " , 0x" + p.getYCoord() + "];").zipWithIndex().map(t -> "garr[" + t.v2 + "]" + t.v1).printOut();
        base.getHs().getVector().map(BouncyCastleECPoint::getPoint).map(ECPoint::normalize).map(p -> "=[0x" + p.getXCoord() + " , 0x" + p.getYCoord() + "];").zipWithIndex().map(t -> "harr[" + t.v2 + "]" + t.v1).printOut();
        System.out.println(base.getH());
        FieldVector as = FieldVector.pow(BigInteger.TWO, 256, group.groupOrder());
        //  System.out.println(as);
        FieldVector bs = FieldVector.pow(BigInteger.ONE, 256, group.groupOrder());
        //  System.out.println(bs);
        InnerProductWitness witness = new InnerProductWitness(as, bs);
        BouncyCastleECPoint point = base.commit(as, bs, as.innerPoduct(bs));
        ECPoint pe=point.getPoint();
        System.out.println("c=EC.Point(0x" + pe.getXCoord() + " , 0x" + pe.getYCoord() + ")");
        BouncyCastleECPoint.addCount=0;
        BouncyCastleECPoint.expCount=0;
        InnerProductProof<BouncyCastleECPoint> productProof = system.getProver().generateProof(base, point, witness);
        System.out.println(BouncyCastleECPoint.addCount);
        System.out.println(BouncyCastleECPoint.expCount);
        System.out.println(productProof.getL().size());
        String lstring = "[" + productProof.getL().stream().map(BouncyCastleECPoint::getPoint).map(ECPoint::normalize).map(p -> "0x"+ p.getXCoord() + " , 0x" + p.getYCoord() ).collect(Collectors.joining(",")) + "]";
        System.out.println(lstring);
        System.out.println(productProof.getA().toString(16));
        System.out.println(productProof.getB().toString(16));
        System.out.println(pe.normalize());
        System.out.println(pe.normalize().negate());
    }
}
