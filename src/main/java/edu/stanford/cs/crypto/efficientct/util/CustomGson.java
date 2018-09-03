package edu.stanford.cs.crypto.efficientct.util;

import com.google.gson.*;
import cyclops.collections.immutable.VectorX;
import cyclops.function.Monoid;
import edu.stanford.cs.crypto.efficientct.algebra.Secp256k1;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;
import edu.stanford.cs.crypto.efficientct.linearalgebra.GeneratorVector;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Base64;

import java.util.List;

public class CustomGson {
    private static final JsonSerializer<ECPoint> ecpointSerializer = (instance, typeOfT, context) -> new JsonPrimitive(Base64.toBase64String(instance.getEncoded(true)));
    private static final JsonDeserializer<ECPoint> ecPointJsonDeserializer = (json, typeOfT, context) -> ECConstants.BITCOIN_CURVE.decodePoint(Base64.decode(json.getAsString()));
    private static final JsonSerializer<VectorX> vectorXJsonSerializer = (instance, typeOfT, context) -> context.serialize(instance.toList());
    private static final JsonDeserializer<VectorX> vectorXJsonDeserializer = (json, typeOfT, context) -> VectorX.fromIterable(context.deserialize(json, List.class));
    private static final JsonSerializer<FieldVector> vectorJsonSerializer = (instance, typeOfT, context) -> context.serialize(instance.getVector());
    private static final JsonDeserializer<FieldVector> vectorJsonDeserializer = (json, typeOfT, context) -> FieldVector.from(context.deserialize(json, List.class), new Secp256k1().groupOrder());

    private CustomGson() {

    }

    public static Gson getGson() {

        GsonBuilder gsonBuilder = new GsonBuilder();

        gsonBuilder.registerTypeAdapter(ECPoint.class, ecpointSerializer);
        gsonBuilder.registerTypeAdapter(ECPoint.class, ecPointJsonDeserializer);
        gsonBuilder.registerTypeAdapter(VectorX.class, vectorXJsonDeserializer);
        gsonBuilder.registerTypeAdapter(VectorX.class, vectorXJsonSerializer);
        gsonBuilder.registerTypeAdapter(FieldVector.class, vectorJsonDeserializer);
        gsonBuilder.registerTypeAdapter(FieldVector.class, vectorJsonSerializer);
        gsonBuilder.registerTypeAdapter(Monoid.class, new PolyMorphismAdapter<Monoid>());
        gsonBuilder.registerTypeAdapter(GeneratorVector.class, new PolyMorphismAdapter<GeneratorVector>());

        return gsonBuilder.create();
    }
}
