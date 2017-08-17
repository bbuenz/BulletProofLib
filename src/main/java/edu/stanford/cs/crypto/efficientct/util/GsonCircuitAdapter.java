package edu.stanford.cs.crypto.efficientct.util;

import com.google.gson.*;
import cyclops.collections.immutable.VectorX;
import edu.stanford.cs.crypto.efficientct.circuit.ArithmeticCircuit;
import edu.stanford.cs.crypto.efficientct.linearalgebra.FieldVector;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.math.BigInteger;

public class GsonCircuitAdapter implements JsonSerializer<ArithmeticCircuit>, JsonDeserializer<ArithmeticCircuit> {
    @Override
    public ArithmeticCircuit deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
        JsonObject object = json.getAsJsonObject();
        VectorX<FieldVector> lWeights = context.deserialize(object.get("lWeights"), VectorX.class);
        VectorX<FieldVector> rWeights = context.deserialize(object.get("rWeights"), VectorX.class);
        VectorX<FieldVector> oWeights = context.deserialize(object.get("oWeights"), VectorX.class);
        VectorX<FieldVector> vWeights = context.deserialize(object.get("vWeights"), VectorX.class);
        VectorX<BigInteger> lWeights =    context.deserialize(object.get("cs"), VectorX.class);
        context.deserialize(object.get("commitments"), VectorX.class);

    }

    @Override
    public JsonElement serialize(ArithmeticCircuit src, Type typeOfSrc, JsonSerializationContext context) {
        JsonElement lWeights = context.serialize(src.getlWeights());
        JsonElement rWeights = context.serialize(src.getrWeights());
        JsonElement oWeights = context.serialize(src.getoWeights());
        JsonElement vWeights = context.serialize(src.getCommitmentWeights());
        JsonElement cs = context.serialize(src.getCs());
        JsonElement commitments = context.serialize(src.getCommitments().getVector());

        JsonObject object = new JsonObject();
        object.add("lWeights", lWeights);
        object.add("rWeights", rWeights);
        object.add("oWeights", oWeights);
        object.add("vWeights", vWeights);
        object.add("cs", cs);
        object.add("commitments", commitments);

        return object;
    }
}
