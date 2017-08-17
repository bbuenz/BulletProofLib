package edu.stanford.cs.crypto.efficientct.util;

import com.google.gson.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.Arrays;

public class PolyMorphismAdapter<T> implements JsonSerializer<T>, JsonDeserializer<T> {
    public static final Logger LOGGER = LoggerFactory.getLogger(PolyMorphismAdapter.class);
    public static final String CLASSNAME = "CLASSNAME";
    public static final String INSTANCE = "INSTANCE";
    public static final String TYPE = "TYPE";

    @Override
    public JsonObject serialize(T src, Type typeOfSrc, JsonSerializationContext context) {
        JsonObject retValue = new JsonObject();
        String className = src.getClass().getCanonicalName();
        retValue.addProperty(CLASSNAME, className);
        JsonElement elem = context.serialize(src, src.getClass());
        retValue.add(INSTANCE, elem);
        if (typeOfSrc instanceof ParameterizedType) {
            Type[] typeArguments = ((ParameterizedType) typeOfSrc).getActualTypeArguments();
            JsonArray array = new JsonArray();
            Arrays.stream(typeArguments).map(Type::getTypeName).map(JsonPrimitive::new).forEach(array::add);
            retValue.add(TYPE, array);
        }
        return retValue;
    }

    @Override
    public T deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
        JsonObject jsonObject = json.getAsJsonObject();

        JsonPrimitive prim = (JsonPrimitive) jsonObject.get(CLASSNAME);
        String className = prim.getAsString();
        Class<?> clazz;
        try {
            clazz = Class.forName(className);
        } catch (ClassNotFoundException e) {
            LOGGER.warn("Failed to desieralize class " + className, e);
            throw new JsonParseException(e.getMessage());
        }
        Type type;
        if (jsonObject.has(TYPE)) {
            type = createParameterizedType(jsonObject, clazz);
        } else {
            type = clazz;
        }
        return context.deserialize(jsonObject.get(INSTANCE), type);
    }

    private Type createParameterizedType(JsonObject jsonObject, Class<?> clazz) {
        Type type;
        type = new ParameterizedType() {
            @Override
            public Type getRawType() {
                return clazz;
            }

            @Override
            public Type getOwnerType() {
                return null;
            }

            @Override
            public Type[] getActualTypeArguments() {
                JsonArray array = jsonObject.getAsJsonArray(TYPE);
                Type[] types = new Type[array.size()];
                for (int i = 0; i < array.size(); ++i) {
                    String clazzName = array.get(i).getAsString();
                    try {
                        types[i] = Class.forName(clazzName);
                    } catch (ClassNotFoundException e) {
                        LOGGER.warn("Failed to deserialize type " + clazzName, e);
                        throw new IllegalArgumentException(e);
                    }
                }
                return types;
            }
        };
        return type;
    }
}