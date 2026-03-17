package no.softmuffin.crypto.sign;

// TODO - Think how to do this better?
public interface PqcSign {
    String algorithmName();
    byte[] sign(byte[] data);
    boolean verify(byte[] data, byte[] signature);
}
