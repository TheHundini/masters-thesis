package no.softmuffin.tls.profile;

import java.util.Set;

public record TlsRuntimeSupport(
        Set<String> configuredTlsGroups,
        boolean frodoKemPrimitiveAvailable,
        boolean frodoKemTlsGroupAvailable
) {
}
