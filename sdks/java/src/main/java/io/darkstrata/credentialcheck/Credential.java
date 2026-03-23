package io.darkstrata.credentialcheck;

import java.util.Objects;

/**
 * Represents a credential pair (email and password) for batch checking.
 */
public class Credential {

    private final String email;
    private final String password;

    public Credential(String email, String password) {
        this.email = email;
        this.password = password;
    }

    public String getEmail() {
        return email;
    }

    public String getPassword() {
        return password;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Credential that = (Credential) o;
        return Objects.equals(email, that.email) && Objects.equals(password, that.password);
    }

    @Override
    public int hashCode() {
        return Objects.hash(email, password);
    }

    @Override
    public String toString() {
        return "Credential{email='" + email + "', password='[REDACTED]'}";
    }
}
