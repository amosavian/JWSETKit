# Security Guidelines and Algorithm Selection

Proper selection of cryptographic algorithms is critical for the security of your JWT/JWS/JWE implementations. This guide provides recommendations to help you make informed decisions.

## Algorithm Selection Guide

### Signature Algorithms

| Algorithm | Security Level | Comments | Recommendation |
|-----------|---------------|----------|----------------|
| HS256 | Medium | Requires secure key management on both sides | Good for backend-to-backend communication |
| HS384/HS512 | Higher | Increased resistance to brute force | Preferred over HS256 when possible |
| RS256 | High | Most widely supported asymmetric algorithm | Good general choice for most applications |
| RS384/RS512 | Higher | Increased resistance to attacks | Preferred over RS256 for sensitive data |
| PS256/PS384/PS512 | High | More resistant to certain attacks than RS* | Preferred when clients support it |
| ES256 | High | Faster and smaller signatures than RSA | Excellent for mobile applications |
| ES384/ES512 | Higher | Increased resistance to quantum attacks | Recommended for long-term security |
| EdDSA | Very High | Modern, fast, secure | Best choice when available |

### Key Encryption Algorithms

| Algorithm | Security Level | Comments | Recommendation |
|-----------|---------------|----------|----------------|
| RSA1_5 | Low | Legacy, vulnerable to padding oracle attacks | Avoid if possible |
| RSA-OAEP | Medium | Better than RSA1_5 | Acceptable |
| RSA-OAEP-256 | High | Modern RSA padding | Recommended for RSA encryption |
| A128KW/A192KW/A256KW | High | AES Key Wrap, secure | Good for symmetric key operations |
| ECDH-ES | Very High | Forward secrecy | Excellent when supported |
| PBES2-* | High | Password-based | Good for key derivation from passwords |

### Content Encryption Algorithms

| Algorithm | Security Level | Comments | Recommendation |
|-----------|---------------|----------|----------------|
| A128CBC-HS256 | Medium | CBC mode requires careful implementation | Acceptable |
| A256CBC-HS512 | High | Stronger variant | Better than A128CBC-HS256 |
| A128GCM/A256GCM | Very High | Modern authenticated encryption | Recommended for most use cases |

## Best Practices

### Key Management

1. **Key Rotation**: Regularly rotate your signing keys to limit the impact of key compromise
2. **Key Size**: Use at least 2048 bits for RSA keys and 256 bits for elliptic curve keys
3. **Key Storage**: Store private keys securely using a hardware security module (HSM) or secure key vault
4. **Multiple Keys**: Maintain multiple keys to facilitate smooth key rotation

### JWT/JWS Implementation

1. **Token Expiry**: Always set reasonable expiration times via the `exp` claim
2. **Validate All Fields**: Verify all relevant claims and not just the signature
3. **Audience Validation**: Always validate the `aud` claim to prevent token reuse
4. **Algorithm Enforcement**: Explicitly check the `alg` header to prevent algorithm switching attacks

### Common Pitfalls to Avoid

1. **Algorithm Confusion**: Do not allow the algorithm to be switched from asymmetric to symmetric (e.g., from RS256 to HS256)
2. **None Algorithm**: Always reject tokens with the "none" algorithm
3. **Key Disclosure**: Never include sensitive key material in the token itself
4. **Signature Verification**: Always verify the signature before trusting any claims

## Algorithm Selection Decision Tree

For selecting a suitable signature algorithm:

1. **If** client and server are trusted and can share secrets securely:
   - Use HMAC-based algorithms (HS256, HS384, HS512)
   
2. **If** you need public/private key separation:
   - **If** performance and token size are concerns:
     - Use Elliptic Curve algorithms (ES256, ES384, ES512, EdDSA)
   - **If** maximum compatibility is needed:
     - Use RSA-based algorithms (RS256, RS384, RS512)
   - **If** enhanced security is needed:
     - Use RSA-PSS algorithms (PS256, PS384, PS512) or EdDSA
     
3. **For** encryption:
   - **If** you need maximum security:
     - Use ECDH-ES for key management with A256GCM for content
   - **If** compatibility is a concern:
     - Use RSA-OAEP-256 for key management with A256CBC-HS512 for content

## References

- [RFC 7518 - JSON Web Algorithms](https://www.rfc-editor.org/rfc/rfc7518.html)
- [NIST Guidelines for Cryptographic Algorithm and Key Size Selection](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf)
- [JWT Best Practices - RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html)

## Topics

### Security References

- ``SECURITY``
- <doc:3-Cryptography>
