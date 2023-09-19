# JSON Web Token (JWT)

Usage of JWT, Verifying and make new signatures.  

## Overview

JSON Web Token (JWT) is a compact, URL-safe means of representing
claims to be transferred between two parties.  

The claims in a JWT are encoded as a JSON object that is used as 
the payload of a JSON Web Signature (JWS) structure or as the 
plaintext of a JSON Web Encryption (JWE) structure, enabling the 
claims to be digitally signed or integrity protected with a Message
Authentication Code (MAC) and/or encrypted.

## Accessing Claims


## Validating JWT


### Verify Signature


### Verify Expiration


## Adding New Signature


## Topics

### JOSE Headers

- ``JOSEHeader``
- ``JoseHeaderJWSRegisteredParameters``

### JWT Claims

- ``JSONWebTokenClaims``
- ``JSONWebTokenClaimsRegisteredParameters``
- ``JSONWebTokenClaimsOAuthParameters``
- ``JSONWebTokenClaimsPublicOIDCStandardParameters``
- ``JSONWebTokenClaimsPublicOIDCAuthParameters``

### Signature

- ``JSONWebSignature``
