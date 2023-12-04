from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization, _serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import *
from cryptography.hazmat.primitives._asymmetric import AsymmetricPadding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

import hashlib

# Import the client library.
from google.cloud import kms

# The format is "projects/{project}/locations/{location}/keyRings/{key_ring}/cryptoKeys/{crypto_key}/cryptoKeyVersions/{crypto_key_version}"
key_version_name = "...you...key...path...here"

# Implements 'remote' RSAPrivateKey
# Only methods required for CSR generation are implemented
class RemoteRSAPrivateKey(RSAPrivateKey):

    # See https://cloud.google.com/kms/docs/retrieve-public-key#kms-get-public-key-python
    def public_key(self) -> RSAPublicKey:
        client = kms.KeyManagementServiceClient()

        public_key = client.get_public_key(request={"name": key_version_name})

        pem_bytes = bytes(public_key.pem, 'utf-8')
        return load_pem_public_key(pem_bytes, default_backend())

    # See https://cloud.google.com/kms/docs/create-validate-signatures
    def sign(self,
        data: bytes,
        padding: AsymmetricPadding,
        algorithm: typing.Union[asym_utils.Prehashed, hashes.HashAlgorithm],
    ) -> bytes:

        client = kms.KeyManagementServiceClient()

        hash_ = hashlib.sha256(data).digest()

        digest = {algorithm.name: hash_}

        sign_response = client.asymmetric_sign(
            request={
                "name": key_version_name,
                "digest": digest
            }
        )

        return sign_response.signature

    def decrypt(self, ciphertext: bytes, padding: AsymmetricPadding) -> bytes:
        raise NotImplementedError

    def key_size(self) -> int:
        raise NotImplementedError

    def private_numbers(self) -> RSAPrivateNumbers:
        raise NotImplementedError

    def private_bytes(
        self,
        encoding: _serialization.Encoding,
        format: _serialization.PrivateFormat,
        encryption_algorithm: _serialization.KeySerializationEncryption,
    ) -> bytes:
        raise NotImplementedError

private_key = RemoteRSAPrivateKey()

# Generate a CSR
# https://cryptography.io/en/latest/x509/tutorial/#creating-a-certificate-signing-request-csr
csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    # Provide various details about who we are.
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
    x509.NameAttribute(NameOID.COMMON_NAME, "mysite.com"),
])).add_extension(
    x509.SubjectAlternativeName([
        # Describe what sites we want this certificate for.
        x509.DNSName("mysite.com"),
        x509.DNSName("www.mysite.com"),
        x509.DNSName("subdomain.mysite.com"),
    ]),
    critical=False,
# Sign the CSR with our private key.
).sign(private_key, hashes.SHA256())

print(csr.public_bytes(serialization.Encoding.PEM))
