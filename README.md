# pyhanko-google-kms
Google KSM Signer implementation for pyHanko
In order to sign PDFs using a Google KMS key, you need to do the following:
1. Create a key using `main.tf` or manually
2. Generate a CSR using the created signing key by using the `generate_csr.py` (work in progress, clean up required!)
3. Submit the CSR to a CA of your choice and receive a certificate
4. Signs PDFs using the Cloud KMS private key and the locally stored certificate (not implemented yet!)
5. 
