# Trusted TPM Endorsement Key (EK) Root CA Certificates

Place trusted TPM manufacturer root CA certificates here (.crt, .pem, .der, .cer).
In production mode, tpm_quote.py will automatically load all certificates from this directory
and pin their SHA-256 fingerprints to authenticate genuine hardware TPM 2.0 endorsement key chains.