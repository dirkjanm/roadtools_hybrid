# Hybrid authentication tools for ROADtools

This repository contains some complementary utilities for ROADtools that interact with on-premises Active Directory configured as a hybrid setup.

# Install

Clone the repository locally, then use `pip install -r requirements.txt` to install the requirements. If using Python 3.10, you may also need the `pycryptodome` package.

# Tools

## setcert.py

This tool finds out the Hybrid join configuration in Active Directory and uses the supplied computer account identity to register a certificate on this computer account. You should already have created (or taken over) this computer account previously, for example using impackets `addcomputer.py`. After configuring the certificate on the computer account, you can use `roadtx` to register the Hybrid device in Azure AD using the generated certificate and private key. Note that due to sync delays it may take up to half an hour for the certificate to be synced to Azure AD. 

Example:

```
python setcert.py 10.0.1.1 -t 'DESKTOP-NAME$' -u 'domain\DESKTOP-NAME$' -p computerpasswordhere
```

## loadticket.py

This tool can extract a partial Kerberos TGT from a roadtx `.prt` file and save it in a ccache for use with tools such as impacket. Only useful if the `.tgt` file actually includes a TGT for on-prem.