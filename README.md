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

## partialtofulltgt.py

This tool takes a partial TGT from either a ccache (extracted using loadticket.py) or from a `.prt` file directly, and upgrades this to a full TGT. It will also recover the NT hash of this account via the KRB KEY LIST feature.

Example:

```
python partialtofulltgt.py HYBRID.IMINYOUR.CLOUD/hybrid -f roadtx.prt
```

## modifyuser.py

This tool uses the Synchronization API used by Azure AD Connect to modify accounts. This API supports more properties than the MS Graph or AAD Graph even with the same privileges. You'll need a Global Admin account or Sync account token to use this tool.

Example:

```
roadtx gettokens -u myadminuser@mytenant.com -p somepassword -r aadgraph
python modifyuser.py -a aec/Es9Xe0CmrjyOUxUH/g== -sid S-1-5-21-1414223725-1888795230-1473887622-1108 -sam newsamname
```

## krbsso.py

This tool takes a Kerberos Service Ticket from a ccache file and converts this into the SPNEGO structure that can be used to authenticate in HTTP flows needed for the Azure AD Seamless Single Sign On feature. Note that since this is time based authentication, the resulting blob should be used within a few minutes of it being requested, and your clock should be set correctly.

Example, requiring a service ticket to be in the `test.ccache` file, which you could request or generate with impacket:

```
krbsso.py test.ccache
```