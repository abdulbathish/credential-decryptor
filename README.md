# MOSIP Credential Decryptor

Simple tool to decrypt MOSIP encrypted credentials.

## Quick Start

```bash
node decryptor-final.js -v
```

Default files needed:
- encrypted-data.txt (data to decrypt)
- partner.p12 (certificate included for testing)

Default password: `mosip123`

To use different password:
```bash
node decryptor-final.js -w your-password
```

Output goes to decrypted-output.txt

Note: Certificate included for testing purposes only. In real applications, never commit certificates to git!