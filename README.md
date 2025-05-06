# PAN-OS Certificate Automation with Certbot 

This Python script automates the renewal, import, and deployment of Let's Encrypt SSL certificates (via Certbot) to Palo Alto Networks firewalls for use with GlobalProtect and SSL/TLS profiles.

## Features

* Automatically checks for expiring production certificates.
* Renews certificates with Certbot using Route53 DNS validation.
* Verifies certificate fingerprint, issuer, and expiration details.
* Uploads certificate and private key to PAN-OS using the XML API.
* Binds new certificate to the appropriate SSL/TLS profile.
* Commits and verifies configuration on PAN-OS.
* Supports both staging and production Let's Encrypt endpoints.

---

## Usage

### 1. Install Dependencies

Make sure the following are installed:

* Python 3.6+

* `certbot` with Route53 plugin

* Python packages:

  ```bash
  pip install requests pan-python
  ```

* OpenSSL command-line tools

* Certbot DNS plugin:

  ```bash
  sudo apt install python3-certbot-dns-route53
  ```

---

### 2. Environment Setup

This script expects two credential files to be present under a `credentials/` folder relative to the script:

#### a. `credentials/certbot_aws_credentials.env`

Used by Certbot for Route53 DNS validation.

```env
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
```

Certbot will automatically read these values via `os.environ`.

> 🔐 **DO NOT COMMIT** this file to GitHub. Add `credentials/` to `.gitignore`.

#### b. `credentials/pan_credentials.env`

Used to authenticate to your PAN-OS XML API.

```env
PAN_IP=192.0.2.1
PAN_API_KEY=your_pan_api_key
```

---

### 3. Configurable Parameters

Located in the config section near the top of the script:

```python
DOMAIN       = 'vpn.yourdomain.com'      # Domain for certificate
SSL_PROFILE  = DOMAIN                    # SSL/TLS profile name on PAN
DAYS_BEFORE  = 15                        # Days before expiry to renew
EMAIL        = 'admin@yourdomain.com'    # Let's Encrypt registration
USE_STAGING  = False                     # Toggle staging certs
PAN_COMMIT_SLEEP_DURATION = 120          # Seconds to wait after commit
```

---

### 4. Running the Script

```bash
sudo -E python3 automate_cert_pan.py
```

* The `-E` ensures Certbot inherits your environment for AWS keys.
* Run with elevated privileges so `certbot` can access `/etc/letsencrypt`.

---

## Output Example

The script will print:

* Certificate issuer/fingerprint details
* Whether the certificate needs to be renewed
* Import/commit status to PAN-OS
* Post-commit verification with updated PAN certificate details

---

## GitHub Considerations

### 🔐 Secure Your Repository

1. Add `credentials/` to `.gitignore`:

```
credentials/
*.env
```

2. Never upload API keys or AWS secrets to version control.

### ✅ Recommended GitHub Usage

* Keep the main script in version control.
* Store secrets securely (e.g., `.env` files on the server or use AWS Secrets Manager if wrapping in Lambda).
* If using GitHub Actions, consider storing secrets in GitHub Secrets and injecting via `env:`.

---

## PAN API Key Setup

To generate an API key for PAN-OS:

1. **Create a dedicated admin user** on the firewall or Panorama.

   * Role should include XML API access and privilege to import certificates and commit.

2. **Log in to the web UI** of the firewall and access:

   ```
   https://<FIREWALL_IP>/api/?type=keygen&user=<USERNAME>&password=<PASSWORD>
   ```

3. The response will include an XML snippet like:

   ```xml
   <response status="success">
     <result>
       <key>APIKEYSTRINGGOESHERE</key>
     </result>
   </response>
   ```

4. Use that key in your `pan_credentials.env` file as `PAN_API_KEY`.

---

## Troubleshooting

* Ensure PAN XML API access is enabled.
* Verify `PAN_API_KEY` has full permissions.
* Certbot needs IAM permissions for:

  * `route53:ListHostedZones`
  * `route53:GetChange`
  * `route53:ChangeResourceRecordSets`

### Test PAN API Key in Command Line

```bash
curl -k "https://<FIREWALL_IP>/api/?type=op&cmd=<show><system><info></info></system></show>&key=<PAN_API_KEY>"
```

This should return system info from the firewall if the key is valid.

---

## License

MIT License
