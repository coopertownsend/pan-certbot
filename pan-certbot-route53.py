#!/usr/bin/env python3
import os
import subprocess
import datetime
import secrets
import string
import time
import tempfile
import base64
import urllib3
import xml.etree.ElementTree as ET
import requests
from pan.xapi import PanXapi

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── CONFIG ────────────────────────────────────────────────────────────
BASE_DIR      = os.path.dirname(__file__)
# AWS creds (for certbot DNS plugin)
AWS_CREDS = os.path.join(BASE_DIR, 'credentials', 'certbot_aws_credentials.env')
if os.path.exists(AWS_CREDS):
    with open(AWS_CREDS) as f:
        for line in f:
            if line.strip() and not line.startswith('#'):
                k,v = line.strip().split('=',1)
                os.environ[k] = v

# PAN creds
PAN_CREDS = os.path.join(BASE_DIR, 'credentials', 'pan_credentials.env')
if os.path.exists(PAN_CREDS):
    with open(PAN_CREDS) as f:
        for line in f:
            if line.strip() and not line.startswith('#'):
                k,v = line.strip().split('=',1)
                os.environ[k] = v

PAN_IP       = os.getenv('PAN_IP')
API_KEY      = os.getenv('PAN_API_KEY')
DOMAIN       = 'vpn.intragreat.com'
SSL_PROFILE  = DOMAIN
CERT_PATH    = f'/etc/letsencrypt/live/{DOMAIN}/fullchain.pem'
KEY_PATH     = f'/etc/letsencrypt/live/{DOMAIN}/privkey.pem'
ARCHIVE_DIR  = f'/etc/letsencrypt/archive/{DOMAIN}'
DAYS_BEFORE  = 15
DNS_PROVIDER = '--dns-route53'
EMAIL        = 'admin@yourdomain.com'
USE_STAGING  = False    # toggle staging vs production
PAN_COMMIT_SLEEP_DURATION = 120 # Adjust to PAN commit time in seconds
# ────────────────────────────────────────────────────────────────────────

def generate_passphrase(n=24):
    return ''.join(secrets.choice(string.ascii_letters+string.digits) for _ in range(n))

def print_cert_details(path,label):
    print(f"\n=== {label} ({path}) ===")
    out = subprocess.check_output([
        "openssl","x509","-in",path,"-noout",
        "-fingerprint","-subject","-issuer","-dates"
    ]).decode().strip()
    print(out)

def cert_fingerprint_sha256(path):
    out = subprocess.check_output([
        "openssl","x509","-in",path,"-noout","-fingerprint","-sha256"
    ]).decode().strip()
    return out.split("=",1)[1].strip()

def local_cert_issuer(path):
    out = subprocess.check_output([
        "openssl","x509","-noout","-issuer","-in",path
    ]).decode().strip()
    return out.split("=",1)[1].strip() if out.startswith("issuer=") else out

def local_cert_expiry(path):
    out = subprocess.check_output([
        "openssl","x509","-enddate","-noout","-in",path
    ]).decode().strip().split('=',1)[1]
    return datetime.datetime.strptime(out,'%b %d %H:%M:%S %Y %Z')

def versioned_name(dt):
    return f"{DOMAIN}-{dt.strftime('%Y%m%d%H%M%S')}"

def find_existing_production_cert():
    if not os.path.isdir(ARCHIVE_DIR):
        return None, None
    fulls = sorted(f for f in os.listdir(ARCHIVE_DIR)
                   if f.startswith("fullchain") and f.endswith(".pem"))
    for fname in reversed(fulls):
        certf = os.path.join(ARCHIVE_DIR, fname)
        issuer = local_cert_issuer(certf)
        if "STAGING" not in issuer:
            keyf = certf.replace("fullchain","privkey")
            if os.path.exists(keyf):
                return certf, keyf
    return None, None

def fetch_pan_cert_file(cert_name):
    params = {
        'type':'export','category':'certificate',
        'certificate-name':cert_name,
        'output-format':'pem','format':'pem',
        'include-key':'no','key':API_KEY
    }
    r = requests.get(f"https://{PAN_IP}/api/", params=params, verify=False)
    r.raise_for_status()
    body = r.text.strip()
    if body.startswith("-----BEGIN CERTIFICATE-----"):
        data = body.encode()
    else:
        root = ET.fromstring(body)
        data = base64.b64decode(root.findtext('.//output'))
    tf = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    tf.write(data); tf.close()
    return tf.name

def pan_get_text(xapi, xpath, tag):
    xapi.get(xpath=xpath)
    xml = xapi.xml_result()
    if not xml or '<result/>' in xml:
        return None
    return ET.fromstring(xml).findtext(f'.//{tag}')

def pan_cert_expiry(xapi, name):
    txt = pan_get_text(xapi,
        f"/config/shared/certificate/entry[@name='{name}']",
        'not-valid-after'
    )
    if not txt:
        return None
    return datetime.datetime.strptime(txt,'%b %d %H:%M:%S %Y GMT')

def run_certbot(staging=False):
    cmd = ["certbot","certonly"]
    if staging:
        cmd += ["--test-cert","--break-my-certs"]
    cmd += [DNS_PROVIDER,"-d",DOMAIN,
            "--email",EMAIL,"--agree-tos",
            "--non-interactive","--force-renewal"]
    print("[INFO] Running Certbot:", " ".join(cmd))
    subprocess.run(cmd, check=True)

def import_to_pan(name, passp, certf, keyf):
    for cat, extra, path in (
      ("certificate", {}, certf),
      ("private-key", {"passphrase": passp}, keyf)
    ):
        params = {
            'type':'import','category':cat,
            'certificate-name':name,'format':'pem',
            'key':API_KEY, **extra
        }
        print(f"[INFO] Importing {cat} → '{name}'")
        r = requests.post(f"https://{PAN_IP}/api/",
                          params=params,
                          files={'file': open(path,'rb')},
                          verify=False)
        print(r.text)

def main():
    print_cert_details(CERT_PATH, "CERTBOT BEFORE")
    issuer = local_cert_issuer(CERT_PATH)
    print("[INFO] Certbot live cert issuer:", issuer)

    if "STAGING" in issuer:
        cf, kf = find_existing_production_cert()
        if cf and kf:
            print_cert_details(cf, "CERTBOT PROD BEFORE")
            prod_fp = cert_fingerprint_sha256(cf)
            print(f"[INFO] CERTBOT PROD SHA256 Fingerprint: {prod_fp}")
        else:
            print("[WARN] No production cert found in archive to check.")

    print("[INFO] Connecting to PAN…")
    xapi = PanXapi(hostname=PAN_IP, api_key=API_KEY, timeout=30)

    base = ("/config/devices/entry[@name='localhost.localdomain']"
            "/vsys/entry[@name='vsys1']/global-protect")
    portal_xp  = base + f"/global-protect-portal/entry[@name='{DOMAIN}']"
    gateway_xp = base + f"/global-protect-gateway/entry[@name='{DOMAIN}']"

    prof_portal = pan_get_text(xapi, portal_xp, 'ssl-tls-service-profile')
    prof_gate   = pan_get_text(xapi, gateway_xp, 'ssl-tls-service-profile')
    prof = prof_portal or prof_gate
    print(f"[INFO] GP SSL profile: '{prof}'")
    if not prof:
        print("[ERROR] no portal/gateway profile found")
        return

    pan_cert = pan_get_text(xapi,
        f"/config/shared/ssl-tls-service-profile/entry[@name='{prof}']",
        'certificate'
    )
    pan_exp = pan_cert and pan_cert_expiry(xapi, pan_cert)
    print(f"[INFO] PAN using cert '{pan_cert}'", end='')
    print(f", expires {pan_exp}" if pan_exp else "")

    pan_fp = None
    if pan_cert:
        tmp = fetch_pan_cert_file(pan_cert)
        print_cert_details(tmp, "PAN BEFORE")
        pan_fp = cert_fingerprint_sha256(tmp)
        print(f"[INFO] PAN SHA256 Fingerprint: {pan_fp}")
        os.unlink(tmp)

    if USE_STAGING:
        run_certbot(staging=True)
        cert_file, key_file = CERT_PATH, KEY_PATH
        local_dt = local_cert_expiry(CERT_PATH)
        local_fp = cert_fingerprint_sha256(cert_file)
    else:
        cf, kf = find_existing_production_cert()
        if cf and kf:
            prod_dt = local_cert_expiry(cf)
            prod_fp = cert_fingerprint_sha256(cf)
            prod_days = (prod_dt - datetime.datetime.utcnow()).days
        else:
            prod_dt = prod_fp = prod_days = None

        live_fp = cert_fingerprint_sha256(CERT_PATH)
        live_dt = local_cert_expiry(CERT_PATH)

        if prod_fp is None:
            should_renew = True
            print("[INFO] No production archive found; will renew.")
        elif "Let's Encrypt" not in issuer:
            should_renew = True
            print("[INFO] Live cert is from staging; will renew.")
        elif prod_days is not None and prod_days <= DAYS_BEFORE:
            should_renew = True
            print(f"[INFO] Production cert expires in {prod_days} days ≤ threshold; will renew.")
        else:
            should_renew = False
            print(f"[INFO] Live cert is valid and from production. {prod_days} days left — no renewal.")

        if should_renew:
            pre_fingerprint = live_fp
            pre_expiry = live_dt
            try:
                run_certbot(staging=False)
            except subprocess.CalledProcessError:
                print("[WARN] Certbot renewal failed. Checking if cert was still updated.")
            post_fingerprint = cert_fingerprint_sha256(CERT_PATH)
            post_expiry = local_cert_expiry(CERT_PATH)

            if pre_fingerprint != post_fingerprint or (prod_dt and post_expiry > prod_dt):
                cert_file, key_file = CERT_PATH, KEY_PATH
                local_dt = post_expiry
                local_fp = post_fingerprint
                print("[INFO] Cert changed or newer despite Certbot error — using updated cert.")
            elif cf and kf:
                cert_file, key_file = cf, kf
                local_dt = prod_dt
                local_fp = prod_fp
                print("[WARN] Renewal failed; using last archived production cert.")
            else:
                cert_file, key_file = CERT_PATH, KEY_PATH
                local_dt = pre_expiry
                local_fp = pre_fingerprint
                print("[WARN] Renewal failed and no archive; using live cert.")
        else:

            if live_dt and prod_dt and live_dt > prod_dt:
                print("[INFO] Live cert is newer than archived production cert — using live.")
                cert_file, key_file = CERT_PATH, KEY_PATH
                local_dt = live_dt
                local_fp = live_fp
            else:
                print("[INFO] Using archived production cert.")
                cert_file, key_file = cf, kf
                local_dt = prod_dt
                local_fp = prod_fp


    local_name = versioned_name(local_dt)
    print(f"[INFO] Local cert version → '{local_name}', expires {local_dt}")

    if USE_STAGING:
        need = True
        print("[INFO] Staging mode: forcing cert replace on PAN.")
    else:
        if pan_fp is None:
            need = True
            print("[INFO] No cert on PAN – will import production cert.")
        elif pan_fp != local_fp:
            need = True
            print("[INFO] PAN cert differs from certbot prod/live cert – will import.")
        else:
            need = False
            print("[INFO] PAN already has the production cert – nothing to do.")

    if not need:
        return

    passp = generate_passphrase()
    import_to_pan(local_name, passp, cert_file, key_file)

    print(f"[INFO] Binding SSL profile '{prof}' → '{local_name}'")
    xapi.set(
      xpath=(f"/config/shared/ssl-tls-service-profile/entry"
             f"[@name='{prof}']"),
      element=f"<certificate>{local_name}</certificate>"
    )

    print("[INFO] Committing…")
    xapi.commit(cmd="<commit></commit>")

    print(f"[INFO] Sleeping {PAN_COMMIT_SLEEP_DURATION}s for commit to apply…")
    time.sleep(PAN_COMMIT_SLEEP_DURATION)

    new_cert = pan_get_text(xapi,
      f"/config/shared/ssl-tls-service-profile/entry[@name='{prof}']",
      'certificate'
    )
    print(f"[INFO] After commit, PAN now using '{new_cert}'")
    if new_cert:
        tmp2 = fetch_pan_cert_file(new_cert)
        print_cert_details(tmp2, "PAN AFTER")
        os.unlink(tmp2)

if __name__ == "__main__":
    main()

