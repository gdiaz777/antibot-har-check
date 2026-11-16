#!/usr/bin/env bash
# Deploy the Anti-Bot lab web application to an Azure VM with a public IP.
#
#   ./lab/deploy.sh            create (or reuse) everything
#   ./lab/deploy.sh destroy    delete the whole resource group
#
# Settings can be overridden with environment variables (see below).
# Credentials are generated once and kept in ~/.config/antibot-lab/.
set -euo pipefail

RG=${RG:-rg-antibot-lab}
LOCATION=${LOCATION:-westeurope}
VM=${VM:-vm-antibot-lab}
SIZE=${SIZE:-Standard_B2ats_v2}
DNS_LABEL=${DNS_LABEL:-antibot-lab-$(az account show --query id -o tsv | cut -c1-8)}
SITE_DOMAIN=${SITE_DOMAIN:-test.gdiazcheckpoint.net}
SSH_SOURCE=${SSH_SOURCE:-$(curl -s https://api.ipify.org)/32}
CONF_DIR="$HOME/.config/antibot-lab"
SSH_KEY="$CONF_DIR/id_ed25519"
HERE=$(cd "$(dirname "$0")" && pwd)

if [[ ${1:-} == destroy ]]; then
    az group delete -n "$RG" --yes
    exit 0
fi

mkdir -p "$CONF_DIR" && chmod 700 "$CONF_DIR"
[[ -f $SSH_KEY ]] || ssh-keygen -q -t ed25519 -N '' -C antibot-lab -f "$SSH_KEY"
if [[ ! -f $CONF_DIR/credentials ]]; then
    umask 077
    cat > "$CONF_DIR/credentials" <<EOF
LAB_USER=demo
LAB_PASSWORD=$(python3 -c 'import secrets; print(secrets.token_urlsafe(12))')
LAB_SECRET=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
EOF
fi

CLOUD_INIT=$(mktemp)
trap 'rm -f "$CLOUD_INIT"' EXIT
cat > "$CLOUD_INIT" <<EOF
#cloud-config
package_update: true
packages: [nginx, python3-flask, gunicorn]
write_files:
  - path: /opt/antibot-lab/app.py
    encoding: b64
    content: $(base64 -w0 "$HERE/app.py")
  - path: /etc/antibot-lab.env
    permissions: '0600'
    encoding: b64
    content: $(base64 -w0 "$CONF_DIR/credentials")
  - path: /etc/systemd/system/antibot-lab.service
    content: |
      [Unit]
      Description=Anti-Bot lab web application
      After=network.target
      [Service]
      EnvironmentFile=/etc/antibot-lab.env
      WorkingDirectory=/opt/antibot-lab
      ExecStart=/usr/bin/gunicorn -w 2 -b 127.0.0.1:8000 app:app
      DynamicUser=yes
      Restart=always
      [Install]
      WantedBy=multi-user.target
  - path: /etc/nginx/snippets/antibot-lab-proxy.conf
    content: |
      location / {
          proxy_pass http://127.0.0.1:8000;
          proxy_set_header Host \$host;
          proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
          proxy_set_header X-Forwarded-Proto \$scheme;
      }
  - path: /etc/nginx/sites-available/default
    content: |
      server {
          listen 80 default_server;
          server_name _;
          include snippets/antibot-lab-proxy.conf;
      }
      server {
          listen 443 ssl default_server;
          server_name $SITE_DOMAIN;
          ssl_certificate     /etc/ssl/antibot-lab/cert.pem;
          ssl_certificate_key /etc/ssl/antibot-lab/key.pem;
          ssl_protocols TLSv1.2 TLSv1.3;
          include snippets/antibot-lab-proxy.conf;
      }
runcmd:
  - mkdir -p /etc/ssl/antibot-lab
  - >-
    openssl req -x509 -newkey rsa:2048 -nodes -days 825
    -keyout /etc/ssl/antibot-lab/key.pem -out /etc/ssl/antibot-lab/cert.pem
    -subj "/CN=$SITE_DOMAIN"
    -addext "subjectAltName=DNS:$SITE_DOMAIN,DNS:$DNS_LABEL.$LOCATION.cloudapp.azure.com"
  - chmod 600 /etc/ssl/antibot-lab/key.pem
  - systemctl daemon-reload
  - systemctl enable --now antibot-lab
  - systemctl restart nginx
EOF

TAGS="owner=gdiaz purpose=antibot-lab"
az group create -n "$RG" -l "$LOCATION" --tags $TAGS -o none

az network nsg create -g "$RG" -n "$VM-nsg" --tags $TAGS -o none
az network nsg rule create -g "$RG" --nsg-name "$VM-nsg" -n ssh-admin \
    --priority 100 --protocol Tcp --destination-port-ranges 22 \
    --source-address-prefixes "$SSH_SOURCE" -o none
# HTTP/HTTPS must be reachable by the WAF SaaS. Restrict them to the Check
# Point egress ranges once the asset is up.
az network nsg rule create -g "$RG" --nsg-name "$VM-nsg" -n http \
    --priority 110 --protocol Tcp --destination-port-ranges 80 \
    --source-address-prefixes Internet -o none
az network nsg rule create -g "$RG" --nsg-name "$VM-nsg" -n https \
    --priority 120 --protocol Tcp --destination-port-ranges 443 \
    --source-address-prefixes Internet -o none

if ! az vm show -g "$RG" -n "$VM" -o none 2>/dev/null; then
    az vm create -g "$RG" -n "$VM" -l "$LOCATION" --size "$SIZE" \
        --image Ubuntu2404 --admin-username azureuser \
        --ssh-key-values "$SSH_KEY.pub" \
        --public-ip-sku Standard --public-ip-address-allocation static \
        --public-ip-address-dns-name "$DNS_LABEL" \
        --nsg "$VM-nsg" --custom-data "$CLOUD_INIT" \
        --tags $TAGS -o none
fi

IP=$(az vm show -d -g "$RG" -n "$VM" --query publicIps -o tsv)
FQDN=$(az vm show -d -g "$RG" -n "$VM" --query fqdns -o tsv)
echo "Public IP : $IP"
echo "FQDN      : $FQDN"
echo "URL       : https://$SITE_DOMAIN/login  (self-signed; DNS -> $IP)"
echo "SSH       : ssh -i $SSH_KEY azureuser@$IP"
echo "Creds     : $CONF_DIR/credentials"
