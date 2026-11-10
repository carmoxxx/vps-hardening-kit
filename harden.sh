#!/bin/bash
# Aplica na VPS um conjunto de medidas de segurança já auditado e corrigido
# em produção. Idempotente — pode rodar de novo depois de editar config.env.
#
# Uso:
#   cp config.env.example config.env   # uma vez, e ajuste os valores
#   sudo ./harden.sh
#
# Seções aplicadas: SSH, UFW, fail2ban, unattended-upgrades e (se houver
# Docker) a correção do vazamento de portas de container pelo UFW.

set -euo pipefail
cd "$(dirname "$0")"

if [ "$(id -u)" -ne 0 ]; then
  echo "Rode como root (sudo ./harden.sh)." >&2
  exit 1
fi

if [ ! -f config.env ]; then
  echo "Falta config.env — copie de config.env.example e ajuste antes de rodar." >&2
  exit 1
fi
# shellcheck source=config.env
source config.env

log() { echo; echo "== $* =="; }

# Validações que não mudam nada — rodam antes de qualquer alteração.
if command -v docker >/dev/null 2>&1; then
  # Com a interface errada a regra DROP do DOCKER-USER nunca casa: o script
  # "funciona", mas as portas de container continuam abertas sem aviso.
  DEFAULT_IFACE=$(ip -o route get 1.1.1.1 2>/dev/null | grep -o 'dev [^ ]*' | cut -d' ' -f2)
  if ! ip link show dev "$EXTERNAL_IFACE" >/dev/null 2>&1; then
    echo "ERRO: EXTERNAL_IFACE='$EXTERNAL_IFACE' não existe nesta VPS." >&2
    echo "A interface da rota padrão aqui é '${DEFAULT_IFACE:-?}' (ip -br link mostra todas)." >&2
    echo "Ajuste o config.env — nada foi alterado." >&2
    exit 1
  fi
  if [ -n "$DEFAULT_IFACE" ] && [ "$DEFAULT_IFACE" != "$EXTERNAL_IFACE" ]; then
    echo "AVISO: EXTERNAL_IFACE='$EXTERNAL_IFACE', mas a rota padrão sai por '$DEFAULT_IFACE'." >&2
    echo "Se '$DEFAULT_IFACE' é a interface pública, o filtro do Docker não vai pegar nada." >&2
  fi
fi

# ---------------------------------------------------------------------------
log "Pacotes base"
# ---------------------------------------------------------------------------
apt-get update -qq
apt-get install -y -qq ufw fail2ban unattended-upgrades >/dev/null
echo "ufw, fail2ban e unattended-upgrades instalados/confirmados."

# ---------------------------------------------------------------------------
log "SSH"
# ---------------------------------------------------------------------------
SSHD_CONFIG=/etc/ssh/sshd_config
ADMIN_HOME=$(getent passwd "$ADMIN_USER" | cut -d: -f6 || true)

if [ -z "$ADMIN_HOME" ]; then
  echo "ERRO: usuário '$ADMIN_USER' não existe nesta VPS. Crie o usuário e" >&2
  echo "instale a chave SSH dele ANTES de rodar este script." >&2
  exit 1
fi

if [ ! -s "$ADMIN_HOME/.ssh/authorized_keys" ]; then
  echo "ERRO: $ADMIN_HOME/.ssh/authorized_keys vazio ou inexistente." >&2
  echo "Não vou desligar autenticação por senha sem uma chave já instalada" >&2
  echo "— isso trancaria o acesso à VPS. Instale a chave primeiro." >&2
  exit 1
fi

cp -a "$SSHD_CONFIG" "${SSHD_CONFIG}.bak.$(date +%s)"

set_sshd_option() {
  local key="$1" val="$2"
  if grep -qE "^\s*#?\s*${key}\b" "$SSHD_CONFIG"; then
    sed -i -E "s|^\s*#?\s*${key}\b.*|${key} ${val}|" "$SSHD_CONFIG"
  else
    echo "${key} ${val}" >> "$SSHD_CONFIG"
  fi
}

SSHD_BACKUP="$(ls -t ${SSHD_CONFIG}.bak.* | head -1)"
SSHD_DROPIN=/etc/ssh/sshd_config.d/00-harden.conf

revert_sshd() {
  cp -a "$SSHD_BACKUP" "$SSHD_CONFIG"
  rm -f "$SSHD_DROPIN"
}

set_sshd_option Port "$SSH_PORT"
set_sshd_option PermitRootLogin no
set_sshd_option PasswordAuthentication no
set_sshd_option KbdInteractiveAuthentication no
set_sshd_option PubkeyAuthentication yes
set_sshd_option MaxAuthTries 3
set_sshd_option X11Forwarding no
set_sshd_option AllowUsers "$SSH_ALLOW_USERS"

# No sshd vale o PRIMEIRO valor encontrado para cada opção, e o Debian põe
# "Include /etc/ssh/sshd_config.d/*.conf" no topo do sshd_config. Um drop-in
# de terceiros (ex.: 50-cloud-init.conf com "PasswordAuthentication yes",
# comum em imagens de VPS) ganharia das linhas acima. Por isso gravamos as
# mesmas opções num drop-in "00-", que é lido antes de todos os outros.
if grep -qE '^\s*Include\s+/etc/ssh/sshd_config\.d/' "$SSHD_CONFIG"; then
  mkdir -p /etc/ssh/sshd_config.d
  cat > "$SSHD_DROPIN" <<EOF
# Gerado por harden.sh a partir de config.env — não editar à mão.
# Port fica só no sshd_config: é cumulativa (repetir abriria a porta duas vezes).
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
X11Forwarding no
AllowUsers ${SSH_ALLOW_USERS}
EOF
fi

if ! sshd -t; then
  echo "ERRO: sshd_config ficou inválido, revertendo e abortando." >&2
  revert_sshd
  exit 1
fi

# Confere a configuração EFETIVA (com todos os Includes resolvidos), não só
# o que escrevemos — é isso que pega um drop-in esquecido sobrescrevendo.
EFFECTIVE=$(sshd -T 2>/dev/null)
ssh_ok=1
for expect in "permitrootlogin no" "passwordauthentication no" \
              "kbdinteractiveauthentication no" "pubkeyauthentication yes" \
              "maxauthtries 3" "x11forwarding no"; do
  if ! grep -qxi "$expect" <<<"$EFFECTIVE"; then
    echo "ERRO: configuração efetiva do sshd não tem '$expect'." >&2
    ssh_ok=0
  fi
done
# Port e AllowUsers são cumulativas (somam entre arquivos), então exige-se o
# conjunto EXATO — uma "Port 22" ou um usuário extra em outro drop-in reprova.
eff_ports=$(grep -i '^port ' <<<"$EFFECTIVE" | awk '{print $2}' | sort -u | xargs)
if [ "$eff_ports" != "$SSH_PORT" ]; then
  echo "ERRO: portas efetivas do sshd são '$eff_ports' (esperado só '$SSH_PORT')." >&2
  ssh_ok=0
fi
eff_users=$(grep -i '^allowusers ' <<<"$EFFECTIVE" | cut -d' ' -f2- | tr ' ' '\n' | sed '/^$/d' | sort -u | xargs)
exp_users=$(tr ' ' '\n' <<<"$SSH_ALLOW_USERS" | sed '/^$/d' | sort -u | xargs)
if [ "$eff_users" != "$exp_users" ]; then
  echo "ERRO: AllowUsers efetivo é '$eff_users' (esperado '$exp_users')." >&2
  ssh_ok=0
fi
if [ "$ssh_ok" -ne 1 ]; then
  echo "Algum arquivo em /etc/ssh/sshd_config.d/ ou Match block está" >&2
  echo "sobrescrevendo as opções. Confira com: grep -r . /etc/ssh/sshd_config.d/" >&2
  echo "Revertendo e abortando (sshd não foi reiniciado)." >&2
  revert_sshd
  exit 1
fi
echo "Configuração efetiva do sshd conferida com 'sshd -T'."

# Alguns sistemas (Ubuntu 22.10+, imagens Debian ajustadas) usam socket
# activation: ssh.socket abre a porta e o "Port" do sshd_config é ignorado
# no bind — quem manda é o override do socket. Mas a unit ssh.socket EXISTE
# no Debian mesmo desabilitada; o que decide o modo é ela estar HABILITADA.
# Mexer no socket quando quem escuta é o ssh.service liga um segundo
# listener na mesma porta (e, numa 2ª execução, falha com "Job failed").
SSH_SOCKET_OVERRIDE=/etc/systemd/system/ssh.socket.d/override.conf
if [ "$(systemctl is-enabled ssh.socket 2>/dev/null)" = enabled ]; then
  echo "Socket activation em uso (ssh.socket habilitado) — aplicando override de porta."
  mkdir -p "$(dirname "$SSH_SOCKET_OVERRIDE")"
  cat > "$SSH_SOCKET_OVERRIDE" <<EOF
# Gerado por harden.sh a partir de config.env — não editar à mão.
[Socket]
ListenStream=
ListenStream=${SSH_PORT}
EOF
  systemctl daemon-reload
  # O sshd que segura o socket antigo precisa sair para a porta nova valer.
  # Sessões abertas sobrevivem (ficam em processos sshd-session próprios).
  systemctl stop ssh.service 2>/dev/null || true
  systemctl restart ssh.socket
else
  # Modo serviço: desfaz restos de uma execução antiga (override e socket
  # ativo sem estar habilitado) antes de reiniciar o sshd.
  if [ -f "$SSH_SOCKET_OVERRIDE" ]; then
    rm -f "$SSH_SOCKET_OVERRIDE"
    rmdir --ignore-fail-on-non-empty "$(dirname "$SSH_SOCKET_OVERRIDE")"
    systemctl daemon-reload
  fi
  if systemctl is-active --quiet ssh.socket 2>/dev/null; then
    systemctl stop ssh.socket
  fi
  systemctl restart ssh.service 2>/dev/null || systemctl restart sshd.service
fi

# Confere que o sshd está de fato escutando na porta nova.
listening=0
for _ in 1 2 3 4 5; do
  if ss -Htln "sport = :${SSH_PORT}" | grep -q .; then listening=1; break; fi
  sleep 1
done
if [ "$listening" -ne 1 ]; then
  echo "ERRO: nada escutando na porta ${SSH_PORT} depois do restart do SSH." >&2
  echo "NÃO feche esta sessão. Veja: systemctl status ssh.service ssh.socket" >&2
  exit 1
fi

ufw allow "${SSH_PORT}/tcp" comment 'ssh' >/dev/null

echo "sshd configurado para a porta ${SSH_PORT}."
echo "*** IMPORTANTE: abra uma NOVA sessão testando 'ssh -p ${SSH_PORT} ${ADMIN_USER}@<host>'"
echo "*** ANTES de fechar este terminal. ***"

# ---------------------------------------------------------------------------
log "UFW"
# ---------------------------------------------------------------------------
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
for rule in "${UFW_EXTRA_ALLOW[@]}"; do
  ufw allow "$rule" >/dev/null
done
ufw --force enable >/dev/null
ufw status verbose

# ---------------------------------------------------------------------------
log "fail2ban"
# ---------------------------------------------------------------------------
{
  echo "# Gerado por harden.sh a partir de config.env — não editar à mão."
  echo "[DEFAULT]"
  echo "bantime  = ${F2B_BANTIME}"
  echo "findtime = ${F2B_FINDTIME}"
  echo "maxretry = 5"
  echo "backend  = systemd"
  echo
  echo "[sshd]"
  echo "enabled  = true"
  # NUNCA usar "port = ssh": esse alias resolve pra 22 via /etc/services e,
  # com SSH em porta não-padrão, a regra de ban fica olhando pra porta
  # errada — o firewall "bane" mas não bloqueia nada de verdade. Já
  # aconteceu em produção; usar sempre a porta explícita.
  echo "port     = ${SSH_PORT}"
  echo "maxretry = ${F2B_MAXRETRY}"
  echo "bantime  = ${F2B_BANTIME}"

  if [ -d /etc/nginx ]; then
    # O nginx grava em arquivo, não no journal. Com backend=systemd (herdado
    # do [DEFAULT]) o fail2ban ignora o logpath e o jail nunca bane ninguém —
    # por isso estes jails forçam backend=auto.
    echo
    echo "[nginx-limit-req]"
    echo "enabled  = true"
    echo "backend  = auto"
    echo "port     = http,https"
    echo "logpath  = /var/log/nginx/error.log"
    echo "maxretry = 10"
    echo "findtime = 1m"
    echo "bantime  = 24h"
    echo
    echo "[nginx-botsearch]"
    echo "enabled  = true"
    echo "backend  = auto"
    echo "port     = http,https"
    echo "logpath  = /var/log/nginx/access.log"
    echo "maxretry = 5"
    echo "findtime = 1m"
    echo "bantime  = 24h"
  fi
} > /etc/fail2ban/jail.local

systemctl enable --now fail2ban >/dev/null
systemctl restart fail2ban
sleep 1
fail2ban-client status

# ---------------------------------------------------------------------------
log "unattended-upgrades"
# ---------------------------------------------------------------------------
systemctl enable --now unattended-upgrades >/dev/null
echo "unattended-upgrades habilitado (cobre pacotes Debian/security; pacotes"
echo "de repositórios de terceiros, como docker-ce, precisam de 'apt upgrade' manual)."

# ---------------------------------------------------------------------------
if command -v docker >/dev/null 2>&1; then
  log "Docker — corrigindo vazamento de portas publicadas pelo UFW"
  # ---------------------------------------------------------------------------
  cat > /etc/docker-user-firewall.conf <<EOF
# Gerado por harden.sh a partir de config.env — não editar à mão.
EXTERNAL_IFACE="${EXTERNAL_IFACE}"
DOCKER_NET_RANGE="${DOCKER_NET_RANGE}"
DOCKER_PUBLIC_PORTS=(
$(for e in "${DOCKER_PUBLIC_PORTS[@]:-}"; do [ -n "$e" ] && echo "  \"$e\""; done)
)
EOF

  cat > /usr/local/lib/docker-user-firewall.sh <<'EOF'
#!/bin/bash
# bash, não sh: o .conf e o laço abaixo usam arrays, que o dash (/bin/sh do
# Debian) não entende — com sh o script morre com erro de sintaxe e o
# ExecStartPost derruba o docker.service.
# Restaura o controle do UFW sobre portas publicadas por containers em
# 0.0.0.0. Por padrão, "docker -p 0.0.0.0:X:Y" faz DNAT direto na chain
# FORWARD, contornando o UFW (que só filtra INPUT). DOCKER-USER é avaliada
# antes das regras internas do Docker e nunca é sobrescrita pelo dockerd em
# restarts — é o local oficialmente recomendado para regras de admin.
#
# Idempotente: seguro chamar toda vez que o docker.service sobe.
set -e
[ -f /etc/docker-user-firewall.conf ] && . /etc/docker-user-firewall.conf
EXTERNAL_IFACE="${EXTERNAL_IFACE:-eth0}"
DOCKER_NET_RANGE="${DOCKER_NET_RANGE:-172.16.0.0/12}"

iptables -F DOCKER-USER

# 1) Tráfego de conexões já estabelecidas
iptables -A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN

# 2) Exceções explícitas — portas de container intencionalmente públicas.
#    Casa pela porta ORIGINAL do host (antes do DNAT), via conntrack, como a
#    documentação do Docker recomenda. Não depende do IP do container, que
#    muda quando ele é recriado ou quando os containers sobem em outra ordem
#    no boot — casar por IP chegou a liberar o container errado num teste.
for entry in "${DOCKER_PUBLIC_PORTS[@]:-}"; do
  [ -z "$entry" ] && continue
  spec="${entry%% *}"
  if [[ $spec == *:* ]]; then
    # Formato antigo "ip_do_container:porta_do_container/proto": ainda aceito.
    ip="${spec%%:*}"; rest="${spec#*:}"; port="${rest%%/*}"; proto="${rest##*/}"
    echo "AVISO: '$spec' usa o formato antigo (IP do container). Troque pela porta do host, ex.: \"8080/tcp\"." >&2
    iptables -A DOCKER-USER -i "$EXTERNAL_IFACE" -p "$proto" -d "$ip" --dport "$port" -j RETURN
  else
    port="${spec%%/*}"; proto="${spec##*/}"; [ "$proto" = "$spec" ] && proto=tcp
    iptables -A DOCKER-USER -i "$EXTERNAL_IFACE" -p "$proto" \
      -m conntrack --ctorigdstport "$port" --ctdir ORIGINAL -j RETURN
  fi
done

# 3) Default deny: qualquer outra conexão nova vinda da internet para
#    qualquer rede de container é bloqueada.
iptables -A DOCKER-USER -i "$EXTERNAL_IFACE" -d "$DOCKER_NET_RANGE" -j DROP

# 4) Fallback (equivalente ao comportamento padrão do Docker)
iptables -A DOCKER-USER -j RETURN
EOF
  chmod +x /usr/local/lib/docker-user-firewall.sh

  mkdir -p /etc/systemd/system/docker.service.d
  cat > /etc/systemd/system/docker.service.d/docker-user-firewall.conf <<'EOF'
[Service]
ExecStartPost=/usr/local/lib/docker-user-firewall.sh
EOF
  systemctl daemon-reload
  /usr/local/lib/docker-user-firewall.sh
  echo "DOCKER-USER configurada. Portas públicas atuais:"
  iptables -L DOCKER-USER -n -v --line-numbers
  if docker info --format '{{json .}}' 2>/dev/null | grep -q '"IPv6":true' \
     || grep -qs '"ipv6"[[:space:]]*:[[:space:]]*true' /etc/docker/daemon.json; then
    echo
    echo "ATENÇÃO: Docker com IPv6 habilitado. Estas regras são só IPv4 (iptables);"
    echo "portas publicadas em IPv6 NÃO estão filtradas. Ver README, seção Docker."
  fi
  echo
  echo "Lembrete: toda vez que publicar uma porta nova em 0.0.0.0 num container,"
  echo "adicione em DOCKER_PUBLIC_PORTS no config.env e rode ./harden.sh de novo"
  echo "(ou ela fica bloqueada por padrão)."
else
  log "Docker não encontrado — pulando correção do DOCKER-USER"
fi

log "Concluído"
echo "Revise 'ufw status verbose' e 'fail2ban-client status' acima."
echo "NÃO feche esta sessão até confirmar login funcionando na porta ${SSH_PORT}."
