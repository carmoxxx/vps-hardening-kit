# VPS Hardening

Checklist + script pra replicar nas outras VPS o conjunto de medidas
auditado e corrigido num servidor de produção (09/2026). O script (`harden.sh`) cobre
tudo que é seguro de automatizar; o resto fica documentado aqui porque
depende de julgamento por servidor (senão o script vira uma armadilha).

## Uso numa VPS nova

```bash
# 1. copie o repo pra VPS de destino (troque a porta se ela já tiver SSH endurecido)
scp -r /root/vps-hardening root@novo-host:/root/

# 2. entre na VPS de destino
ssh root@novo-host

# 3. configure e rode
cd vps-hardening
cp config.env.example config.env
vim config.env          # ajuste porta SSH, usuário admin, portas públicas de container etc.
sudo ./harden.sh
```

Seguro rodar de novo depois de editar `config.env` — o script regenera os
arquivos que gerencia (`jail.local`, `docker-user-firewall.sh` etc.) do zero
a cada execução.

**Antes de rodar:** garanta que `ADMIN_USER` já existe e já tem uma chave em
`~/.ssh/authorized_keys` funcionando. O script se recusa a desligar login
por senha sem isso — mas confirme mesmo assim, numa segunda aba, antes de
fechar a sessão atual.

---

## O que o script aplica, e por quê

### 1. SSH
- Porta não-padrão, `PermitRootLogin no`, `PasswordAuthentication no` (só
  chave), `AllowUsers <admin>`, `MaxAuthTries 3`, `X11Forwarding no`.
- **Por quê:** elimina praticamente todo o ruído de brute-force automatizado
  (bots varrem a 22 aos milhões, não a porta 2233) e fecha os dois vetores
  mais comuns de comprometimento de VPS — senha fraca e root direto.
- **Pegadinha de Debian 13+/systemd novo:** SSH pode estar com *socket
  activation* (`ssh.socket`). Nesse caso o `Port` do `sshd_config` é
  **ignorado** pro bind real — quem manda é
  `/etc/systemd/system/ssh.socket.d/override.conf`. Atenção: a unit
  `ssh.socket` existe no Debian **mesmo desabilitada**, então o script só
  usa o modo socket se ela estiver *habilitada*
  (`systemctl is-enabled ssh.socket`). Senão ele usa o `ssh.service` e
  limpa restos de override/socket de execuções antigas — ligar o socket
  sem precisar abre um segundo listener na mesma porta e faz a próxima
  execução falhar. No fim, confere que há algo escutando na porta nova. Se
  for editar a porta à mão num servidor, cheque
  `systemctl is-enabled ssh.socket` primeiro.
- **Pegadinha do `sshd_config.d/`:** no sshd vale o *primeiro* valor lido de
  cada opção, e o Debian faz `Include /etc/ssh/sshd_config.d/*.conf` no topo
  do `sshd_config`. Imagens de VPS costumam trazer um `50-cloud-init.conf`
  com `PasswordAuthentication yes`, que ganharia da edição do `sshd_config`.
  O script grava as opções também em `sshd_config.d/00-harden.conf` (lido
  antes dos outros) e, antes de reiniciar o sshd, confere a configuração
  efetiva com `sshd -T`. `Port` e `AllowUsers` somam entre arquivos, então
  ali exige-se o conjunto exato. Se algo não bater, reverte e aborta sem
  reiniciar o SSH.

### 2. UFW
- Política padrão: nega tudo que entra, libera tudo que sai. Libera só a
  porta SSH configurada + o que estiver em `UFW_EXTRA_ALLOW` (80, 443,
  WireGuard se houver).
- **Por quê:** modelo default-deny é a base de tudo — qualquer serviço novo
  que alguém subir sem querer expor fica fechado até alguém liberar
  explicitamente.

### 3. fail2ban
- Jail do `sshd` com `bantime=24h`, `findtime=10m`, `maxretry=3`. Se houver
  nginx, jails `nginx-limit-req` e `nginx-botsearch` também.
- **Backend dos jails do nginx:** o `[DEFAULT]` usa `backend = systemd`
  (lê o journal, bom pro sshd), mas com esse backend o fail2ban *ignora* o
  `logpath`. O nginx grava em arquivo, então os jails do nginx forçam
  `backend = auto` — sem isso eles sobem "ativos" e nunca banem nada.
- **Erro que já pegamos uma vez — não repetir:** o jail do sshd **nunca**
  deve usar `port = ssh`. Esse alias resolve pra porta 22 via
  `/etc/services`, e como o SSH real roda em outra porta, a regra de
  bloqueio do fail2ban fica vigiando uma porta que ninguém usa — o IP
  aparece como "banido" nos logs, mas o firewall não bloqueia nada de
  verdade na porta real. Isso já passou meses despercebido em produção. O script sempre usa `port = ${SSH_PORT}` explícito. **Se você
  mudar a porta do SSH manualmente numa VPS no futuro, confira essa linha.**
- **Como verificar que está bloqueando de verdade** (não só "banido" no
  status): `nft list ruleset | grep -A3 f2b-chain` — o `tcp dport` da regra
  tem que bater com a porta real do SSH.

### 4. unattended-upgrades
- Habilitado, cobre atualizações de segurança do repositório padrão
  Debian.
- **Limitação a lembrar:** pacotes de repositórios de terceiros (ex.:
  `docker-ce`, `docker-ce-cli`, `containerd.io` — vêm do repo oficial do
  Docker, não do Debian) **não são cobertos**. Rode `apt update && apt list
  --upgradable` de vez em quando, ou monte um lembrete/cron pra isso.

### 5. Docker — vazamento de portas pelo UFW
- **O problema:** `docker run -p 0.0.0.0:X:Y` (ou `ports:` no compose com
  IP `0.0.0.0` implícito) faz DNAT direto na chain `FORWARD` do iptables,
  contornando completamente o `INPUT`/UFW. `ufw status` pode dizer que uma
  porta não está liberada e, mesmo assim, ela estar 100% acessível da
  internet através de um container. Isso é comportamento documentado do
  Docker, não um bug — mas pega muita gente desprevenida.
- **A correção:** regras na chain `DOCKER-USER` (ponto que o próprio Docker
  recomenda pra isso — é avaliada antes das regras internas do Docker e
  nunca é sobrescrita quando o `dockerd` reinicia). Modelo: bloqueia por
  padrão qualquer conexão nova vinda da internet pra qualquer rede de
  container, com exceção explícita das portas listadas em
  `DOCKER_PUBLIC_PORTS` no `config.env`.
- **Persistência:** um drop-in em `docker.service.d/` reaplica as regras
  toda vez que o `dockerd` sobe (inclusive depois de reboot).
- **Manutenção:** toda vez que publicar uma porta nova de container em
  `0.0.0.0` numa dessas VPS, adicione a entrada em `DOCKER_PUBLIC_PORTS` e
  rode `./harden.sh` de novo — senão ela fica bloqueada (o que é o
  comportamento seguro por padrão, mas pode confundir na hora de debugar
  "por que esse serviço não responde de fora").
- **Só IPv4:** as regras usam `iptables`. Se o Docker estiver com IPv6
  ligado (`"ipv6": true` no `daemon.json`), portas publicadas em IPv6 não
  são filtradas — o script avisa quando detecta isso. Nesse caso, replique
  as regras com `ip6tables` ou publique as portas só em `127.0.0.1`.
- **Interface certa:** `EXTERNAL_IFACE` tem que ser a interface pública de
  verdade (`ip -o route get 1.1.1.1`). Muita VPS usa `ens3`/`enp1s0`, não
  `eth0` — com o nome errado a regra DROP nunca casa e tudo continua aberto
  sem aviso. O script aborta se a interface não existir e avisa se ela não
  for a da rota padrão.
- **Exceção pela porta do host, não pelo IP do container:** em
  `DOCKER_PUBLIC_PORTS` vai a porta publicada no host, a da esquerda em
  `docker ps` (`0.0.0.0:8080->80/tcp` → `"8080/tcp"`). A regra casa com
  `-m conntrack --ctorigdstport`, a porta original antes do DNAT — que é o
  que a documentação do Docker recomenda.
- **Por que não pelo IP do container (formato antigo `ip:porta`):** o IP
  muda quando o container é recriado e também quando os containers sobem em
  outra ordem no boot. Num teste com dois containers `--restart=always`, os
  IPs trocaram depois de um reboot e a exceção passou a liberar o container
  *interno* e bloquear o público — sem nenhum aviso. O formato antigo ainda
  é aceito, mas o script avisa para trocar.

---

## O que NÃO está no script (decisão de projeto, não automatize às cegas)

Cada item abaixo depende do que a VPS específica roda — automatizar geraria
mais risco de misconfiguração do que benefício.

- **Grupo `docker`**: qualquer usuário nele é root-equivalente no host
  (`docker run -v /:/host` monta o disco inteiro). Só coloque quem
  realmente precisa (ex.: uma conta de deploy de CI) — nunca por
  conveniência.
- **Chaves SSH restritas pra automação** (ex.: deploy via GitHub Actions):
  no `authorized_keys` do usuário de deploy, prefixe a chave com
  `command="/caminho/do/script.sh",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty`.
  Isso limita a chave a rodar *só* aquele comando, sem shell interativo.
- **TLS do nginx** (se a VPS servir HTTPS direto): garanta
  `ssl_protocols TLSv1.2 TLSv1.3;` e o header HSTS:
  ```
  add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
  ```
- **WireGuard**: sempre que adicionar um peer, use `allowed ips` restrito a
  um `/32` individual, nunca uma sub-rede larga — cada peer só deve
  enxergar a si mesmo, não a rede toda dos outros.
- **Certificados**: `certbot certificates` pra conferir validade; renovação
  automática já vem via `certbot.timer` na instalação padrão.

---

## Rotina periódica (manual, não dá pra automatizar com segurança)

- Mensal: `apt update && apt list --upgradable` — prestar atenção especial
  em pacotes de repositórios de terceiros (Docker, etc.) que o
  unattended-upgrades não cobre.
- Ao adicionar qualquer `docker-compose.yml` novo: checar se algum `ports:`
  usa `0.0.0.0` (ou omite o IP, que é o padrão) quando o serviço deveria
  ser só interno — nesse caso, prefira `"127.0.0.1:X:Y"` e nem precisa medir
  a exceção no UFW/DOCKER-USER.
- A cada novo peer WireGuard ou usuário SSH: revisar `AllowUsers` e
  `allowed ips` — não deixar acumular acesso que ninguém usa mais.

---

## Licença

MIT, ver [`LICENSE`](LICENSE). Sem garantia: o script mexe em SSH e
firewall, então teste numa VM ou com acesso ao console antes de rodar em
produção.
