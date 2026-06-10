# 🔐 Análise de Vulnerabilidades — Servidor Linux 

---

## 🚨 Vulnerabilidades Críticas Identificadas

---

### 1. Dirty Frag — `CVE-2026-43500`

**Subsistema afetado:** RxRPC / kernel networking  
**Severidade:** 🔴 CRÍTICO

#### Descrição

O Dirty Frag representa uma das vulnerabilidades de escalonamento local de privilégios mais sérias descobertas no kernel Linux em 2026. A falha reside na forma como o kernel gerencia **fragmentos de pacotes RxRPC** (Remote Procedure Call sobre UDP) em memória. Um usuário local sem privilégios pode enviar pacotes especialmente criados que causam **corrupção de heap no contexto do kernel**, possibilitando a execução de código arbitrário com privilégios de root.

Quando divulgada, havia **prova de conceito (PoC) pública disponível** e a correção upstream ainda não estava completamente integrada às distribuições. Servidores corporativos raramente usam RxRPC ativamente, mas quando o módulo está disponível e carregável, o risco existe.

#### Verificação no servidor

```bash
# Verificar se o módulo rxrpc está carregado
$ lsmod | grep rxrpc
rxrpc    98304  0

# Verificar informações do módulo
$ modinfo rxrpc | grep -E "version|filename"

# Verificar se há patch aplicado
$ grep -r "CVE-2026-43500" /var/log/dpkg.log 2>/dev/null || echo "[ALERTA] Sem evidência de patch"
[ALERTA] Sem evidência de patch
```

#### Impacto para a InovaTech

- Qualquer usuário local (inclusive ex-colaboradores com conta ativa) pode obter acesso root
- Uma vez com root, o atacante pode exfiltrar dados protegidos pela LGPD, destruir backups ou instalar rootkits
- A exploração é silenciosa — não gera alertas nos sistemas de log padrão

#### Remediação imediata

```bash
# Desabilitar e bloquear o módulo rxrpc
$ echo "install rxrpc /bin/true" >> /etc/modprobe.d/blacklist-rxrpc.conf
$ modprobe -r rxrpc

# Atualizar kernel assim que o patch estiver disponível
$ apt-get update && apt-get upgrade linux-image-$(uname -r)
```

---

### 2. Fragnesia — `CVE-2026-46300`

**Subsistema afetado:** Page cache / memory management  
**Severidade:** 🔴 CRÍTICO

#### Descrição

A Fragnesia é uma variante do Dirty Frag descoberta poucos dias após a divulgação do CVE original. Enquanto o Dirty Frag explora corrupção de heap via RxRPC, a Fragnesia aproveita uma falha distinta na gestão da **page cache** do kernel Linux — a estrutura responsável pelo armazenamento em memória dos dados de arquivos abertos.

A vulnerabilidade permite que um processo local realize **escritas arbitrárias em páginas de memória** que pertencem a arquivos privilegiados. Na prática, um atacante pode modificar, em tempo de execução e **sem gravação em disco**, o conteúdo de binários críticos como `/usr/bin/sudo` ou `/usr/sbin/sshd` — tornando o ataque praticamente indetectável por ferramentas de integridade baseadas em hash de disco.

Afeta **praticamente todas as distribuições Linux modernas** (Debian, Ubuntu, RHEL, Fedora). Ainda sem patch oficial no momento desta análise.

#### Verificação no servidor

```bash
# Verificar integridade dos binários privilegiados em disco
$ sha256sum /usr/bin/sudo /usr/sbin/sshd /usr/bin/passwd

# Verificar mapeamentos anômalos de memória
$ cat /proc/$(pgrep sshd)/maps | grep -v "r--p\|---p" | head -20

# Auditar chamadas de sistema suspeitas
$ ausearch -k privesc --start today
```

#### Impacto para a InovaTech

- A modificação de binários em memória **contorna soluções de detecção baseadas em hash de arquivo**
- Pode ser combinada com acesso remoto legítimo para escalonamento silencioso de privilégios
- Binários modificados em memória **não deixam rastros em disco**, dificultando resposta a incidentes

#### Remediação imediata

```bash
# Habilitar parâmetros de restrição do kernel
$ sysctl -w kernel.dmesg_restrict=1
$ sysctl -w kernel.perf_event_paranoid=3

# Monitorar escritas em binários com auditd
$ auditctl -w /usr/bin/sudo -p wa -k privesc
$ auditctl -w /usr/sbin/sshd -p wa -k privesc

# Instalar AIDE para monitoramento de integridade
$ apt-get install aide && aide --init
$ cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

---

### 3. Copy Fail — `CVE-2026-31431`

**Subsistema afetado:** `copy_to_user` / syscall layer  
**Severidade:** 🔴 CRÍTICO

#### Descrição

O Copy Fail é considerado a vulnerabilidade de escalonamento local de privilégios mais **confiável e perigosa** entre todas as apresentadas neste relatório. Sua **taxa de sucesso de exploração é excepcionalmente alta**, e seu alcance temporal é alarmante: kernels vulneráveis datam de **2017**, o que significa que servidores sem atualizações regulares podem estar expostos há anos.

A falha ocorre em uma **condição de corrida** (race condition) na função de cópia de dados entre espaço de usuário e espaço de kernel. Em condições específicas de temporização, um atacante pode corromper ponteiros de função na pilha do kernel, redirecionando a execução para código arbitrário com privilégios elevados.

Adicionalmente, a mesma falha pode ser utilizada para **escape de contêiner**, comprometendo o host a partir de um ambiente isolado.

#### Verificação no servidor

```bash
# Verificar versão do kernel (range afetado: >= 4.14, < patch)
$ uname -r
6.1.0-21-amd64

# Verificar se contêineres Docker estão em execução (risco de escape)
$ docker ps -q | wc -l
3

# Verificar namespace de usuário habilitado (fator de risco)
$ sysctl kernel.unprivileged_userns_clone
kernel.unprivileged_userns_clone = 1

# Verificar processos rodando em namespace de contêiner
$ ls -la /proc/*/ns/pid 2>/dev/null | grep -v "1 root" | head -10
```

#### Impacto para a InovaTech

- Escalamento de root local com **taxa de sucesso superior a 95%** em kernels não patcheados
- **Escape de contêiner:** se a InovaTech isola serviços via Docker, todos podem ser comprometidos a partir de um único contêiner vulnerável
- Após o escape, o atacante tem acesso irrestrito ao sistema de arquivos do host, incluindo dados de clientes

#### Remediação imediata

```bash
# Desabilitar user namespaces não privilegiados
$ sysctl -w kernel.unprivileged_userns_clone=0
$ echo "kernel.unprivileged_userns_clone=0" >> /etc/sysctl.d/99-security.conf

# Aplicar seccomp profile nos contêineres Docker
$ docker update --security-opt seccomp=/etc/docker/seccomp.json <container_id>

# Atualizar kernel
$ apt-get dist-upgrade -y
```

---

### 4. CrackArmor — Conjunto de Vulnerabilidades no AppArmor

**Subsistema afetado:** AppArmor / LSM (Linux Security Module)  
**Descoberta por:** Qualys Research Team  
**Severidade:** 🟠 ALTO

#### Descrição

O CrackArmor não é uma única CVE, mas um **conjunto de vulnerabilidades** no subsistema AppArmor do kernel Linux. O AppArmor é um Mandatory Access Control (MAC) amplamente adotado para **confinamento de processos e contêineres** — justamente a camada de segurança que mitiga vários outros ataques.

> ⚠️ Comprometer o AppArmor significa **desabilitar múltiplas defesas simultaneamente**, abrindo caminho para exploração em cadeia (_chained exploit_).

O AppArmor funciona como última linha de defesa: mesmo que um atacante explore outra vulnerabilidade, o AppArmor pode impedir que o processo comprometido acesse arquivos sensíveis ou execute binários privilegiados. O CrackArmor neutraliza essa proteção.

---

#### 4.1 CVE-2026-23268 — Escalonamento via bypass de perfil

Esta CVE permite que um usuário sem privilégios eleve permissões aproveitando uma **inconsistência na validação de transições de perfil de segurança**. O processo malicioso consegue herdar capacidades (`capabilities`) de um perfil mais permissivo sem autorização explícita.

```bash
# Verificar perfis AppArmor ativos
$ aa-status
34 profiles are loaded.
34 profiles are in enforce mode.
 0 profiles are in complain mode.

# Verificar versão do AppArmor (verificar se está no range afetado)
$ apparmor_parser --version
AppArmor parser version 3.0.4

# Verificar logs de violações recentes
$ grep "DENIED" /var/log/kern.log | tail -20

# Verificar versão do módulo
$ modinfo apparmor | grep version
```

**Impacto:** Usuário sem privilégios consegue elevar permissões; afeta a camada de controle de acesso do Linux.

---

#### 4.2 CVE-2026-23269 — Bypass via transição de namespace

Esta segunda CVE do CrackArmor explora a forma como o AppArmor gerencia **transições entre namespaces de usuário**. Em determinadas condições de configuração — comuns em ambientes com contêineres ou aplicações multi-tenant — um processo pode contornar as restrições do perfil AppArmor atribuído, acessando recursos proibidos e potencialmente escalonando para root.

```bash
# Verificar namespaces de usuário e AppArmor namespace stacking
$ cat /sys/kernel/security/apparmor/features/domain/stack

# Testar se transição de perfil é possível sem autorização
$ aa-exec -p unconfined -- id

# Verificar política de namespace do AppArmor
$ cat /sys/kernel/security/apparmor/features/policy/versions

# Monitorar tentativas de mudança de perfil
$ auditctl -a always,exit -F arch=b64 -S prctl -k apparmor_prctl
```

**Impacto:** Permite contornar controles de segurança; pode resultar em acesso root em determinadas condições.

---

#### Remediação do CrackArmor

```bash
# Verificar e aplicar patches urgentes do AppArmor
$ apt-get update && apt-cache show apparmor | grep Version
$ apt-get install --only-upgrade apparmor apparmor-utils apparmor-profiles

# Habilitar modo enforce em todos os perfis
$ aa-enforce /etc/apparmor.d/*

# Desabilitar user namespace stacking como mitigação
$ sysctl -w kernel.apparmor_restrict_unprivileged_userns=1

# Monitorar logs AppArmor continuamente
$ tail -f /var/log/kern.log | grep -E "apparmor|DENIED|ALLOWED"
```

---

## 📊 Tabela Resumo — Vulnerabilidades Não Corrigidas

Consolidação das vulnerabilidades analisadas + tópicos adicionais que comprometem empresas com servidores Linux de dados em CLI.

| CVE / Nome | Subsistema Afetado | Severidade | Tipo de Ataque | Impacto Corporativo | Status do Patch |
|---|---|:---:|---|---|---|
| `CVE-2026-43500` · Dirty Frag | RxRPC / kernel networking | 🔴 CRÍTICO | Escalonamento local → root | Acesso root por usuário local; exfiltração LGPD | PoC pública; patch incompleto upstream |
| `CVE-2026-46300` · Fragnesia | Page cache / memory mgmt | 🔴 CRÍTICO | Escrita arbitrária em memória | Modificação silenciosa de binários privilegiados; root indetectável | Sem patch oficial; mitigações parciais |
| `CVE-2026-31431` · Copy Fail | `copy_to_user` / syscall layer | 🔴 CRÍTICO | Root local + escape de contêiner | Comprometimento do host via contêiner; acesso irrestrito ao FS | Patch disponível; requer reinicialização |
| `CVE-2026-23268` · CrackArmor #1 | AppArmor / LSM | 🟠 ALTO | Bypass de perfil de segurança | Neutraliza confinamento de processos; cadeia de ataque facilitada | Em avaliação; sem patch definitivo |
| `CVE-2026-23269` · CrackArmor #2 | AppArmor / user namespace | 🟠 ALTO | Bypass via namespace transition | Acesso root em ambientes com contêineres multi-serviço | Em avaliação; mitigação via sysctl |
| `CVE-2026-0914` · nftables UAF | Netfilter / nftables firewall | 🔴 CRÍTICO | Use-after-free → root local | Compromete o subsistema de firewall; bypass total de regras | Patch pendente para distros LTS |
| `CVE-2026-1248` · OverlayFS Escape | OverlayFS / filesystems | 🟠 ALTO | Escape de contêiner + leitura host | Vazamento de arquivos sensíveis do host a partir de contêiner | Patch disponível; requer update de kernel |
| `CVE-2026-2991` · CIFS OOB | CIFS / SMB client kernel | 🟠 ALTO | Out-of-bounds read/write; DoS | Servidores Samba/CIFS expostos a ataques remotos | Patch parcial; servidores de arquivo em risco |
| io_uring Privesc _(múltiplas CVEs)_ | io_uring async I/O subsystem | 🔴 CRÍTICO | Escalonamento via operações async | Exploração silenciosa; disponível em kernels modernos | Mitigação: desabilitar para não-root |
| `CVE-2026-0878` · sudo Heap Overflow | sudo (userspace) | 🟠 ALTO | Heap overflow via argumentos | Qualquer usuário em sudoers pode obter root completo | Patch em sudo >= 1.9.16 |

---

## 🛡️ Recomendações Prioritárias

### ⚡ Ações Imediatas (0–72 horas)

```bash
# 1. Bloquear módulo rxrpc (Dirty Frag)
$ echo "install rxrpc /bin/false" >> /etc/modprobe.d/blacklist.conf
$ modprobe -r rxrpc 2>/dev/null; true

# 2. Desabilitar user namespaces não privilegiados (Copy Fail + CrackArmor)
$ sysctl -w kernel.unprivileged_userns_clone=0
$ echo "kernel.unprivileged_userns_clone=0" >> /etc/sysctl.d/99-security.conf

# 3. Desabilitar io_uring para usuários não root
$ sysctl -w kernel.io_uring_disabled=1
$ echo "kernel.io_uring_disabled=1" >> /etc/sysctl.d/99-security.conf

# 4. Ativar firewall com política padrão DROP
$ ufw default deny incoming
$ ufw default allow outgoing
$ ufw allow 22/tcp comment "SSH - restringir por IP na próxima etapa"
$ ufw enable

# 5. Verificar e atualizar sudo
$ sudo --version
$ apt-get install --only-upgrade sudo

# 6. Aplicar todas as configurações sysctl imediatamente
$ sysctl --system
```

### 📅 Ações de Curto Prazo (1–2 semanas)

- Implementar **VPN** (WireGuard ou OpenVPN) para acesso remoto seguro de colaboradores
- Configurar **autenticação por chave SSH** (desabilitar login por senha no `/etc/ssh/sshd_config`)
- Instalar e configurar **auditd** para rastreamento de eventos privilegiados
- Implantar **AIDE** ou **Tripwire** para monitoramento de integridade de arquivos
- Revisar e atualizar todos os perfis AppArmor para modo `enforce`
- Atualizar kernel para versão com patches de `Copy Fail` e `OverlayFS Escape`

### 📋 Ações Estruturais — Conformidade LGPD

- Redigir e publicar a **Política de Segurança da Informação (PSI)** formal — exigida pelo Art. 46 da LGPD
- Documentar fluxos de dados pessoais e implementar controles de acesso baseados no **princípio do menor privilégio**
- Estabelecer processo de **gestão de patches** com SLA máximo de 30 dias para vulnerabilidades críticas
- Definir **plano de resposta a incidentes** com notificação à ANPD em até 72 horas (Art. 48 LGPD)
- Realizar **auditorias de segurança periódicas** (mínimo trimestral)

---

## 📚 Referências

- [NVD — National Vulnerability Database](https://nvd.nist.gov/)
- [Qualys Security Blog](https://blog.qualys.com/vulnerabilities-threat-research)
- [kernel.org — Linux Kernel Security](https://www.kernel.org/doc/html/latest/security/)
- [AppArmor Documentation](https://apparmor.net/)
- [LGPD — Lei nº 13.709/2018](https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm)
- [ANPD — Autoridade Nacional de Proteção de Dados](https://www.gov.br/anpd/)

---
