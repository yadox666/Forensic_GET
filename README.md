**Descripción de los trabajos realizados**

Tras la detección de algunos posibles casos de uso fraudulento de tarjetas de crédito aparentemente relacionadas con el sitio web de comercio electrónico basado en Magento, se sospecha de un nuevo caso de compromiso de las infraestructuras del cliente. Es prioritario realizar una auditoría forénsica completa dirigida principalemente a la localización de cualquier herramienta maliciosa (malware) o vulnerabilidad que pueda permitir el acceso remoto a los servidores del cliente o la los datos ahí almacenados. Para ello se realizarán pruebas exhaustivas que ayuden a encontrar cualquier tipo de IoC (indicadores de compromiso) en los sistemas presuntamente afectados.

Además se procurará extraer, si las huberia, algún tipo de evidencias sobre actos delictivos o simplemente accidentales que puedan haber causado algún incidente de pérdida de control sobre la información de carácter privado que debe ser protegida.

Los antecedentes de ataques dirigidos a este cliente hacen que se deba de tener un cuidado especial en la protección de sus infraestructuras y datos personales ahí almacenados y tratados, por lo que se ha tenido un cuidado especial y una gran minuciosidad en la realización de la auditoría prolongando su ejecución lo necesario para alcanzar los resultados más fiables. A pesar de esto, y debido a la complejidad de sus infraestructuras, siempre recomendaremos la realización de auditorías de seguridad de tipo pentest de caja blanca y de caja negra de forma periódica a fin de localizar vulnerabilidades en el software, aplicaciones, servicios y sistemas operativos que componen estas infraestructuras, ya que éste tipo de auditorías no se realizan en este procedimiento que es de tipo forénsico.

Tras la sospecha de fraude relacionado con tarjetas de crédito, y tras la realización de una forénsica previa con una compañía certificada en los protocolos PCI-DSS, el cliente contacta con nosotros a fin de realizar ciertos trabajos más dirigidos a revisar que su principal sitio web no esté comprometido y pueda seguir realizando su labor comercial con seguridad. Sobre el rango de fechas del posible incidente, el cliente informa:

&quot;_Respecto a las fechas, nos notificaron que el rango de fechas era desde Junio 2018 hasta Octubre 2019, pero creo que habría que analizar hasta la actualidad por cubrirnos en lo que hay ahora mismo en producción.&quot;_

Las tareas que se realizan tras la aceptación del presupuesto son las siguientes:

1. **Descarga y recuperación de las máquinas virtuales**. Se producen algunas dificultades y retrasos en la ejecución por el tamaño de las mismas y los métodos de entrega. Las máquinas virtuales a analizar son las siguiente según conversación por email con el cliente:

&quot;_La máquina fw1.weareknitters.com es el cortafuegos y balanceador por donde pasa TODO._

_Las máquinas w1.weareknitters.com y w2.weareknitters.com son frontales web balanceados._

_La máquina wa.weareknitters.com es el panel de control de Magento donde solo se puede conectar el equipo de WAK mediante certificado digital._

_db1.weareknitters.com es la máquina de la base de datos de Magento._

_wp2.weareknitters.com es un servidor aparte donde está el Wordpress. Para el análisis, el wp2 creo que lo podríamos dejar, verdad Doro? Es un servidor aislado del resto que usamos para wordpress y creo que no hay conectividad al resto. Pero tu nos dices Doro. Se puede ignorar, si.&quot;_

1. **Creación de un sistema de virtualización** sobre ESx 6.x para garantizar la compatibilidad con la infraestructura del cliente que según nos informa, está originalmente montada sobre esta versión.

1. **Montaje de las máquinas virtuales en el servidor de virtualización** VMware ESx 6.x. Se producen ciertas dificultades en el montaje de las máquinas virtuales en nuestros servidores, pero finalmente se consiguen poner en funcionamiento.

1. **Modificación de las contraseñas del usuario &quot;root&quot;** en todas las máquinas virtuales a analizar, para poder ganar acceso y control en todos los sistemas. Se ha decidido realizar auditorías en los propios sistemas funcionando. Este tipo de auditoría se considera auditoría forénsica en vivo (live systems forensics) y ofrece una visión más realista de posibles infecciones, procesos maliciosos o conexiónes mediante sockets abiertos, además de rootkits presentes y otros posibles agujeros de seguridad.

1. **Realización de imágenes o snapshots** de las máquinas virtuales por si hubiera que restaurarlas a un estado anterior.

1. **Copias de seguridad** del contenido de las páginas web, configuraciones &quot;/etc&quot;, todo tipo de logs y herramientas relacionadas para la realización de análisis externos de los mismos.

1. Solicitud al cliente del **directorio** _ **/media** _ _no presente en las máquinas virtuales suministradas_. Además se procede a revisar el contenido de estos extensos directorios que contienen principalmente imágenes, videos y documentos.

1. Se realiza el **análisis de la estructura de contenidos** en los directorios y sistemas relacionados para entender la infraestructura (funciones de cada máquina en la misma) junto con sus servicios relacionados (apache2, nginx, mysql, php, proxies, email, fail2ban, etc.)

1. **Realización de todas las pruebas** en las máquinas virtuales y extracción de los datos y evidencias relacionadas.

1. **Análisis de las evidencias** extraídas en búsqueda de algún tipo de IoC (indicador de compromiso).

**Descripción de la información extraída y pruebas realizadas**

Al determinarse que es un trabajo muy específico y arduo debido a la gran cantidad de información que hay que analizar, decidimos programar una herramienta que extraiga la información importante de cada máquina virtual hacia una unidad extraíble de forma que pueda ser analizada posteriormente por un auditor.

Esta herramienta a la que nombramos &quot;_forensic\_get.sh_&quot; selecciona y extrae la siguiente información formateada para el análisis forénsico posterior (se aportan los ficheros generados en cada servidor en los directorios con las fechas de extracción en un archivo comprimido con el password &quot;weRknitt3rS!!!f0r3nSE&quot; sin incluir las comillas):

1. **Información del sistema auditado** (fecha, hora, zona geográfica, nombre de host, usuario utilizado en la auditoría, permisos del usuario utilizado, tiempo de funcionamiento del sistema, fecha introducida por el auditor como posible inicio del compromiso, fecha final del posible compromiso para el análisis, destino de la extracción, número de serie del dispositivo utilizado para la extracción, directorios relacionados con el análisis, usuario del servidor web, sistema operativo del servidor y kernel, conexión a internet del servidor).

**Ficheros:** _index.txt_

1. **Histórico de comandos ejecutados en el espacio de cada usuario del sistema** (historial de ejecución de cada usuario con su fecha y hora de ejecución).

**Ficheros:** _history\_root.txt / history\_nombredeusuario\_orig.txt_

1. **Variables del sistema durante la ejecución** (análisis de las variables del sistema en memoria durante la auditoría, para buscar indicadores de compromiso en aplicaciones corriendo en memoria).

**Ficheros:** _env.txt_

1. **Investigación de scripts de inicio de sesión de usuario** (búsqueda de scripts o aplicaciones que puedan arrancar de forma automática durante el inicio de sesiones de usuarios que indique &quot;persistencia&quot; del malware).

**Ficheros:** _shell.txt_

1. **Investigación de scripts en el arranque del sistema** (búsqueda de scripts o aplicaciones que puedan arrancar de forma automática durante el inicio del sistema operativo que puedan indicar &quot;persistencia&quot; del malware. Se analizan los servicios de Linux &quot;init&quot;, &quot;Sys-V&quot; y &quot;systemd&quot;, además de analizar el actual runlevel de ejecución).

**Ficheros:** rc_sysinit.txt / initd.txt / system.txt_

1. **Análisis de trabajos programados mediante el servicio cron del sistema** (Otra forma habitual de obtención de persistencia en el sistema es el uso del servicio &quot;cron&quot; en Linux).

**Ficheros:** _cron.txt_

1. **Análisis de procesos en ejecución** (al realizarse la auditoría en un sistema &quot;vivo&quot; podemos estudiar aquellos procesos que estén en ejecución durante la misma para buscar procesos extraños, poco habituales o modificados. Sobre cada uno de estos procesos se analiza además la lista de ficheros y sockets relacionados y su historial de memoria y tiempo de procesamiento para ver comportamientos anómalos. Se vigilan especialmente procesos relacionados con usuarios y administradores).

**Ficheros:** _proc.txt_

1. **Estudio de drivers, controladores o módulos del sistema** (aunque no es algo demasiado habitual, el malware de tipo rootkit se suele ocultar tras módulos del kernel de Linux. Por ello analizaremos los módulos cargados durante la ejecución de la auditoría para buscar módulos desconocidos o extraños. Además se analizarán dispositivos USB o PCI conectados para relacionarlos con los módulos del kernel en búsqueda de inconcordancias. Se vigilarán errores en los módulos durante el arranque del sistema mediante mensajes del kernel &quot;dmesg&quot;).

**Ficheros:** _modules.txt_

1. **Usuarios presentes en el sistema y grupos de pertenencia** (en este tipo de auditorías forénsicas resulta siempre necesario analizar cada uno de los usuarios presentes y con que finalidad se han creado. Además se deben de analizar los permisos y pertenencia a grupos de cada uno de ellos en búsqueda de permisos excesivos. Principalmente aquellos usuarios que tengan algún tipo de login resultan sospechosos. Analizamos la fecha de modificación de los ficheros de configuración de usuarios).

**Ficheros:** _users.txt_

1. **Extracción de todo tipo de accesos o logins de usuarios en cada sistema** (se extraen uno por uno los login de cada usuario en el servidor, tanto los últimos como los históricos dentro del período a analizar. Esto es una labor lenta y ardua porque los ficheros históricos ya fueron archivados y comprimidos y hay que buscarlos y extraerlos dependiendo del sistema operativo y configuración de archivado. Se extraen de forma independiente los login del servicio remoto SSH con logins fallidos y exitosos).

**Ficheros:** _loginsnow.txt / loginsfail.txt / logins.txt / loginSSHok.txt / loginSSHfail.txt_

1. **Extracción de los intentos de login mediante el servicio fail2ban** (si este servicio se encuentra presente, se extraen los ficheros de reporte o logs del mismo para su posterior análisis de intentos de penetración).

**Ficheros:** _fail2banlogins.txt_

1. **Análisis de la configuración de red** (se investigan los ficheros de configuración de red, interfaces en modo promiscuo, servidores de nombres DNS y nombres de host asignados de forma manual, proxies, tablas de enrutamiento, etc. en busca de exfiltración de datos o ataques de tipo MiTM. Además se extraen las conexiones TCP y UDP abiertas en busca de conexiones e intentos de conexión a direcciones IP externas. Se revisa especialmente la configuración del servicio de conexión remota SSH).

**Ficheros:** _network.txt_

1. **Investigación del sistema de archivos y directorios** (esta investigación es una de las más importantes para la localización de trazas de archivos sospechosos o anómalos debido a sus características, análisis temporal, permisos, usuario y grupo de pertenencia, tipo de archivo, directorio de pertenencia, trazas en el contenido, etc). Debido a la importancia de este análisis lo desgranaremos en cada uno de los análisis realizados:

1. **Estudio sobre almacenamiento y puntos de** (en este punto se muestran los discos duros, particiones o unidades lógicas presentes en el sistema, además de aquellos montajes y puntos de montaje que se crean durante el arranque del sistema).

**Ficheros:** _fsinfo.txt_

1. **Generación de un fichero de tipo .csv (archivo separado por comas) de cada fichero del sistema de archivos** (cada archivo en una línea con los datos separados por comas: _Nombre, Fecha y hora de último acceso conocida en Linux como atime, fecha y hora de última modificación conocida en Linux como mtime, fecha y hora de último cambio de estado conocidad en Linux como mtime, Usuario o Identificador, Grupo o identificador, Permisos, tamaño en bytes, tipo de archivo analizado_. Esta estructura de .CSV se mantendrá en posteriores ficheros y directorios analizados).

**Ficheros:** _allfilestimeline.csv_

**Acerca de la marcas de tiempo en Linux:**

La marca de tiempo de acceso _atime_ es la última vez que se leyó un archivo. Esto significa que alguien usó un programa para mostrar el contenido del archivo o leer algunos valores de él. Nada fue editado o agregado al archivo. Los datos fueron referenciados pero sin cambios.

Una marca de tiempo modificada mtime significa la última vez que se modificó el contenido de un archivo. Un programa o proceso editó o manipuló el archivo. &quot;Modificado&quot; significa que algo dentro del archivo se modificó o eliminó, o se agregaron datos nuevos.

Las marcas de tiempo modificadas _ctime_ no se refieren a los cambios realizados en el contenido de un archivo. Por el contrario, es el momento en que se modificaron los metadatos relacionados con el archivo. Los cambios en los permisos de archivos, por ejemplo, actualizarán la marca de tiempo modificada.

1. **Generación de un fichero de tipo .csv de cada directorio del sistema de archivos** (necesario para verificar fechas de creación, modificación o cambio de estado en cualquier directorio del sistema, así como analizar permisos y usuarios o grupos de pertenencia no habituales o incorrectos).

**Ficheros:** _alldirstimeline.csv_

1. **Árbol de directorios del sistema** (forma visual de analizar los directorios del sistema en busca de directorios extraños o no habituales, además de permitir hacerse una idea visual del contenido del sistema).

**Ficheros:** _dirtree.txt_

1. **Características de los directorios &quot;tmp&quot; y &quot;mnt&quot;** (algo que podría indicar intento de violación de permisos, ejecución de código aprovechando sus características o montaje de unidades remotas, entre otros).

**Ficheros:** _filestmp.txt / filesmnt.txt_

1. **Archivos ocultos en el sistema de archivos en formato .csv** (en ocasiones ocultar archivos en un listado simple, facilita la ocultación de scripts y malware, por lo que se debe estudiar la presencia de archivos ocultos en el sistema y especialmente en el directorio de la aplicación WEB).

**Ficheros:** _fileshidden.csv / fileshidden\_webdir.csv_

1. **Archivos cuya fecha de creación o modificación esté en el período del incidente** (búsqueda de archivos en el sistema y especialmente en la aplicación WEB que hayan sido creados o modificados en el período de estudio, algo que puede ser indicador de infección).

**Ficheros:** _filesperiod.csv / filesperiod\_webdir.csv_

1. **Archivos de tipo ejecutable o con permisos de ejecución** (se revisan y listan los archivos con permisos de ejecución, de tipo ejecutable que estén presentes en el sistema o principalmente en el directorio WEB o media).

**Ficheros:** _filesexecperm.csv / filesexecperm\_webdir.csv / filesexe\_media.csv_

1. **Archivos con extensiones ejecutables .sh, .exe y .bin** (se revisan y listan los archivos con extensiones de tipo .bin, .sh, .exe que estén en el sistema o principalmente presentes en el directorio WEB o media).

**Ficheros:** _filesbin.csv / filesbin\_webdir.csv_

1. **Archivos pertenecientes al usuario &quot;root&quot;** (algunos archivos que pertenecen al usuario o al grupo administrador del sistema puede indicar la presencia de un usuario administrador fuera de su contexto habitual).

**Ficheros:** _filesroot.csv / filesroot\_webdir.csv_

1. **Archivos que no pertenecen al usuario web dentro del directorio de la aplicación web** (dentro del directorio en el que reside la aplicación web, deberían figurar solamente archivos y directorios pertenecientes a este usuario. La presencia de archivos de otro usuario o grupo puede indicar la presencia de malware o simplemente mala administración, por lo que se deben vigilar estos archivos y directorios con precaución).

**Ficheros:** _filesbaduser\_webdir.csv_

1. **Revisar permisos de archivos y directorios del directorio de la aplicación web** (Folder permissions: 755, File permissions: 644, Mage permissions: 550, Configuration file permission: 440).

**Ficheros:** _filesbadperms\_webdir.csv / dirsbadperms\_webdir.csv_

1. **Búsqueda de scripts de instalación en el directorio de la aplicación web** (se buscan scripts en php de instalación de plataformas estándar que normalmente se nombran con nombres similares a install.php y por seguridad no deben estar presentes en el directorio web).

**Ficheros:** _installers\_webdir.txt_

1. **Listar para su revisión los ficheros .htaccess del servicio Web** (debido a sus especiales características en el servidor Web, los ficheros .htaccess ocultos pueden contener reglas, ejecuciones y filtros que los hacen muy peligrosos si son modificados por los atacantes).

**Ficheros:** _htaccess\_webdir.txt_

1. **Configuraciones de servicios Web** (aunque resulta una tarea ardua, se debe de revisar las configuraciones de servicios web como apache2 o en este caso nginx, así como las de servidores proxy y PHP en busca de configuraciones inseguras no intencionadas o intencionadas que permitan el acceso a directorios web, o la subida o ejecución de archivos maliciosos. Además se estudia la fecha de última modificación de estos ficheros y la versión de estos servicios).

**Ficheros:** _http.txt / HTTP\_SERVER\_DIR\_php.tar / HTTP\_SERVER\_DIR\_apache.tar.gz / HTTP\_SERVER\_DIR\_nginx.tgz_

1. **Versiones de otros interpretadores como Python y Perl** (se debe estudiar la presencia de runtimes de Python y Perl por si no debieran estar presentes y se lista su versión y librerías para buscar vulnerabilidades).

**Ficheros:** _python.txt / perl.txt_

1. **Compiladores y versiones presentes** (se debe estudiar la presencia de compiladores y lenguajes de compilación ya que lo normal y más recomendable es que no estén presentes en entornos de producción y se lista su versión para buscar vulnerabilidades).

**Ficheros:** _compilers.txt_

1. **Software criptográfico instalado** (se deberá revisar la versión de librerías y programas de cifrado como OpenSSL para buscar vulnerabilidades en el cifrado que puedan significar importantes fallos de seguridad, como ocurrió en ocasiones con TLS-SSL).

**Ficheros:** _crypto.txt_

1. **Búsqueda de certificados y claves privadas en el sistema** (los certificados y claves privadas se deben de manejar con suma precaución. Se busca la presencia de certificados y claves privadas relacionadas y se analizan sus propiedades. Se extrae el módulus de cada certificado y de cada clave para estudiar su coincidencia).

**Ficheros:** _certspub.txt / certskey.txt_

1. **Se buscan indicadores de compromiso y malware mediante análisis estático de código PHP, javascript, Ajax o Shell Script** (para ello se analizan posibles indicadores mediante comandos y código de programación habitualmente utilizado en la ejecución directa de código Shell o en la ofuscación de código).

1. **Análisis de Seguridad** (se descarga e instala la última versión compatible con el sistema operativo presente del escáner de seguridad lynis en búsqueda de configuraciones de seguridad débil o mejorable).

**Ficheros:** _lynis.log_

1. **Análisis de Malware** (se ejecutan las principales herramientas de detección de malware para Linux haciendo especial incapié en utilizar las últimas versiones en sus motores y las últimas actualizaciones de firmas. Se busca malware de todo tipo presente en ficheros web de tipo php, javascript, Shell o Ajax entre los que pueden figurar rootkits, shells, etc).

**Ficheros:** _chkrootkit.txt / rkhunter.txt / shelldetector.txt / neopi\_shelldetect.txt / php-malware-scanner.txt / php-malware-finder.txt_

1. **Análisis específico de Magento** (se localiza, instala y ejecutan las principales herramientas gratuitas o en versión de prueba relacionadas específicamente con la seguridad en aplicaciones Magento. Se ejecutan únicamente aquellas que permiten análisis offline o en sistemas live).

**Ficheros:** _magento\_malware.txt_

1. **Búsqueda de archivos de malware Magento conocidos** (con el mismo nombre que los utilizados en ataques a webs mediante las mismas o similares técnicas o que contengan keywords como &quot;onepage | checkout | onestep | firecheckout&quot;).

**Ficheros:** _magentomalware\_webdir.csv / magentoskimmer\_webdir.txt_

1. **Análisis de otros indicadores de compromiso IoC** (se buscan patrones presentes en archivos del sistema de archivo relacionados con malware, ofuscación de archivos en lenguajes PHP, o javascript como: passthru | shell\_exec | cmd| sh –c | system | phpinfo | base64\_decode | edoced\_46esab | chmod | mkdir | gzinflate | fopen | fclose | readfile | php\_uname | eval |atob).

**Ficheros:** _manual\_shelldetect.txt_

1. **Archivos o directorios extraños o dañados** (se analizan los archivos y directorios que puedan estar dañados o hayan sido dañados intencionadamente en búsqueda de indicadores de rootkits. Se listan los archivos sin usuario, sin grupo, con fechas en el futuro, o en un pasado muy lejano).

**Ficheros:** _filesnogroup.csv / filesnogroup\_webdir.csv / filesnouser.csv / filesnouser\_webdir.csv / filesfuture.csv / filesfuture\_webdir.csv / filesbefore2015.csv / filesbefore2015\_webdir.csv_

1. **Indicadores de &quot;leaks o data breach&quot; relacionados con robo de información en la empresa** (en muchos incidentes relacionados con el robo de datos, se manifiestan en el sistema archivos, habitualmente comprimidos de tamaño muy grande. Esto puede indicar además la presencia de backups por parte de los administradores que no deben de estar presentes en el sistema).

**Ficheros:** _filesgreater100MB.csv / filesgreater100MB\_webdir.csv / filesgreater10MB.csv / filesgreater10MB\_webdir.csv_

1. **Archivos que contengan el término &quot;password&quot; en el directorio Web** (debemos analizar principalmente aquellos archivos que contengan credenciales en el directorio de la aplicación web, ya que si incorporan credenciales de servicios o aplicaciones crean un potencial peligro en el sistema).

**Ficheros:** _passwords\_webdir.txt_

1. **Archivos que contengan términos relacionados con el hacking, exfiltración o servidores utilizados por cibercriminales** (podrán contener términos relacionados con sitios o direcciones habituales para la exfiltración de datos como: hack | malware | infected | compromis | protonmail | tormail | silentcircle | torguard | oneshar | pastebin | dropbox | drive.google).

**Ficheros:** _hack\_webdir.txt_

1. **Archivos que incluyan direcciones de correo, direcciones IP o enlaces URL dentro del directorio Web** (aunque esto genera muchos falsos positivos, la búsqueda de este tipo de endpoints dentro de archivos en el directorio Web podría indicar algún tipo de conexión o exfiltración de datos por parte del malware. Además se buscan scripts javascript externos al sistema en nodos remotos que puedan indicar compromiso o ejecución remota de código, presentes en malware de tipo minería mediante JS o keyloggers de datos).

**Ficheros:** _emails\_webdir.txt / urls\_webdir.txt / ips\_webdir.txt / javascript\_webdir.txt / jsendpoints\_webdir.txt_

1. **Análisis de PAN o números de tarjetas de crédito** (se utilizan al menos tres herramientas de búsqueda de patrones de tarjetas de crédito en ficheros presentes en el sistema de archivos. Se modifican algunas de ellas para generar reportes adecuados o por fallar en su ejecución).

**Ficheros:** _PANHunter.log / PANhunt.log_

1. **Análisis de logs de Nginx o de Apache2** (de forma externa, en el laboratorio se analizaran patrones de ataques web mediante el análisis de logs del servidor web nginx o apache2 y sus archivos de log estándar. Para ello se utilizan herramientas como Scalp para Linux).

**Ficheros:** _http.txt_

1. **Análisis de Bases de Datos** (se extraen las bases de datos MySQL presentes y se buscan patrones binarios, ofuscados o directamente en texto claro, como tarjetas de crédito, webshells, malware, etc. Búsqueda de patrones de tarjetas de crédito / débito en todo tipo de ficheros y en base de datos.

**Ficheros:** _mysql\_search.txt_

1. **Se archivan en formato tar comprimido mediante gzip los principales directorios** (se archivan y extraen los directorios &quot;logs, root, etc, home y www&quot; para el análisis posterior de otros datos de relevancia en el laboratorio forénsico).

**Ficheros:** _VAR\_LOG.tgz / ROOT\_HOME.tgz / ETC.tgz / HOME\_user.tgz / VAR\_WWW.tgz_

1. **Análisis dinámico mediante Google y otras webs de análisis de reputación** (aprovechamiento de los motores gratuitos existentes en el mercado para el análisis de reputación y de malware).

**Ficheros:** _loginsnow.txt_

1. **Errores durante la ejecución de comandos del script** (por motivos de depuración, este fichero muestra cualquier error que haya ocurrido durante la ejecución de cada uno de los comandos del script. Sólo es necesario en caso de errores para depuración).

**Ficheros:** _errors.txt_
