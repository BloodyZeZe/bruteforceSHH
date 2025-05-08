#!/usr/bin/env python3
"""
SSH Manager - Herramienta avanzada para conexiones SSH con múltiples funcionalidades.

Este script permite:
1. Probar múltiples credenciales contra servidores SSH
2. Ejecutar comandos remotos
3. Transferir archivos
4. Implementar túneles SSH
5. Realizar conexiones a múltiples servidores

Compatible con Python 3.6+
"""

import argparse
import concurrent.futures
import getpass
import logging
import os
import paramiko
import socket
import sys
import time
import threading
import re
from typing import Dict, List, Optional, Tuple, Union, Any
from datetime import datetime


# Configuración de logging
def configurar_logging(nivel_log: str = "INFO", archivo_log: Optional[str] = None) -> None:
    """
    Configura el sistema de logging.
    
    Args:
        nivel_log: Nivel de detalle del log (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        archivo_log: Ruta donde guardar el archivo de log (opcional)
    """
    formateador = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Convertir string de nivel a constante de logging
    nivel_numerico = getattr(logging, nivel_log.upper(), logging.INFO)
    
    # Configurar logger root
    logger = logging.getLogger()
    logger.setLevel(nivel_numerico)
    
    # Handler para consola
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formateador)
    logger.addHandler(console_handler)
    
    # Handler para archivo si se especificó
    if archivo_log:
        file_handler = logging.FileHandler(archivo_log)
        file_handler.setFormatter(formateador)
        logger.addHandler(file_handler)


class SSHManager:
    """Gestor completo para conexiones SSH"""
    
    def __init__(
        self,
        host: str = "",
        puerto: int = 22,
        usuario: str = "",
        contraseña: Optional[str] = None,
        clave_privada: Optional[str] = None,
        frase_clave: Optional[str] = None,
        timeout: int = 5,
        verbose: bool = False
    ):
        """
        Inicializa el gestor SSH con parámetros de conexión.
        
        Args:
            host: Dirección IP o hostname del servidor
            puerto: Puerto SSH (normalmente 22)
            usuario: Nombre de usuario
            contraseña: Contraseña para autenticación (opcional)
            clave_privada: Ruta a archivo de clave privada (opcional)
            frase_clave: Frase de la clave privada (opcional)
            timeout: Tiempo máximo de espera para la conexión en segundos
            verbose: Modo verboso para mostrar más información
        """
        self.host = host
        self.puerto = puerto
        self.usuario = usuario
        self.contraseña = contraseña
        self.clave_privada = clave_privada
        self.frase_clave = frase_clave
        self.timeout = timeout
        self.verbose = verbose
        self.cliente = None
        self.sftp = None
        self.canal_shell = None
        self.conectado = False
        
        # Configurar nivel de log según verbose
        self.logger = logging.getLogger(__name__)
        if verbose:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)
        
    def conectar(self) -> bool:
        """
        Establece conexión SSH al servidor.
        
        Returns:
            bool: True si la conexión fue exitosa, False en caso contrario
        """
        if self.conectado:
            self.logger.debug(f"Ya existe una conexión activa a {self.host}:{self.puerto}")
            return True
            
        self.cliente = paramiko.SSHClient()
        self.cliente.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            # Preparar argumentos para la conexión
            kwargs = {
                'hostname': self.host,
                'port': self.puerto,
                'username': self.usuario,
                'timeout': self.timeout,
                'allow_agent': False,
                'look_for_keys': False
            }
            
            # Añadir autenticación por contraseña o clave según lo proporcionado
            if self.contraseña:
                kwargs['password'] = self.contraseña
            elif self.clave_privada:
                if os.path.isfile(self.clave_privada):
                    key = paramiko.RSAKey.from_private_key_file(
                        self.clave_privada,
                        password=self.frase_clave
                    )
                    kwargs['pkey'] = key
                else:
                    self.logger.error(f"Archivo de clave privada no encontrado: {self.clave_privada}")
                    return False
            
            # Realizar la conexión
            self.logger.debug(f"Conectando a {self.host}:{self.puerto} como {self.usuario}...")
            self.cliente.connect(**kwargs)
            self.conectado = True
            self.logger.info(f"✅ Conexión establecida con {self.host}")
            return True
            
        except paramiko.AuthenticationException:
            self.logger.warning(f"❌ Error de autenticación en {self.host}")
            return False
        except (socket.timeout, paramiko.SSHException) as e:
            self.logger.error(f"❌ Error de conexión en {self.host}: {str(e)}")
            return False
        except Exception as e:
            self.logger.error(f"❌ Error inesperado al conectar a {self.host}: {str(e)}")
            return False
    
    def desconectar(self) -> None:
        """Cierra la conexión SSH y todos los recursos asociados"""
        if self.canal_shell:
            self.canal_shell.close()
            self.canal_shell = None
            
        if self.sftp:
            self.sftp.close()
            self.sftp = None
            
        if self.cliente:
            self.cliente.close()
            self.cliente = None
            
        self.conectado = False
        self.logger.debug(f"Conexión con {self.host} cerrada")
    
    def ejecutar_comando(self, comando: str, timeout: int = 60) -> Tuple[int, str, str]:
        """
        Ejecuta un comando en el servidor remoto.
        
        Args:
            comando: Comando a ejecutar
            timeout: Tiempo máximo de espera para la ejecución
            
        Returns:
            Tuple[int, str, str]: Código de salida, salida estándar y error estándar
        """
        if not self.conectado and not self.conectar():
            return (-1, "", "No se pudo establecer conexión")
            
        try:
            self.logger.debug(f"Ejecutando comando: {comando}")
            stdin, stdout, stderr = self.cliente.exec_command(comando, timeout=timeout)
            
            # Obtener salidas
            salida = stdout.read().decode('utf-8', errors='replace')
            error = stderr.read().decode('utf-8', errors='replace')
            codigo = stdout.channel.recv_exit_status()
            
            if self.verbose:
                if salida:
                    self.logger.debug(f"Salida estándar:\n{salida}")
                if error:
                    self.logger.debug(f"Error estándar:\n{error}")
                self.logger.debug(f"Código de salida: {codigo}")
                
            return (codigo, salida, error)
            
        except Exception as e:
            self.logger.error(f"Error al ejecutar comando '{comando}': {str(e)}")
            return (-1, "", str(e))
    
    def ejecutar_multiples_comandos(self, comandos: List[str]) -> List[Tuple[int, str, str]]:
        """
        Ejecuta múltiples comandos secuencialmente.
        
        Args:
            comandos: Lista de comandos a ejecutar
            
        Returns:
            List[Tuple[int, str, str]]: Lista con resultados de cada comando
        """
        resultados = []
        for comando in comandos:
            resultado = self.ejecutar_comando(comando)
            resultados.append(resultado)
            
            # Si un comando falla, podemos detener la ejecución
            if resultado[0] != 0:
                self.logger.warning(f"Comando '{comando}' falló con código {resultado[0]}")
                break
                
        return resultados
    
    def abrir_shell(self) -> bool:
        """
        Abre una sesión de shell interactiva.
        
        Returns:
            bool: True si se abrió correctamente, False en caso contrario
        """
        if not self.conectado and not self.conectar():
            return False
            
        try:
            self.canal_shell = self.cliente.invoke_shell()
            self.canal_shell.settimeout(self.timeout)
            self.logger.info(f"Shell interactiva abierta en {self.host}")
            return True
        except Exception as e:
            self.logger.error(f"Error al abrir shell interactiva: {str(e)}")
            return False
    
    import time
    import re

    def enviar_comando_shell(self, comando: str, esperar_salida: bool = True, timeout: int = 5) -> str:
        """
        Envía un comando a la shell interactiva y opcionalmente espera la salida.

        Args:
            comando (str): Comando a enviar.
            esperar_salida (bool): Si debe esperar y recoger la salida.
            timeout (int): Tiempo máximo de espera para la respuesta en segundos.

        Returns:
            str: Salida del comando si esperar_salida es True. Vacío en caso contrario o si ocurre un error.
        """
        if not self.canal_shell:
            if not self.abrir_shell():
                return "Error: no se pudo abrir shell interactiva"

        try:
            # Enviar el comando seguido de un salto de línea
            self.canal_shell.send(comando + "\n")

            if esperar_salida:
                tiempo_inicio = time.time()
                salida = ""

                while time.time() - tiempo_inicio < timeout:
                    if self.canal_shell.recv_ready():
                        # Leer fragmento de datos
                        chunk = self.canal_shell.recv(4096).decode('utf-8', errors='replace')
                        salida += chunk

                        # Verificar si el prompt ha regresado (usualmente $, # o >)
                        if re.search(r'[$#>]\s*$', chunk.strip()):
                            break

                    time.sleep(0.1)  # Evita uso excesivo de CPU

                return salida.strip()

            return ""

        except Exception as e:
            self.logger.error(f"Error en shell interactiva: {str(e)}")
            return f"Error: {str(e)}"
    
    def iniciar_sftp(self) -> bool:
        """
        Inicia una sesión SFTP para transferencia de archivos.
        
        Returns:
            bool: True si se inició correctamente, False en caso contrario
        """
        if not self.conectado and not self.conectar():
            return False
            
        try:
            self.sftp = self.cliente.open_sftp()
            self.logger.debug(f"Sesión SFTP iniciada con {self.host}")
            return True
        except Exception as e:
            self.logger.error(f"Error al iniciar sesión SFTP: {str(e)}")
            return False
    
    def subir_archivo(self, archivo_local: str, ruta_remota: str) -> bool:
        """
        Sube un archivo al servidor remoto.
        
        Args:
            archivo_local: Ruta del archivo local a subir
            ruta_remota: Ruta donde guardar el archivo en el servidor
            
        Returns:
            bool: True si la operación fue exitosa, False en caso contrario
        """
        if not self.sftp and not self.iniciar_sftp():
            return False
            
        try:
            if not os.path.isfile(archivo_local):
                self.logger.error(f"El archivo local no existe: {archivo_local}")
                return False
                
            self.logger.info(f"Subiendo {archivo_local} a {self.host}:{ruta_remota}")
            self.sftp.put(archivo_local, ruta_remota)
            self.logger.info(f"✅ Archivo subido correctamente")
            return True
        except Exception as e:
            self.logger.error(f"Error al subir archivo: {str(e)}")
            return False
    
    def descargar_archivo(self, archivo_remoto: str, ruta_local: str) -> bool:
        """
        Descarga un archivo desde el servidor remoto.
        
        Args:
            archivo_remoto: Ruta del archivo en el servidor
            ruta_local: Ruta donde guardar el archivo descargado
            
        Returns:
            bool: True si la operación fue exitosa, False en caso contrario
        """
        if not self.sftp and not self.iniciar_sftp():
            return False
            
        try:
            self.logger.info(f"Descargando {self.host}:{archivo_remoto} a {ruta_local}")
            self.sftp.get(archivo_remoto, ruta_local)
            self.logger.info(f"✅ Archivo descargado correctamente")
            return True
        except Exception as e:
            self.logger.error(f"Error al descargar archivo: {str(e)}")
            return False
    
    def listar_directorio(self, ruta_remota: str = '.') -> List[str]:
        """
        Lista el contenido de un directorio remoto.
        
        Args:
            ruta_remota: Ruta del directorio a listar
            
        Returns:
            List[str]: Lista de archivos y directorios
        """
        if not self.sftp and not self.iniciar_sftp():
            return []
            
        try:
            archivos = self.sftp.listdir(ruta_remota)
            return archivos
        except Exception as e:
            self.logger.error(f"Error al listar directorio {ruta_remota}: {str(e)}")
            return []
    
    def crear_directorio(self, ruta_remota: str) -> bool:
        """
        Crea un directorio en el servidor remoto.
        
        Args:
            ruta_remota: Ruta del directorio a crear
            
        Returns:
            bool: True si la operación fue exitosa, False en caso contrario
        """
        if not self.sftp and not self.iniciar_sftp():
            return False
            
        try:
            self.sftp.mkdir(ruta_remota)
            self.logger.debug(f"Directorio creado: {ruta_remota}")
            return True
        except Exception as e:
            self.logger.error(f"Error al crear directorio {ruta_remota}: {str(e)}")
            return False
    
    def obtener_info_sistema(self) -> Dict[str, str]:
        """
        Recopila información básica del sistema remoto.
        
        Returns:
            Dict[str, str]: Diccionario con información del sistema
        """
        info = {}
        
        # Comandos para obtener información
        comandos_info = {
            'hostname': 'hostname',
            'kernel': 'uname -r',
            'os': 'cat /etc/os-release | grep PRETTY_NAME',
            'uptime': 'uptime',
            'cpu': 'cat /proc/cpuinfo | grep "model name" | head -1',
            'memoria': 'free -h',
            'discos': 'df -h'
        }
        
        for clave, comando in comandos_info.items():
            codigo, salida, _ = self.ejecutar_comando(comando)
            if codigo == 0:
                info[clave] = salida.strip()
            else:
                info[clave] = "No disponible"
                
        return info
    
    def crear_tunel(self, puerto_local: int, host_destino: str, puerto_destino: int) -> bool:
        """
        Crea un túnel SSH desde un puerto local hacia un destino remoto.
        
        Args:
            puerto_local: Puerto local para escuchar conexiones
            host_destino: Host destino (desde la perspectiva del servidor SSH)
            puerto_destino: Puerto destino
            
        Returns:
            bool: True si el túnel se estableció correctamente, False en caso contrario
        """
        if not self.conectado and not self.conectar():
            return False
            
        try:
            # Crear hilo para el reenvío de puertos
            thread = threading.Thread(
                target=self._iniciar_reenvio,
                args=(puerto_local, host_destino, puerto_destino)
            )
            thread.daemon = True
            thread.start()
            
            self.logger.info(f"🔄 Túnel SSH establecido: localhost:{puerto_local} -> {host_destino}:{puerto_destino}")
            return True
        except Exception as e:
            self.logger.error(f"Error al crear túnel SSH: {str(e)}")
            return False
    
    def _iniciar_reenvio(self, puerto_local: int, host_destino: str, puerto_destino: int) -> None:
        """
        Método interno para iniciar el reenvío de puertos en un hilo separado.
        
        Args:
            puerto_local: Puerto local para escuchar conexiones
            host_destino: Host destino (desde la perspectiva del servidor SSH)
            puerto_destino: Puerto destino
        """
        try:
            # Iniciar el reenvío de puertos
            self.cliente.get_transport().request_port_forward('', puerto_local)
            
            while True:
                # Esperar a que llegue una conexión al puerto local
                chan = self.cliente.get_transport().accept(1000)
                if chan is None:
                    continue
                    
                # Crear un canal al destino
                dest_addr = (host_destino, puerto_destino)
                dest_chan = self.cliente.get_transport().open_channel('direct-tcpip', dest_addr, chan.getpeername())
                
                if dest_chan is None:
                    chan.close()
                    continue
                    
                # Iniciar hilos para reenviar datos en ambas direcciones
                threading.Thread(target=self._reenviar, args=(chan, dest_chan)).start()
                threading.Thread(target=self._reenviar, args=(dest_chan, chan)).start()
                
        except Exception as e:
            self.logger.error(f"Error en reenvío de puertos: {str(e)}")
    
    def _reenviar(self, origen: paramiko.Channel, destino: paramiko.Channel) -> None:
        """
        Método interno para reenviar datos entre canales SSH.
        
        Args:
            origen: Canal de origen
            destino: Canal de destino
        """
        try:
            while True:
                datos = origen.recv(1024)
                if not datos:
                    break
                destino.send(datos)
        except Exception:
            pass
        finally:
            origen.close()
            destino.close()


class SSHBruteForce:
    """Clase para realizar pruebas de credenciales SSH"""
    
    def __init__(
        self, 
        hosts: List[str], 
        puertos: List[int] = [22],
        usuarios: List[str] = ["root", "admin"],
        contraseñas: Optional[List[str]] = None,
        archivo_contraseñas: Optional[str] = None,
        timeout: int = 3,
        max_hilos: int = 5,
        intervalo: float = 1.0,
        verbose: bool = False
    ):
        """
        Inicializa el objeto para pruebas de credenciales.
        
        Args:
            hosts: Lista de hosts a probar
            puertos: Lista de puertos a probar
            usuarios: Lista de usuarios a probar
            contraseñas: Lista de contraseñas a probar (opcional)
            archivo_contraseñas: Ruta a un archivo con contraseñas (opcional)
            timeout: Tiempo máximo de espera para cada intento
            max_hilos: Número máximo de hilos concurrentes
            intervalo: Intervalo entre intentos para evitar bloqueos
            verbose: Modo verboso para mostrar más información
        """
        self.hosts = hosts
        self.puertos = puertos
        self.usuarios = usuarios
        self.timeout = timeout
        self.max_hilos = max_hilos
        self.intervalo = intervalo
        self.verbose = verbose
        self.logger = logging.getLogger(__name__)
        
        # Cargar contraseñas
        self.contraseñas = []
        if contraseñas:
            self.contraseñas = contraseñas
        if archivo_contraseñas:
            self._cargar_contraseñas_desde_archivo(archivo_contraseñas)
            
        if not self.contraseñas:
            self.contraseñas = ["password", "admin", "root", "123456", "toor", "1234"]
        
        # Resultados
        self.resultados = []
        
    def _cargar_contraseñas_desde_archivo(self, archivo: str) -> None:
        """
        Carga contraseñas desde un archivo.
        
        Args:
            archivo: Ruta al archivo de contraseñas
        """
        try:
            if not os.path.isfile(archivo):
                self.logger.error(f"Archivo de contraseñas no encontrado: {archivo}")
                return
                
            with open(archivo, 'r', encoding='utf-8', errors='ignore') as f:
                for linea in f:
                    pwd = linea.strip()
                    if pwd and pwd not in self.contraseñas:
                        self.contraseñas.append(pwd)
                        
            self.logger.info(f"Cargadas {len(self.contraseñas)} contraseñas desde {archivo}")
        except Exception as e:
            self.logger.error(f"Error al cargar contraseñas desde archivo: {str(e)}")
    
    def probar_credencial(self, host: str, puerto: int, usuario: str, contraseña: str) -> bool:
        """
        Prueba una credencial específica.
        
        Args:
            host: Host a probar
            puerto: Puerto SSH
            usuario: Nombre de usuario
            contraseña: Contraseña a probar
            
        Returns:
            bool: True si la autenticación fue exitosa, False en caso contrario
        """
        ssh = SSHManager(
            host=host,
            puerto=puerto,
            usuario=usuario,
            contraseña=contraseña,
            timeout=self.timeout,
            verbose=self.verbose
        )
        
        # Intentar conectar
        resultado = ssh.conectar()
        
        # Si conectó, guardar resultado y obtener información adicional
        if resultado:
            info_extra = {}
            try:
                codigo, salida, _ = ssh.ejecutar_comando("id")
                if codigo == 0:
                    info_extra["id"] = salida.strip()
                    
                codigo, salida, _ = ssh.ejecutar_comando("whoami")
                if codigo == 0:
                    info_extra["whoami"] = salida.strip()
            except Exception:
                pass
                
            # Guardar resultado exitoso
            self.resultados.append({
                "host": host,
                "puerto": puerto,
                "usuario": usuario,
                "contraseña": contraseña,
                "info_extra": info_extra,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
            
        # Cerrar conexión
        ssh.desconectar()
        return resultado
    
    def probar_host(self, host: str) -> List[Dict[str, Any]]:
        """
        Prueba todas las combinaciones de credenciales para un host.
        
        Args:
            host: Host a probar
            
        Returns:
            List[Dict[str, Any]]: Lista de credenciales exitosas
        """
        resultados_host = []
        
        self.logger.info(f"🔍 Iniciando pruebas en {host}")
        
        # Probar cada puerto
        for puerto in self.puertos:
            # Probar cada usuario
            for usuario in self.usuarios:
                self.logger.debug(f"Probando usuario: {usuario} en {host}:{puerto}")
                
                # Probar cada contraseña
                for i, contraseña in enumerate(self.contraseñas):
                    # Mensaje de progreso
                    if self.verbose or i % 10 == 0:
                        self.logger.debug(f"Intento {i+1}/{len(self.contraseñas)}: {usuario}@{host}:{puerto}")
                    
                    # Probar credencial
                    if self.probar_credencial(host, puerto, usuario, contraseña):
                        self.logger.info(f"✅ ¡Credencial válida encontrada! {usuario}:{contraseña}@{host}:{puerto}")
                        resultados_host.append({
                            "host": host,
                            "puerto": puerto,
                            "usuario": usuario,
                            "contraseña": contraseña
                        })
                        
                        # Si encontramos una credencial válida para este usuario, no seguimos probando
                        break
                        
                    # Pausa entre intentos
                    time.sleep(self.intervalo)
                    
        return resultados_host
    
    def ejecutar(self) -> List[Dict[str, Any]]:
        """
        Ejecuta pruebas en todos los hosts especificados.
        
        Returns:
            List[Dict[str, Any]]: Lista de todas las credenciales exitosas
        """
        self.resultados = []
        tiempo_inicio = time.time()
        
        self.logger.info(f"Iniciando pruebas de credenciales en {len(self.hosts)} hosts")
        self.logger.info(f"Usuarios a probar: {len(self.usuarios)}")
        self.logger.info(f"Contraseñas a probar: {len(self.contraseñas)}")
        
                    # Usar ThreadPoolExecutor para pruebas en paralelo
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_hilos) as executor:
            # Iniciar tareas para cada host
            futuros = {executor.submit(self.probar_host, host): host for host in self.hosts}
            
            # Procesar resultados a medida que se completan
            for futuro in concurrent.futures.as_completed(futuros):
                host = futuros[futuro]
                try:
                    # Obtener resultados
                    resultados_host = futuro.result()
                    if resultados_host:
                        self.logger.info(f"🎯 Encontradas {len(resultados_host)} credenciales válidas para {host}")
                    else:
                        self.logger.info(f"❌ No se encontraron credenciales válidas para {host}")
                except Exception as e:
                    self.logger.error(f"Error al procesar {host}: {str(e)}")
        
        # Estadísticas finales
        tiempo_total = time.time() - tiempo_inicio
        self.logger.info(f"✨ Prueba completada en {tiempo_total:.2f} segundos")
        self.logger.info(f"📊 Resultados: {len(self.resultados)} credenciales válidas encontradas")
        
        # Mostrar credenciales encontradas
        if self.resultados:
            self.logger.info("📝 Credenciales válidas:")
            for res in self.resultados:
                self.logger.info(f"  🔑 {res['usuario']}:{res['contraseña']}@{res['host']}:{res['puerto']}")
                
        return self.resultados
    
    def guardar_resultados(self, archivo: str) -> bool:
        """
        Guarda los resultados en un archivo.
        
        Args:
            archivo: Ruta del archivo donde guardar los resultados
            
        Returns:
            bool: True si se guardó correctamente, False en caso contrario
        """
        try:
            with open(archivo, 'w', encoding='utf-8') as f:
                # Cabecera
                f.write("# Resultados de pruebas SSH\n")
                f.write(f"# Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                # Detalles
                f.write("## Credenciales Válidas\n\n")
                
                if not self.resultados:
                    f.write("No se encontraron credenciales válidas.\n")
                else:
                    # Tabla de resultados
                    f.write("| Host | Puerto | Usuario | Contraseña | Información |\n")
                    f.write("|------|--------|---------|------------|-------------|\n")
                    
                    for res in self.resultados:
                        info = ""
                        if "info_extra" in res and res["info_extra"]:
                            for k, v in res["info_extra"].items():
                                info += f"{k}: {v}; "
                                
                        f.write(f"| {res['host']} | {res['puerto']} | {res['usuario']} | {res['contraseña']} | {info} |\n")
            
            self.logger.info(f"✅ Resultados guardados en {archivo}")
            return True
        except Exception as e:
            self.logger.error(f"Error al guardar resultados: {str(e)}")
            return False


class SSHCommander:
    """Clase para ejecutar comandos en múltiples servidores SSH"""
    
    def __init__(self, config_hosts: List[Dict[str, Any]], timeout: int = 10, verbose: bool = False):
        """
        Inicializa el gestor de comandos SSH.
        
        Args:
            config_hosts: Lista de diccionarios con configuración de hosts
                Ejemplo: [{"host": "1.2.3.4", "puerto": 22, "usuario": "root", "contraseña": "pass"}]
            timeout: Tiempo máximo de espera para las conexiones
            verbose: Modo verboso para mostrar más información
        """
        self.hosts = config_hosts
        self.timeout = timeout
        self.verbose = verbose
        self.logger = logging.getLogger(__name__)
        self.conexiones = {}  # Almacena las conexiones activas
        
    def conectar_todos(self) -> Dict[str, bool]:
        """
        Establece conexión con todos los hosts configurados.
        
        Returns:
            Dict[str, bool]: Diccionario con el estado de cada conexión
        """
        resultados = {}
        
        for config in self.hosts:
            host_id = f"{config['host']}:{config.get('puerto', 22)}"
            self.logger.info(f"Conectando a {host_id}...")
            
            # Crear gestor SSH
            ssh = SSHManager(
                host=config['host'],
                puerto=config.get('puerto', 22),
                usuario=config['usuario'],
                contraseña=config.get('contraseña'),
                clave_privada=config.get('clave_privada'),
                frase_clave=config.get('frase_clave'),
                timeout=self.timeout,
                verbose=self.verbose
            )
            
            # Intentar conectar
            if ssh.conectar():
                self.conexiones[host_id] = ssh
                resultados[host_id] = True
            else:
                resultados[host_id] = False
                
        # Resumen
        exitosos = sum(1 for v in resultados.values() if v)
        self.logger.info(f"Conexiones establecidas: {exitosos}/{len(self.hosts)}")
        
        return resultados
    
    def ejecutar_en_todos(self, comando: str) -> Dict[str, Tuple[int, str, str]]:
        """
        Ejecuta un comando en todos los servidores conectados.
        
        Args:
            comando: Comando a ejecutar
            
        Returns:
            Dict[str, Tuple[int, str, str]]: Resultados por host
        """
        resultados = {}
        
        # Conectar a hosts no conectados
        for config in self.hosts:
            host_id = f"{config['host']}:{config.get('puerto', 22)}"
            if host_id not in self.conexiones:
                ssh = SSHManager(
                    host=config['host'],
                    puerto=config.get('puerto', 22),
                    usuario=config['usuario'],
                    contraseña=config.get('contraseña'),
                    clave_privada=config.get('clave_privada'),
                    timeout=self.timeout,
                    verbose=self.verbose
                )
                if ssh.conectar():
                    self.conexiones[host_id] = ssh
        
        # Ejecutar comando en todos los hosts conectados
        self.logger.info(f"Ejecutando comando en {len(self.conexiones)} hosts: {comando}")
        
        for host_id, ssh in self.conexiones.items():
            self.logger.debug(f"Ejecutando en {host_id}...")
            resultado = ssh.ejecutar_comando(comando)
            resultados[host_id] = resultado
            
            # Mostrar resultado resumido
            codigo, salida, error = resultado
            if codigo == 0:
                self.logger.info(f"✅ {host_id}: Comando ejecutado correctamente")
                if self.verbose:
                    self.logger.debug(f"Salida: {salida[:100]}...")
            else:
                self.logger.warning(f"❌ {host_id}: Error (código {codigo})")
                if error:
                    self.logger.debug(f"Error: {error[:100]}...")
                    
        return resultados
    
    def ejecutar_script(self, ruta_script: str) -> Dict[str, List[Tuple[int, str, str]]]:
        """
        Ejecuta un script en todos los servidores conectados.
        
        Args:
            ruta_script: Ruta al script a ejecutar
            
        Returns:
            Dict[str, List[Tuple[int, str, str]]]: Resultados por host
        """
        resultados = {}
        
        # Verificar si el script existe
        if not os.path.isfile(ruta_script):
            self.logger.error(f"El script no existe: {ruta_script}")
            return resultados
            
        # Leer script
        try:
            with open(ruta_script, 'r') as f:
                lineas = f.readlines()
        except Exception as e:
            self.logger.error(f"Error al leer script: {str(e)}")
            return resultados
            
        # Filtrar comentarios y líneas vacías
        comandos = []
        for linea in lineas:
            linea = linea.strip()
            if linea and not linea.startswith('#'):
                comandos.append(linea)
                
        if not comandos:
            self.logger.warning("El script no contiene comandos válidos")
            return resultados
            
        # Ejecutar cada comando del script en todos los hosts
        for host_id, ssh in self.conexiones.items():
            self.logger.info(f"Ejecutando script en {host_id}...")
            resultados_host = []
            
            for comando in comandos:
                resultado = ssh.ejecutar_comando(comando)
                resultados_host.append(resultado)
                
                # Si un comando falla y no es el último, mostrar advertencia
                codigo = resultado[0]
                if codigo != 0:
                    self.logger.warning(f"❌ {host_id}: Comando '{comando}' falló con código {codigo}")
                    
            resultados[host_id] = resultados_host
            
        return resultados
    
    def subir_archivo_a_todos(self, archivo_local: str, ruta_remota: str) -> Dict[str, bool]:
        """
        Sube un archivo a todos los servidores conectados.
        
        Args:
            archivo_local: Ruta del archivo local
            ruta_remota: Ruta donde guardar el archivo en los servidores
            
        Returns:
            Dict[str, bool]: Resultados de la operación por host
        """
        resultados = {}
        
        # Verificar si el archivo existe
        if not os.path.isfile(archivo_local):
            self.logger.error(f"El archivo local no existe: {archivo_local}")
            return resultados
            
        # Subir a cada host
        for host_id, ssh in self.conexiones.items():
            self.logger.info(f"Subiendo archivo a {host_id}...")
            resultado = ssh.subir_archivo(archivo_local, ruta_remota)
            resultados[host_id] = resultado
            
            if resultado:
                self.logger.info(f"✅ {host_id}: Archivo subido correctamente")
            else:
                self.logger.warning(f"❌ {host_id}: Error al subir archivo")
                
        return resultados
    
    def desconectar_todos(self) -> None:
        """Cierra todas las conexiones SSH activas"""
        for host_id, ssh in self.conexiones.items():
            self.logger.debug(f"Cerrando conexión con {host_id}...")
            ssh.desconectar()
            
        self.conexiones = {}
        self.logger.info("Todas las conexiones cerradas")


def main():
    """Función principal que procesa argumentos y ejecuta operaciones"""
    # Configurar parser de argumentos
    parser = argparse.ArgumentParser(
        description="Herramienta avanzada para conexiones SSH",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  # Probar credenciales en un host
  python ssh_manager.py bruteforce -t 192.168.1.10 -u root -P passwords.txt
  
  # Ejecutar comando en un servidor
  python ssh_manager.py exec -t 192.168.1.10 -u admin -p secreto -c "ls -la"
  
  # Obtener información del sistema
  python ssh_manager.py info -t 192.168.1.10 -u admin -p secreto
  
  # Subir un archivo
  python ssh_manager.py upload -t 192.168.1.10 -u admin -p secreto -l archivo_local.txt -r /tmp/remoto.txt
  
  # Crear túnel SSH
  python ssh_manager.py tunnel -t 192.168.1.10 -u admin -p secreto -L 8080:127.0.0.1:80
        """
    )
    
    # Subparsers para diferentes comandos
    subparsers = parser.add_subparsers(dest="comando", help="Comando a ejecutar")
    
    # Parser para bruteforce
    bf_parser = subparsers.add_parser("bruteforce", help="Probar múltiples credenciales SSH")
    bf_parser.add_argument("-t", "--targets", required=True, nargs="+", help="Host(s) objetivo")
    bf_parser.add_argument("-p", "--ports", type=int, nargs="+", default=[22], help="Puerto(s) SSH (default: 22)")
    bf_parser.add_argument("-u", "--users", nargs="+", default=["root", "admin"], help="Usuario(s) a probar")
    bf_parser.add_argument("-P", "--passwords-file", help="Archivo con contraseñas")
    bf_parser.add_argument("-pw", "--passwords", nargs="+", help="Contraseña(s) a probar")
    bf_parser.add_argument("--threads", type=int, default=5, help="Número máximo de hilos (default: 5)")
    bf_parser.add_argument("--timeout", type=int, default=3, help="Timeout de conexión en segundos (default: 3)")
    bf_parser.add_argument("--delay", type=float, default=1.0, help="Retardo entre intentos en segundos (default: 1.0)")
    bf_parser.add_argument("-o", "--output", help="Archivo donde guardar resultados")
    
    # Parser para ejecutar comandos
    exec_parser = subparsers.add_parser("exec", help="Ejecutar comandos en servidor(s) SSH")
    exec_parser.add_argument("-t", "--targets", required=True, nargs="+", help="Host(s) objetivo")
    exec_parser.add_argument("-p", "--port", type=int, default=22, help="Puerto SSH (default: 22)")
    exec_parser.add_argument("-u", "--user", required=True, help="Usuario SSH")
    exec_parser.add_argument("-pw", "--password", help="Contraseña SSH")
    exec_parser.add_argument("-k", "--key-file", help="Archivo de clave privada")
    exec_parser.add_argument("-c", "--command", help="Comando a ejecutar")
    exec_parser.add_argument("-s", "--script", help="Archivo de script a ejecutar")
    exec_parser.add_argument("--timeout", type=int, default=10, help="Timeout de conexión en segundos (default: 10)")
    
    # Parser para transferencia de archivos
    transfer_parser = subparsers.add_parser("transfer", help="Transferir archivos con SSH")
    transfer_parser.add_argument("-t", "--target", required=True, help="Host objetivo")
    transfer_parser.add_argument("-p", "--port", type=int, default=22, help="Puerto SSH (default: 22)")
    transfer_parser.add_argument("-u", "--user", required=True, help="Usuario SSH")
    transfer_parser.add_argument("-pw", "--password", help="Contraseña SSH")
    transfer_parser.add_argument("-k", "--key-file", help="Archivo de clave privada")
    transfer_parser.add_argument("-l", "--local", required=True, help="Archivo o directorio local")
    transfer_parser.add_argument("-r", "--remote", required=True, help="Ruta remota")
    transfer_parser.add_argument("--upload", action="store_true", help="Subir archivo(s)")
    transfer_parser.add_argument("--download", action="store_true", help="Descargar archivo(s)")
    transfer_parser.add_argument("--timeout", type=int, default=10, help="Timeout de conexión en segundos (default: 10)")
    
    # Parser para información del sistema
    info_parser = subparsers.add_parser("info", help="Obtener información del sistema remoto")
    info_parser.add_argument("-t", "--target", required=True, help="Host objetivo")
    info_parser.add_argument("-p", "--port", type=int, default=22, help="Puerto SSH (default: 22)")
    info_parser.add_argument("-u", "--user", required=True, help="Usuario SSH")
    info_parser.add_argument("-pw", "--password", help="Contraseña SSH")
    info_parser.add_argument("-k", "--key-file", help="Archivo de clave privada")
    info_parser.add_argument("--timeout", type=int, default=10, help="Timeout de conexión en segundos (default: 10)")
    
    # Parser para túneles SSH
    tunnel_parser = subparsers.add_parser("tunnel", help="Crear túnel SSH")
    tunnel_parser.add_argument("-t", "--target", required=True, help="Host objetivo")
    tunnel_parser.add_argument("-p", "--port", type=int, default=22, help="Puerto SSH (default: 22)")
    tunnel_parser.add_argument("-u", "--user", required=True, help="Usuario SSH")
    tunnel_parser.add_argument("-pw", "--password", help="Contraseña SSH")
    tunnel_parser.add_argument("-k", "--key-file", help="Archivo de clave privada")
    tunnel_parser.add_argument("-L", "--local-forward", required=True, help="Reenvío local (formato: puerto_local:host_destino:puerto_destino)")
    tunnel_parser.add_argument("--timeout", type=int, default=10, help="Timeout de conexión en segundos (default: 10)")
    
    # Opciones comunes
    parser.add_argument("--debug", action="store_true", help="Activar modo debug")
    parser.add_argument("--log-file", help="Archivo de log")
    
    # Parsear argumentos
    args = parser.parse_args()
    
    # Configurar logging
    nivel_log = "DEBUG" if args.debug else "INFO"
    configurar_logging(nivel_log, args.log_file)
    logger = logging.getLogger(__name__)
    
    # Ejecutar comando correspondiente
    if args.comando == "bruteforce":
        # Iniciar bruteforce
        bruteforce = SSHBruteForce(
            hosts=args.targets,
            puertos=args.ports,
            usuarios=args.users,
            contraseñas=args.passwords,
            archivo_contraseñas=args.passwords_file,
            timeout=args.timeout,
            max_hilos=args.threads,
            intervalo=args.delay,
            verbose=args.debug
        )
        
        # Ejecutar prueba
        resultados = bruteforce.ejecutar()
        
        # Guardar resultados si se especificó
        if args.output and resultados:
            bruteforce.guardar_resultados(args.output)
            
    elif args.comando == "exec":
        if not (args.command or args.script):
            logger.error("Debe especificar un comando (-c) o un script (-s)")
            sys.exit(1)
            
        # Configurar hosts
        hosts_config = []
        for host in args.targets:
            hosts_config.append({
                "host": host,
                "puerto": args.port,
                "usuario": args.user,
                "contraseña": args.password,
                "clave_privada": args.key_file
            })
            
        # Iniciar commander
        commander = SSHCommander(
            config_hosts=hosts_config,
            timeout=args.timeout,
            verbose=args.debug
        )
        
        # Conectar
        commander.conectar_todos()
        
        # Ejecutar comando o script
        if args.command:
            commander.ejecutar_en_todos(args.command)
        else:
            commander.ejecutar_script(args.script)
            
        # Desconectar
        commander.desconectar_todos()
        
    elif args.comando == "transfer":
        if not (args.upload or args.download):
            logger.error("Debe especificar --upload o --download")
            sys.exit(1)
            
        # Crear gestor SSH
        ssh = SSHManager(
            host=args.target,
            puerto=args.port,
            usuario=args.user,
            contraseña=args.password,
            clave_privada=args.key_file,
            timeout=args.timeout,
            verbose=args.debug
        )
        
        # Conectar
        if not ssh.conectar():
            logger.error("No se pudo conectar al servidor")
            sys.exit(1)
            
        # Realizar transferencia
        if args.upload:
            ssh.subir_archivo(args.local, args.remote)
        else:
            ssh.descargar_archivo(args.remote, args.local)
            
        # Desconectar
        ssh.desconectar()
        
    elif args.comando == "info":
        # Crear gestor SSH
        ssh = SSHManager(
            host=args.target,
            puerto=args.port,
            usuario=args.user,
            contraseña=args.password,
            clave_privada=args.key_file,
            timeout=args.timeout,
            verbose=args.debug
        )
        
        # Conectar
        if not ssh.conectar():
            logger.error("No se pudo conectar al servidor")
            sys.exit(1)
            
        # Obtener información
        info = ssh.obtener_info_sistema()
        
        # Mostrar información
        print("\n===== INFORMACIÓN DEL SISTEMA =====")
        for clave, valor in info.items():
            print(f"\n--- {clave.upper()} ---")
            print(valor)
            
        # Desconectar
        ssh.desconectar()
        
    elif args.comando == "tunnel":
        # Parsear formato del reenvío local
        try:
            partes = args.local_forward.split(':')
            if len(partes) != 3:
                raise ValueError()
                
            puerto_local = int(partes[0])
            host_destino = partes[1]
            puerto_destino = int(partes[2])
        except:
            logger.error("Formato de reenvío local incorrecto. Use: puerto_local:host_destino:puerto_destino")
            sys.exit(1)
            
        # Crear gestor SSH
        ssh = SSHManager(
            host=args.target,
            puerto=args.port,
            usuario=args.user,
            contraseña=args.password,
            clave_privada=args.key_file,
            timeout=args.timeout,
            verbose=args.debug
        )
        
        # Conectar
        if not ssh.conectar():
            logger.error("No se pudo conectar al servidor")
            sys.exit(1)
            
        # Crear túnel
        if ssh.crear_tunel(puerto_local, host_destino, puerto_destino):
            logger.info(f"Túnel establecido: localhost:{puerto_local} -> {host_destino}:{puerto_destino}")
            logger.info("Presione Ctrl+C para salir")
            
            try:
                # Mantener el programa en ejecución
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                logger.info("Cerrando túnel...")
            finally:
                ssh.desconectar()
    else:
        # Si no se especificó ningún comando o uno no válido
        parser.print_help()


if __name__ == "__main__":
    main()