import threading
import platform
from scapy.all import ARP, Ether, srp
import time
from datetime import datetime
import socket
import configparser  # Para leer el archivo .conf
import os  # Para ejecutar el comando ping en el sistema
import pathlib  # Para manejo de rutas de manera más portátil

# Definición de la versión del programa
__version__ = "1.5.0"

# Registro de cambios (changelog)
__changelog__ = """
Versión 1.5.0:
- Portabilidad del programa para Linux, Windows y macOS.
- Creación automática de archivo de configuración si no existe.
- Detección automática del comando ping según el sistema operativo.
- Manejo de rutas de archivos usando pathlib.
"""

# Límite de intentos de escaneo fallidos antes de declarar la red como caída
MAX_INTENTOS = 5

def leer_configuracion(archivo_conf):
    """
    Lee la configuración desde un archivo .conf o lo crea si no existe.
    """
    config = configparser.ConfigParser()
    if not archivo_conf.exists():
        # Crear archivo de configuración por defecto si no existe
        print(f"{archivo_conf} no existe. Creando archivo de configuración predeterminado...")
        config['CONFIG'] = {
            'red': '192.168.1.0/24',
            'tiempo_espera': '10',
            'ip_ping': '8.8.8.8',
            'intervalo_ping': '5'
        }
        with open(archivo_conf, 'w') as configfile:
            config.write(configfile)
    
    config.read(archivo_conf)
    
    # Leer la configuración de la sección CONFIG
    red = config['CONFIG']['red']
    tiempo_espera = int(config['CONFIG']['tiempo_espera'])
    ip_ping = config['CONFIG']['ip_ping']
    intervalo_ping = int(config['CONFIG']['intervalo_ping'])
    
    return red, tiempo_espera, ip_ping, intervalo_ping

def obtener_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        hostname = "No disponible"
    return hostname

def obtener_nombre_archivo_log():
    fecha_actual = datetime.now().strftime('%d-%m-%Y')
    return f"{fecha_actual}_dispositivos_conectados.log"

def escribir_encabezado_log(archivo_log):
    with open(archivo_log, 'a') as file:
        file.write(f"=== Registro de dispositivos conectados - Versión {__version__} ===\n")
        file.write(f"Fecha de inicio del log: {datetime.now().strftime('%d-%m-%y %H:%M:%S')}\n")
        file.write(f"Changelog:\n{__changelog__}\n\n")

def escanear_red(red, tiempo_espera=1):
    dispositivos_previos = set()
    contador_caida_red = 0

    while True:
        try:
            arp = ARP(pdst=red)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            paquete = ether / arp
            resultado = srp(paquete, timeout=2, verbose=0)[0]
        except Exception as e:
            print(f"Error durante el escaneo: {e}")
            archivo_log = obtener_nombre_archivo_log()
            with open(archivo_log, 'a') as file:
                file.write(f"Error durante el escaneo: {e}\n")
            continue

        if not resultado:
            contador_caida_red += 1
            print(f"No se detectaron dispositivos en el escaneo. Intento {contador_caida_red}.")
            if contador_caida_red >= MAX_INTENTOS:
                fecha_anomalia = datetime.now().strftime('%d-%m-%y %H:%M:%S')
                mensaje_anomalia = f"ALERTA CRÍTICA: Red caída después de {MAX_INTENTOS} intentos en {fecha_anomalia}"
                print(mensaje_anomalia)
                archivo_log = obtener_nombre_archivo_log()
                with open(archivo_log, 'a') as file:
                    file.write(mensaje_anomalia + "\n")
                break
            time.sleep(tiempo_espera)
            continue
        else:
            contador_caida_red = 0

        dispositivos_actuales = set()
        for enviado, recibido in resultado:
            ip = recibido.psrc
            mac = recibido.hwsrc
            hostname = obtener_hostname(ip)
            dispositivos_actuales.add((ip, mac, hostname))

        nuevos_dispositivos = dispositivos_actuales - dispositivos_previos
        dispositivos_desconectados = dispositivos_previos - dispositivos_actuales

        if nuevos_dispositivos:
            print("Nuevos dispositivos conectados a la red:")
            for ip, mac, hostname in nuevos_dispositivos:
                fecha_conexion = datetime.now().strftime('%d-%m-%y %H:%M:%S')
                print(f"- IP: {ip}, MAC: {mac}, Hostname: {hostname} conectado en {fecha_conexion}")
                archivo_log = obtener_nombre_archivo_log()
                with open(archivo_log, 'a') as file:
                    file.write(f"IP: {ip}, MAC: {mac}, Hostname: {hostname} conectado en {fecha_conexion}\n")

        if dispositivos_desconectados:
            print("Dispositivos desconectados de la red:")
            for ip, mac, hostname in dispositivos_desconectados:
                fecha_desconexion = datetime.now().strftime('%d-%m-%y %H:%M:%S')
                print(f"- IP: {ip}, MAC: {mac}, Hostname: {hostname} desconectado en {fecha_desconexion}")
                archivo_log = obtener_nombre_archivo_log()
                with open(archivo_log, 'a') as file:
                    file.write(f"IP: {ip}, MAC: {mac}, Hostname: {hostname} desconectado en {fecha_desconexion}\n")

        dispositivos_previos = dispositivos_actuales
        time.sleep(tiempo_espera)

def monitorear_ping(ip, intervalo=1):
    """
    Monitorea el estado de la conexión con el IP especificado usando ping.
    Detecta el sistema operativo y ejecuta el comando correspondiente.
    """
    sistema = platform.system()
    ping_comando = "ping -n 1" if sistema == "Windows" else "ping -c 1"

    while True:
        response = os.system(f"{ping_comando} {ip} > /dev/null 2>&1")
        if response == 0:
            print(f"{ip} está en línea")
        else:
            fecha_anomalia = datetime.now().strftime('%d-%m-%y %H:%M:%S')
            mensaje_anomalia = f"ALERTA: Conexión perdida con {ip} a las {fecha_anomalia}"
            print(mensaje_anomalia)
            archivo_log = obtener_nombre_archivo_log()
            with open(archivo_log, 'a') as file:
                file.write(mensaje_anomalia + "\n")
        time.sleep(intervalo)

if __name__ == "__main__":
    # Usar pathlib para manejo de rutas
    archivo_conf = pathlib.Path("config.conf")
    
    # Leer la configuración desde el archivo .conf
    red, tiempo_espera, ip_ping, intervalo_ping = leer_configuracion(archivo_conf)

    print(f"Escaneando la red {red} cada {tiempo_espera} segundos...")
    print(f"Monitoreando la conexión a {ip_ping} con ping cada {intervalo_ping} segundo(s)...")
    print(f"Versión del programa: {__version__}")
    
    archivo_log = obtener_nombre_archivo_log()
    escribir_encabezado_log(archivo_log)

    # Crear hilos separados para escaneo de red y monitoreo de ping
    hilo_escanear_red = threading.Thread(target=escanear_red, args=(red, tiempo_espera))
    hilo_monitoreo_ping = threading.Thread(target=monitorear_ping, args=("8.8.8.8", intervalo_ping))

    # Iniciar ambos hilos
    hilo_escanear_red.start()
    hilo_monitoreo_ping.start()

    # Esperar a que ambos hilos terminen
    hilo_escanear_red.join()
    hilo_monitoreo_ping.join()
