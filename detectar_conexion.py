from scapy.all import ARP, Ether, srp
import time
from datetime import datetime
import socket
import configparser
import os
import sys
import signal

# Definición de la versión del programa
__version__ = "1.4.1"

# Registro de cambios (changelog)
__changelog__ = """
Versión 1.4.1:
- Se modifica la IP de la red a 192.168.100.0/24.
- Se monitorea la IP 192.168.100.1 con ping para detectar la pérdida de conexión.
- Se agrega manejo de señales para terminar el script con Ctrl + C.
"""

def leer_configuracion(archivo_conf):
    """
    Lee la configuración desde un archivo .conf.
    """
    config = configparser.ConfigParser()
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
    fecha_actual = datetime.now().strftime('%Y-%m-%d')
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
        arp = ARP(pdst=red)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        paquete = ether / arp
        resultado = srp(paquete, timeout=2, verbose=0)[0]

        if not resultado:
            contador_caida_red += 1
            print(f"No se detectaron dispositivos en el escaneo. Intento {contador_caida_red}.")
            if contador_caida_red >= 3:
                fecha_anomalia = datetime.now().strftime('%d-%m-%y %H:%M:%S')
                mensaje_anomalia = f"ALERTA: Posible caída de la red detectada en {fecha_anomalia}"
                print(mensaje_anomalia)
                archivo_log = obtener_nombre_archivo_log()
                with open(archivo_log, 'a') as file:
                    file.write(mensaje_anomalia + "\n")
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
        if nuevos_dispositivos:
            print("Nuevos dispositivos conectados a la red:")
            for ip, mac, hostname in nuevos_dispositivos:
                fecha_conexion = datetime.now().strftime('%d-%m-%y %H:%M:%S')
                print(f"- IP: {ip}, MAC: {mac}, Hostname: {hostname} conectado en {fecha_conexion}")
                archivo_log = obtener_nombre_archivo_log()
                with open(archivo_log, 'a') as file:
                    file.write(f"IP: {ip}, MAC: {mac}, Hostname: {hostname} conectado en {fecha_conexion}\n")

        dispositivos_previos = dispositivos_actuales
        time.sleep(tiempo_espera)

def monitorear_ping(ip, intervalo=1):
    while True:
        response = os.system(f"ping -c 1 {ip} > /dev/null 2>&1")
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

def detener_script(signal, frame):
    print("\nProceso interrumpido. Cerrando el programa.")
    sys.exit(0)

if __name__ == "__main__":
    # Manejo de señales para detener el script con Ctrl + C
    signal.signal(signal.SIGINT, detener_script)

    # Leer la configuración desde el archivo .conf o usar las IPs por defecto
    archivo_conf = "config.conf"
    if not os.path.exists(archivo_conf):
        print("El archivo de configuración no existe, usando valores por defecto.")
        red = "192.168.100.0/24"
        ip_ping = "192.168.100.1"
        tiempo_espera = 5  # Segundos
        intervalo_ping = 1  # Segundos
    else:
        red, tiempo_espera, ip_ping, intervalo_ping = leer_configuracion(archivo_conf)

    print(f"Escaneando la red {red} cada {tiempo_espera} segundos...")
    print(f"Monitoreando la conexión a {ip_ping} con ping cada {intervalo_ping} segundo(s)...")
    print(f"Versión del programa: {__version__}")
    
    archivo_log = obtener_nombre_archivo_log()
    escribir_encabezado_log(archivo_log)

    # Iniciar el escaneo de red
    escanear_red(red, tiempo_espera)
    
    # Monitorear la conexión a la IP objetivo usando ping
    monitorear_ping(ip_ping, intervalo_ping)
