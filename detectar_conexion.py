from scapy.all import ARP, Ether, srp
import time
from datetime import datetime
import socket  # Para obtener el nombre del host
import argparse  # Para manejar argumentos de línea de comandos

# Definición de la versión del programa
__version__ = "1.3.0"

# Registro de cambios (changelog)
__changelog__ = """
Versión 1.3.0:
- Se agrega la opción de configurar la IP de la red y el tiempo de espera desde la consola.
- Se actualizan las funciones para aceptar estos parámetros de entrada.
"""

def obtener_hostname(ip):
    """
    Obtiene el nombre del host a partir de la dirección IP.
    """
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        hostname = "No disponible"
    return hostname

def obtener_nombre_archivo_log():
    """
    Genera el nombre del archivo de log basado en la fecha actual.
    """
    fecha_actual = datetime.now().strftime('%Y-%m-%d')
    return f"{fecha_actual}_dispositivos_conectados.log"

def escribir_encabezado_log(archivo_log):
    """
    Escribe el encabezado de la versión del programa en el archivo de log.
    """
    with open(archivo_log, 'a') as file:
        file.write(f"=== Registro de dispositivos conectados - Versión {__version__} ===\n")
        file.write(f"Fecha de inicio del log: {datetime.now().strftime('%d-%m-%y %H:%M:%S')}\n")
        file.write(f"Changelog:\n{__changelog__}\n\n")

def escanear_red(red, tiempo_espera=1):
    """
    Escanea la red en busca de dispositivos conectados y guarda las IPs, MACs y nombres de host con fecha de conexión.
    También detecta y registra anomalías, como caídas de red.
    
    Args:
        red (str): Rango de red a escanear. Ejemplo: '192.168.1.0/24'
        tiempo_espera (int): Tiempo en segundos entre cada escaneo.
    """
    dispositivos_previos = set()
    contador_caida_red = 0  # Contador para detectar múltiples intentos fallidos de escaneo

    while True:
        # Crea una solicitud ARP para la red
        arp = ARP(pdst=red)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        paquete = ether / arp
        
        # Envía el paquete y recibe la respuesta
        resultado = srp(paquete, timeout=2, verbose=0)[0]

        # Verificar si hay alguna respuesta
        if not resultado:
            contador_caida_red += 1
            print(f"No se detectaron dispositivos en el escaneo. Intento {contador_caida_red}.")
            # Si no hay respuestas en 3 escaneos consecutivos, se considera que la red podría estar caída
            if contador_caida_red >= 3:
                fecha_anomalia = datetime.now().strftime('%d-%m-%y %H:%M:%S')
                mensaje_anomalia = f"ALERTA: Posible caída de la red detectada en {fecha_anomalia}"
                print(mensaje_anomalia)
                # Guardar en el archivo de log
                archivo_log = obtener_nombre_archivo_log()
                with open(archivo_log, 'a') as file:
                    file.write(mensaje_anomalia + "\n")
            # Espera antes de intentar nuevamente
            time.sleep(tiempo_espera)
            continue
        else:
            contador_caida_red = 0  # Reinicia el contador si se recibe alguna respuesta

        # Obtener las IPs, MACs y nombres de host de los dispositivos conectados
        dispositivos_actuales = set()
        for enviado, recibido in resultado:
            ip = recibido.psrc
            mac = recibido.hwsrc
            hostname = obtener_hostname(ip)
            dispositivos_actuales.add((ip, mac, hostname))

        # Comparar dispositivos anteriores con los actuales para detectar nuevos dispositivos
        nuevos_dispositivos = dispositivos_actuales - dispositivos_previos
        if nuevos_dispositivos:
            print("Nuevos dispositivos conectados a la red:")
            for ip, mac, hostname in nuevos_dispositivos:
                # Obtener la fecha y hora actual
                fecha_conexion = datetime.now().strftime('%d-%m-%y %H:%M:%S')
                print(f"- IP: {ip}, MAC: {mac}, Hostname: {hostname} conectado en {fecha_conexion}")
                # Guardar en el archivo de log
                archivo_log = obtener_nombre_archivo_log()
                with open(archivo_log, 'a') as file:
                    file.write(f"IP: {ip}, MAC: {mac}, Hostname: {hostname} conectado en {fecha_conexion}\n")

        # Actualizar la lista de dispositivos previos
        dispositivos_previos = dispositivos_actuales

        # Espera antes de escanear nuevamente
        time.sleep(tiempo_espera)

if __name__ == "__main__":
    # Configuración de argumentos de línea de comandos
    parser = argparse.ArgumentParser(description="Escáner de red para detectar dispositivos conectados.")
    parser.add_argument('-r', '--red', type=str, default="192.168.100.0/24", help="Rango de red a escanear. Ejemplo: '192.168.1.0/24'")
    parser.add_argument('-t', '--tiempo', type=int, default=5, help="Tiempo de espera en segundos entre cada escaneo.")
    args = parser.parse_args()

    # Obtener los parámetros de la línea de comandos
    red = args.red
    tiempo_espera = args.tiempo
    
    print(f"Escaneando la red {red} cada {tiempo_espera} segundos...")
    print(f"Versión del programa: {__version__}")
    print(f"Changelog:\n{__changelog__}")
    
    # Obtener el nombre del archivo de log para hoy y escribir el encabezado
    archivo_log = obtener_nombre_archivo_log()
    escribir_encabezado_log(archivo_log)
    
    escanear_red(red, tiempo_espera)
