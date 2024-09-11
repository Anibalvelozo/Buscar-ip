from scapy.all import ARP, Ether, srp
import time
from datetime import datetime

def escanear_red(red, tiempo_espera=5, archivo_log='dispositivos_conectados.log'):
    """
    Escanea la red en busca de dispositivos conectados y guarda las IPs con fecha de conexión.
    
    Args:
        red (str): Rango de red a escanear. Ejemplo: '192.168.1.0/24'
        tiempo_espera (int): Tiempo en segundos entre cada escaneo.
        archivo_log (str): Nombre del archivo donde se guardará el log de dispositivos conectados.
    """
    dispositivos_previos = set()

    while True:
        # Crea una solicitud ARP para la red
        arp = ARP(pdst=red)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        paquete = ether/arp
        
        # Envía el paquete y recibe la respuesta
        resultado = srp(paquete, timeout=2, verbose=0)[0]

        # Obtener las IP de los dispositivos conectados
        dispositivos_actuales = set()
        for enviado, recibido in resultado:
            dispositivos_actuales.add(recibido.psrc)

        # Comparar dispositivos anteriores con los actuales para detectar nuevos dispositivos
        nuevos_dispositivos = dispositivos_actuales - dispositivos_previos
        if nuevos_dispositivos:
            print("Nuevos dispositivos conectados a la red:")
            for dispositivo in nuevos_dispositivos:
                # Obtener la fecha y hora actual
                fecha_conexion = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                print(f"- {dispositivo} conectado en {fecha_conexion}")
                # Guardar en el archivo de log
                with open(archivo_log, 'a') as file:
                    file.write(f"{dispositivo} conectado en {fecha_conexion}\n")

        # Actualizar la lista de dispositivos previos
        dispositivos_previos = dispositivos_actuales

        # Espera antes de escanear nuevamente
        time.sleep(tiempo_espera)

if __name__ == "__main__":
    # Define la red a escanear, ajusta esto según tu red
    red = "192.168.100.0/24"
    # Define el tiempo de espera entre escaneos
    tiempo_espera = 10
    print(f"Escaneando la red {red} cada {tiempo_espera} segundos...")
    escanear_red(red, tiempo_espera)
