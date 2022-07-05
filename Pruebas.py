from scapy.all import *

# show_interfaces ()

# numeroInterfaz = int (input ("\nSelecciona una interfaz: "))

# interfaz = dev_from_index (numeroInterfaz)

# captura = sniff (count=3, iface=interfaz)

captura = sniff (count=10)
contadorPaquetes = int (0)

while True:
    if contadorPaquetes != 10:

        paquete = captura[contadorPaquetes]
        paquete = raw (paquete)

        paqueteArchivo = open (f"dns{contadorPaquetes}.bin", "wb")
        paqueteArchivo.write (paquete)
        paqueteArchivo.close ()

        contadorPaquetes += 1
    else:
        break