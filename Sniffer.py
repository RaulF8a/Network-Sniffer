from io import *
from os import system
from scapy.all import *
import codecs
import icmpCodigos
import arpCodigos
import icmpv6Codigos
import tcpCodigos
import dnsCodigos

system ("cls")

puntos = ":"
contadorPaquetes = 0

show_interfaces ()

numeroInterfaz = int (input ("\nSelecciona una interfaz (valor de Index): "))
interfaz = dev_from_index (numeroInterfaz)

paquetesALeer = 30
captura = sniff (count=paquetesALeer, iface=interfaz)

system ("cls")

while True:
    if (contadorPaquetes != paquetesALeer):
        paquete = captura[contadorPaquetes]
        paquete = raw (paquete)

        paqueteArchivo = open ("paquete.bin", "wb")
        paqueteArchivo.write (paquete)
        paqueteArchivo.close ()

        archivo = open ('paquete.bin', "rb+")
        contadorPaquetes += 1

        print ("\t\t                ETHERNET\n")

        texto = archivo.read (6)
        direccionMACOrigen = texto.hex ()
        direccionMACOrigen = puntos.join (direccionMACOrigen[i:i+2] for i in range(0, len(direccionMACOrigen), 2))
        print (f"- Direccion MAC de Origen: {direccionMACOrigen}")

        texto = archivo.read (6)
        direccionMACDes = texto.hex ()
        direccionMACDes = puntos.join (direccionMACDes[i:i+2] for i in range(0, len(direccionMACDes), 2))
        print (f"- Direccion MAC de Destino: {direccionMACDes}")

        texto = archivo.read (2)
        codigo = texto.hex ()

        if codigo == "0800":
            print (f"- Tipo: {codigo} IPv4")

            print ("\n\t\t                 IPv4")

            #Version y Longitud
            texto = archivo.read (1)
            hexadecimal = texto.hex ()
            byte1 = bin(int(hexadecimal, 16))[2:].zfill(8)

            print (f"- Version: {int(byte1[:4], 2)}")
            print (f"- Longitud: {int(byte1[4:], 2)} palabras")

            #Servicios Diferenciados
            texto = archivo.read (1)
            hexadecimal = texto.hex ()
            byte2 = bin(int(hexadecimal, 16))[2:].zfill(8)

            #Prioridad
            if (byte2[:3] == "000"):
                print ("- Prioridad: De rutina")

            elif (byte2[:3] == "001"):
                print ("- Prioridad: Prioritario")

            elif (byte2[:3] == "010"):
                print ("- Prioridad: Inmediato")

            elif (byte2[:3] == "011"):
                print ("- Prioridad: Relampago")

            elif (byte2[:3] == "100"):
                print ("- Prioridad: Invalidacion Relampago")
            
            elif (byte2[:3] == "101"):
                print ("- Prioridad: Procesando llamada critica y de emergencia")
            
            elif (byte2[:3] == "110"):
                print ("- Prioridad: Control de trabajo de internet")
            
            elif (byte2[:3] == "111"):
                print ("- Prioridad: Control de red")

            #Retardo
            if (byte2[3] == "0"):
                print ("- Retardo: Normal")
            else:
                print ("- Retardo: Bajo")
            
            #Rendimiento
            if (byte2[4] == "0"):
                print ("- Rendimiento: Normal")
            else:
                print ("- Rendimiento: Alto")
            
            #Fiabilidad
            if (byte2[5] == "0"):
                print ("- Fiabilidad: Normal")
            else:
                print ("- Fiabilidad: Alta")
            
            #Longitud Total
            texto = archivo.read (2)
            hexadecimal = texto.hex ()
            byte34 = bin(int(hexadecimal, 16))[2:].zfill(8)

            print (f"- Longitud Total: {int (byte34, 2)} bytes")

            #Identificacion
            texto = archivo.read (2)
            hexadecimal = texto.hex ()
            byte56 = bin(int(hexadecimal, 16))[2:].zfill(8)

            print (f"- Identificacion: {int (byte56, 2)}")

            #Flags y Posicion del Fragmento
            texto = archivo.read (1)
            hexadecimal = texto.hex ()
            byte7 = bin(int(hexadecimal, 16))[2:].zfill(8)

            #Flag1 Divisble
            if (byte7[1] == "0"):
                print ("- Divisible: Si")
            else:
                print ("- Divisible: No (NF)")

            #Flag2 Fragmento Final o no
            if (byte7[2] == "0"):
                print ("- Ultimo fragmento")
            else:
                print ("- Fragmento intermedio")

            #Posicion del fragmento
            texto = archivo.read (1)
            hexadecimal = texto.hex ()
            byte8 = bin(int(hexadecimal, 16))[2:].zfill(8)

            posicionFragmento = byte7[3:] + byte8

            print (f"- Posicion del Fragmento: {int (posicionFragmento, 2)}")

            #Tiempo de vida
            texto = archivo.read (1)
            hexadecimal = texto.hex ()
            byte9 = bin(int(hexadecimal, 16))[2:].zfill(8)

            print (f"- Tiempo de Vida (TTL): {int (byte9, 2)}")

            #Protocolo
            texto = archivo.read (1)
            hexadecimal = texto.hex ()
            byte10 = bin(int(hexadecimal, 16))[2:].zfill(8)
            protocolo = int (byte10, 2)
            
            #Suma de Control de Cabecera
            texto = archivo.read (2)
            byteOnceDoce = texto.hex ()

            print (f"- Checksum: {byteOnceDoce}")

            #Direccion IP de Origen
            texto = archivo.read (4)
            hexadecimal = texto.hex ()
            direccionIPOrigen = bin (int(hexadecimal, 16))[2:].zfill(8)

            print (f"- Direccion IP del Origen: {int (direccionIPOrigen[:8], 2)}.{int (direccionIPOrigen[8:16], 2)}.{int (direccionIPOrigen[16:24], 2)}.{int (direccionIPOrigen[24:], 2)}")

            #Direccion IP de Destino
            texto = archivo.read (4)
            hexadecimal = texto.hex ()
            direccionIPDestino = bin (int(hexadecimal, 16))[2:].zfill(8)

            print (f"- Direccion IP del Destino: {int (direccionIPDestino[:8], 2)}.{int (direccionIPDestino[8:16], 2)}.{int (direccionIPDestino[16:24], 2)}.{int (direccionIPDestino[24:], 2)}")

            if (protocolo == 1):
                print ("- Protocolo: ICMPv4")
                texto = archivo.read (1)
                hexadecimal = texto.hex ()
                tipoMensaje = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                icmpCodigos.icmpMensaje (tipoMensaje)

                texto = archivo.read (1)
                hexadecimal = texto.hex ()
                codigoError = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                icmpCodigos.icmpCodigoError (codigoError)

                texto = archivo.read (2)
                checksum = texto.hex ()

                print (f"    -> Checksum: {checksum}")

                print ("\n")

            elif (protocolo == 6):
                print ("- Protocolo: TCP")
                texto = archivo.read (2)
                hexadecimal = texto.hex ()
                puertoOrigen = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                tcpCodigos.tipoPuertoOrigen (puertoOrigen)

                texto = archivo.read (2)
                hexadecimal = texto.hex ()
                puertoDestino = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                tcpCodigos.tipoPuertoDestino (puertoDestino)    

                texto = archivo.read (4)
                hexadecimal = texto.hex ()
                numeroSecuencia = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                print (f"    -> Numero de Secuencia: {numeroSecuencia}")

                texto = archivo.read (4)
                hexadecimal = texto.hex ()
                numeroAcuse = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                print (f"    -> Numero de Acuse de Recibido: {numeroAcuse}") 

                texto = archivo.read (1)
                hexadecimal = texto.hex ()
                byte13 = bin (int (hexadecimal, 16))[2:].zfill(8)

                longitudCabecera = int (byte13[:4], 2)
                print (f"    -> Longitud de Cabecera: {longitudCabecera} palabras")

                reservado = int (byte13[4:7], 2)
                print (f"    -> Reservado: {reservado}")

                texto = archivo.read (1)
                hexadecimal = texto.hex ()
                aux = bin (int (hexadecimal, 16))[2:].zfill(8)
                banderas = byte13[7] + aux

                tcpCodigos.banderas (banderas)

                texto = archivo.read (2)
                hexadecimal = texto.hex ()
                tamanioVentana = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                print (f"    -> Tamaño de Ventana: {tamanioVentana} bytes")
                
                texto = archivo.read (2)
                checksum = texto.hex ()

                print (f"    -> Checksum: {checksum}")

                texto = archivo.read (2)
                hexadecimal = texto.hex ()
                punteroUrgente = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                if (banderas[3] == 1):
                    print (f"    -> Puntero Urgente: {punteroUrgente} bytes")

                if (puertoOrigen == 53 or puertoDestino == 53):
                    print ("\n    - Paquete DNS")

                    inicioPaqueteDNS = archivo.tell ()
                    texto = archivo.read (2)
                    transID = texto.hex ()
                    
                    print (f"        -> ID de Transaccion: {transID}")

                    texto = archivo.read (1)
                    hexadecimal = texto.hex ()
                    parte1 = bin (int (hexadecimal, 16))[2:].zfill(8)

                    texto = archivo.read (1)
                    hexadecimal = texto.hex ()
                    parte2 = bin (int (hexadecimal, 16))[2:].zfill(8)

                    banderas = parte1 + parte2

                    dnsCodigos.banderasDNS (banderas)

                    texto = archivo.read (2)
                    hexadecimal = texto.hex ()
                    queryCount = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                    print (f"        -> Question Entries Count: {queryCount}")

                    texto = archivo.read (2)
                    hexadecimal = texto.hex ()
                    anCount = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)
                    
                    print (f"        -> Answer RRs Count: {anCount}")

                    texto = archivo.read (2)
                    hexadecimal = texto.hex ()
                    auCount = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)
                    
                    print (f"        -> Authority RRs Count: {auCount}")

                    texto = archivo.read (2)
                    hexadecimal = texto.hex ()
                    arCount = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)
                    
                    print (f"        -> Additional Records RRs Count: {arCount}")

                    print ("")
                    contadorLetras = dnsCodigos.leerLetras (archivo)
                    print ("        -> Dominio (Pregunta): ", end='')

                    #Campos de pregunta.
                    while True:
                        if (queryCount != 0):
                            if (contadorLetras >= 1):
                                texto = archivo.read (contadorLetras)
                                dominio = codecs.decode (texto, 'ASCII')
                        
                                contadorLetras = dnsCodigos.leerLetras (archivo)

                                if (contadorLetras == 0):
                                    print (f"{dominio}")
                                else:
                                    print (f"{dominio}.", end='')
                            else:
                                queryCount -= 1
                                break
                        else:
                            break
                    
                    texto = archivo.read (2)
                    hexadecimal = texto.hex ()
                    tipoRecurso = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                    dnsCodigos.tipoRecurso (tipoRecurso)

                    texto = archivo.read (2)
                    hexadecimal = texto.hex ()
                    clase = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                    dnsCodigos.clase (clase)

                    print ("")

                    #Campos de respuesta.
                    while True:    
                        if (anCount != 0):
                            print (f"        -> Dominio (Respuesta): ", end='')
                            
                            while True:
                                texto = archivo.read (1)
                                hexadecimal = texto.hex ()
                                # print (hexadecimal)
                                if (hexadecimal == "c0"):
                                    offset = dnsCodigos.calcularOffset (archivo)

                                    posicionActualDNS = archivo.tell ()
                                    archivo.seek (inicioPaqueteDNS + offset)

                                    dnsCodigos.dominio (archivo, inicioPaqueteDNS)

                                    break
                                else:
                                    break
                            

                            archivo.seek (posicionActualDNS)

                            texto = archivo.read (2)
                            hexadecimal = texto.hex ()
                            tipoRecurso = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                            dnsCodigos.tipoRecurso (tipoRecurso)

                            texto = archivo.read (2)
                            hexadecimal = texto.hex ()
                            clase = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                            dnsCodigos.clase (clase)

                            texto = archivo.read (4)
                            hexadecimal = texto.hex ()
                            tiempoDeVida = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                            print (f"        -> Tiempo de Vida: {tiempoDeVida}")

                            texto = archivo.read (2)
                            hexadecimal = texto.hex ()
                            longitudDeDatos = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)
                            
                            print (f"        -> Longitud de Datos: {longitudDeDatos}")

                            dnsCodigos.respuesta (archivo, tipoRecurso, inicioPaqueteDNS)

                            print ("")

                            anCount -= 1
                            # archivo.seek (archivo.tell () - 1)
                        else:
                            break
            
            elif (protocolo == 17):
                print ("- Protocolo: UDP")

                texto = archivo.read (2)
                hexadecimal = texto.hex ()
                puertoOrigenUDP = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                tcpCodigos.tipoPuertoOrigen (puertoOrigenUDP)

                texto = archivo.read (2)
                hexadecimal = texto.hex ()
                puertoDestinoUDP = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                tcpCodigos.tipoPuertoDestino (puertoDestinoUDP)

                texto = archivo.read (2)
                hexadecimal = texto.hex ()
                longitudTotal = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                print (f"    -> Longitud Total: {longitudTotal} bytes")

                texto = archivo.read (2)
                checksum = texto.hex ()

                print (f"    -> Checksum: {checksum}")

                if (puertoOrigenUDP == 53 or puertoDestinoUDP == 53):
                    print ("\n    - Paquete DNS")

                    inicioPaqueteDNS = archivo.tell ()
                    texto = archivo.read (2)
                    transID = texto.hex ()
                    
                    print (f"        -> ID de Transaccion: {transID}")

                    texto = archivo.read (1)
                    hexadecimal = texto.hex ()
                    parte1 = bin (int (hexadecimal, 16))[2:].zfill(8)

                    texto = archivo.read (1)
                    hexadecimal = texto.hex ()
                    parte2 = bin (int (hexadecimal, 16))[2:].zfill(8)

                    banderas = parte1 + parte2

                    dnsCodigos.banderasDNS (banderas)

                    texto = archivo.read (2)
                    hexadecimal = texto.hex ()
                    queryCount = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                    print (f"        -> Question Entries Count: {queryCount}")

                    texto = archivo.read (2)
                    hexadecimal = texto.hex ()
                    anCount = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)
                    
                    print (f"        -> Answer RRs Count: {anCount}")

                    texto = archivo.read (2)
                    hexadecimal = texto.hex ()
                    auCount = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)
                    
                    print (f"        -> Authority RRs Count: {auCount}")

                    texto = archivo.read (2)
                    hexadecimal = texto.hex ()
                    arCount = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)
                    
                    print (f"        -> Additional Records RRs Count: {arCount}")

                    print ("")
                    contadorLetras = dnsCodigos.leerLetras (archivo)
                    print ("        -> Dominio (Pregunta): ", end='')

                    #Campos de pregunta.
                    while True:
                        if (queryCount != 0):
                            if (contadorLetras >= 1):
                                texto = archivo.read (contadorLetras)
                                dominio = codecs.decode (texto, 'ASCII')
                        
                                contadorLetras = dnsCodigos.leerLetras (archivo)

                                if (contadorLetras == 0):
                                    print (f"{dominio}")
                                else:
                                    print (f"{dominio}.", end='')
                            else:
                                queryCount -= 1
                                break
                        else:
                            break
                    
                    texto = archivo.read (2)
                    hexadecimal = texto.hex ()
                    tipoRecurso = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                    dnsCodigos.tipoRecurso (tipoRecurso)

                    texto = archivo.read (2)
                    hexadecimal = texto.hex ()
                    clase = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                    dnsCodigos.clase (clase)

                    print ("")

                    #Campos de respuesta.
                    while True:    
                        if (anCount != 0):
                            print (f"        -> Dominio (Respuesta): ", end='')
                            
                            while True:
                                texto = archivo.read (1)
                                hexadecimal = texto.hex ()
                                # print (hexadecimal)
                                if (hexadecimal == "c0"):
                                    offset = dnsCodigos.calcularOffset (archivo)

                                    posicionActualDNS = archivo.tell ()
                                    archivo.seek (inicioPaqueteDNS + offset)

                                    dnsCodigos.dominio (archivo, inicioPaqueteDNS)

                                    break
                                else:
                                    break
                            

                            archivo.seek (posicionActualDNS)

                            texto = archivo.read (2)
                            hexadecimal = texto.hex ()
                            tipoRecurso = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                            dnsCodigos.tipoRecurso (tipoRecurso)

                            texto = archivo.read (2)
                            hexadecimal = texto.hex ()
                            clase = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                            dnsCodigos.clase (clase)

                            texto = archivo.read (4)
                            hexadecimal = texto.hex ()
                            tiempoDeVida = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                            print (f"        -> Tiempo de Vida: {tiempoDeVida}")

                            texto = archivo.read (2)
                            hexadecimal = texto.hex ()
                            longitudDeDatos = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)
                            
                            print (f"        -> Longitud de Datos: {longitudDeDatos}")

                            dnsCodigos.respuesta (archivo, tipoRecurso, inicioPaqueteDNS)

                            print ("")

                            anCount -= 1
                            # archivo.seek (archivo.tell () - 1)
                        else:
                            break

        elif codigo == "0806":
            print (f"- Tipo: {codigo} ARP")

            print ("\n\t\t                 ARP\n")
            texto = archivo.read (2)
            hexadecimal = texto.hex ()
            tipoHardware = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

            arpCodigos.tipoHardware (tipoHardware)

            texto = archivo.read (2)
            hexadecimal = texto.hex ()

            arpCodigos.protocolo (hexadecimal)

            texto = archivo.read (1)
            hexadecimal = texto.hex ()
            longitudMAC = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

            print (f"- Longitud de la Direccion de Hardware: {longitudMAC} bytes")

            texto = archivo.read (1)
            hexadecimal = texto.hex ()
            longitudProtocolo = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

            print (f"- Longitud de la Direccion de Protocolo: {longitudProtocolo} bytes")

            texto = archivo.read (2)
            hexadecimal = texto.hex ()
            codigoOP = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

            arpCodigos.codigoDeOperacion (codigoOP)

            #Direccion Hardware = 6 bytes, Direccion del Protocolo = 4 bytes
            texto = archivo.read (6)
            direccionHardEmisor = texto.hex ()
            direccionHardEmisor = puntos.join (direccionHardEmisor[i:i+2] for i in range(0, len(direccionHardEmisor), 2))
            
            print (f"- Direccion de Hardware del Emisor: {direccionHardEmisor}")

            texto = archivo.read (4)
            hexadecimal = texto.hex ()
            direccionProtocoloEmisor = bin (int(hexadecimal, 16))[2:].zfill(8)

            print (f"- Direccion IP del Destino: {int (direccionProtocoloEmisor[:8], 2)}.{int (direccionProtocoloEmisor[8:16], 2)}.{int (direccionProtocoloEmisor[16:24], 2)}.{int (direccionProtocoloEmisor[24:], 2)}")

            texto = archivo.read (6)
            direccionHardReceptor = texto.hex ()
            direccionHardReceptor = puntos.join (direccionHardReceptor[i:i+2] for i in range(0, len(direccionHardReceptor), 2))
            
            print (f"- Direccion de Hardware del Receptor: {direccionHardReceptor}")

            texto = archivo.read (4)
            hexadecimal = texto.hex ()
            direccionProtocoloReceptor = bin (int(hexadecimal, 16))[2:].zfill(8)

            print (f"- Direccion IP del Destino: {int (direccionProtocoloReceptor[:8], 2)}.{int (direccionProtocoloReceptor[8:16], 2)}.{int (direccionProtocoloReceptor[16:24], 2)}.{int (direccionProtocoloReceptor[24:], 2)}")

            print ("\n")

        elif codigo == "8035":
            print (f"- Tipo: {codigo} RARP")

            print ("\n\t\t                 RARP\n")
            texto = archivo.read (2)
            hexadecimal = texto.hex ()
            tipoHardware = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

            arpCodigos.tipoHardware (tipoHardware)

            texto = archivo.read (2)
            hexadecimal = texto.hex ()

            arpCodigos.protocolo (hexadecimal)

            texto = archivo.read (1)
            hexadecimal = texto.hex ()
            longitudMAC = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

            print (f"- Longitud de la Direccion de Hardware: {longitudMAC} bytes")

            texto = archivo.read (1)
            hexadecimal = texto.hex ()
            longitudProtocolo = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

            print (f"- Longitud de la Direccion de Protocolo: {longitudProtocolo} bytes")

            texto = archivo.read (2)
            hexadecimal = texto.hex ()
            codigoOP = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

            arpCodigos.codigoDeOperacion (codigoOP)

            #Direccion Hardware = 6 bytes, Direccion del Protocolo = 4 bytes
            texto = archivo.read (6)
            direccionHardEmisor = texto.hex ()
            direccionHardEmisor = puntos.join (direccionHardEmisor[i:i+2] for i in range(0, len(direccionHardEmisor), 2))
            
            print (f"- Direccion de Hardware del Emisor: {direccionHardEmisor}")

            texto = archivo.read (4)
            hexadecimal = texto.hex ()
            direccionProtocoloEmisor = bin (int(hexadecimal, 16))[2:].zfill(8)

            print (f"- Direccion IP del Destino: {int (direccionProtocoloEmisor[:8], 2)}.{int (direccionProtocoloEmisor[8:16], 2)}.{int (direccionProtocoloEmisor[16:24], 2)}.{int (direccionProtocoloEmisor[24:], 2)}")

            texto = archivo.read (6)
            direccionHardReceptor = texto.hex ()
            direccionHardReceptor = puntos.join (direccionHardReceptor[i:i+2] for i in range(0, len(direccionHardReceptor), 2))
            
            print (f"- Direccion de Hardware del Receptor: {direccionHardReceptor}")

            texto = archivo.read (4)
            hexadecimal = texto.hex ()
            direccionProtocoloReceptor = bin (int(hexadecimal, 16))[2:].zfill(8)

            print (f"- Direccion IP del Destino: {int (direccionProtocoloReceptor[:8], 2)}.{int (direccionProtocoloReceptor[8:16], 2)}.{int (direccionProtocoloReceptor[16:24], 2)}.{int (direccionProtocoloReceptor[24:], 2)}")

            print ("\n")

        elif codigo == "86dd":
            print (f"- Tipo: {codigo} IPv6")

            print ("\n\t\t                 IPv6")

            texto = archivo.read (1)
            hexadecimal = texto.hex ()
            byte1 = bin(int(hexadecimal, 16))[2:].zfill(8)

            print (f"- Version: {int(byte1[:4], 2)}")

            texto = archivo.read (1)
            hexadecimal = texto.hex ()
            byte2 = bin(int(hexadecimal, 16))[2:].zfill(8)
            
            claseTrafico = byte1[4:] + byte2[:4]

            if (claseTrafico[:3] == "000"):
                print ("- Prioridad: De rutina")

            elif (claseTrafico[:3] == "001"):
                print ("- Prioridad: Prioritario")

            elif (claseTrafico[:3] == "010"):
                print ("- Prioridad: Inmediato")

            elif (claseTrafico[:3] == "011"):
                print ("- Prioridad: Relampago")

            elif (claseTrafico[:3] == "100"):
                print ("- Prioridad: Invalidacion Relampago")
            
            elif (claseTrafico[:3] == "101"):
                print ("- Prioridad: Procesando llamada critica y de emergencia")
            
            elif (claseTrafico[:3] == "110"):
                print ("- Prioridad: Control de trabajo de internet")
            
            elif (claseTrafico[:3] == "111"):
                print ("- Prioridad: Control de red")

            #Retardo
            if (claseTrafico[3] == "0"):
                print ("- Retardo: Normal")
            else:
                print ("- Retardo: Bajo")
            
            #Rendimiento
            if (claseTrafico[4] == "0"):
                print ("- Rendimiento: Normal")
            else:
                print ("- Rendimiento: Alto")
            
            #Fiabilidad
            if (claseTrafico[5] == "0"):
                print ("- Fiabilidad: Normal")
            else:
                print ("- Fiabilidad: Alta")

            #Etiqueta de Flujo
            texto = archivo.read (2)
            hexadecimal = texto.hex ()
            byte34 = bin(int(hexadecimal, 16))[2:].zfill(8)

            etiquetaFlujo = byte2[4:] + byte34

            print (f"- Etiqueta de Flujo: {int(etiquetaFlujo, 2)}")

            texto = archivo.read (2)
            hexadecimal = texto.hex ()
            byte56 = bin(int(hexadecimal, 16))[2:].zfill(8)

            print (f"- Longitud del Campo de Datos: {int(byte56, 2)} octetos")

            texto = archivo.read (1)
            hexadecimal = texto.hex ()
            encabezadoSiguiente = int (bin(int(hexadecimal, 16))[2:].zfill(8), 2)
            
            texto = archivo.read (1)
            hexadecimal = texto.hex ()
            limiteSaltos = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

            print (f"- Limite de Saltos: {limiteSaltos}")

            texto = archivo.read (16)
            direccionIPV6Origen = texto.hex ()
            direccionIPV6Origen = puntos.join (direccionIPV6Origen[i:i+4] for i in range(0, len(direccionIPV6Origen), 4))

            print (f"- Direccion IPv6 de Origen: {direccionIPV6Origen}")

            texto = archivo.read (16)
            direccionIPV6Destino = texto.hex ()
            direccionIPV6Destino = puntos.join (direccionIPV6Destino[i:i+4] for i in range(0, len(direccionIPV6Destino), 4))

            print (f"- Direccion IPv6 de Destino: {direccionIPV6Destino}")

            if (encabezadoSiguiente == 1):
                print ("- Protocolo: ICMPv4")
                texto = archivo.read (1)
                hexadecimal = texto.hex ()
                tipoMensaje = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                icmpCodigos.icmpMensaje (tipoMensaje)

                texto = archivo.read (1)
                hexadecimal = texto.hex ()
                codigoError = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                icmpCodigos.icmpCodigoError (codigoError)

                texto = archivo.read (2)
                checksum = texto.hex ()

                print (f"    -> Checksum: {checksum}")

                print ("\n")

            elif (encabezadoSiguiente == 6):
                print ("- Protocolo: TCP")
                texto = archivo.read (2)
                hexadecimal = texto.hex ()
                puertoOrigen = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                tcpCodigos.tipoPuertoOrigen (puertoOrigen)

                texto = archivo.read (2)
                hexadecimal = texto.hex ()
                puertoDestino = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                tcpCodigos.tipoPuertoDestino (puertoDestino)    

                texto = archivo.read (4)
                hexadecimal = texto.hex ()
                numeroSecuencia = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                print (f"    -> Numero de Secuencia: {numeroSecuencia}")

                texto = archivo.read (4)
                hexadecimal = texto.hex ()
                numeroAcuse = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                print (f"    -> Numero de Acuse de Recibido: {numeroAcuse}") 

                texto = archivo.read (1)
                hexadecimal = texto.hex ()
                byte13 = bin (int (hexadecimal, 16))[2:].zfill(8)

                longitudCabecera = int (byte13[:4], 2)
                print (f"    -> Longitud de Cabecera: {longitudCabecera} palabras")

                reservado = int (byte13[4:7], 2)
                print (f"    -> Reservado: {reservado}")

                texto = archivo.read (1)
                hexadecimal = texto.hex ()
                aux = bin (int (hexadecimal, 16))[2:].zfill(8)
                banderas = byte13[7] + aux

                tcpCodigos.banderas (banderas)

                texto = archivo.read (2)
                hexadecimal = texto.hex ()
                tamanioVentana = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                print (f"    -> Tamaño de Ventana: {tamanioVentana} bytes")
                
                texto = archivo.read (2)
                checksum = texto.hex ()

                print (f"    -> Checksum: {checksum}")

                texto = archivo.read (2)
                hexadecimal = texto.hex ()
                punteroUrgente = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                if (banderas[3] == 1):
                    print (f"    -> Puntero Urgente: {punteroUrgente} bytes")

                if (puertoOrigen == 53 or puertoDestino == 53):
                    print ("\n    - Paquete DNS")

                    inicioPaqueteDNS = archivo.tell ()
                    texto = archivo.read (2)
                    transID = texto.hex ()
                    
                    print (f"        -> ID de Transaccion: {transID}")

                    texto = archivo.read (1)
                    hexadecimal = texto.hex ()
                    parte1 = bin (int (hexadecimal, 16))[2:].zfill(8)

                    texto = archivo.read (1)
                    hexadecimal = texto.hex ()
                    parte2 = bin (int (hexadecimal, 16))[2:].zfill(8)

                    banderas = parte1 + parte2

                    dnsCodigos.banderasDNS (banderas)

                    texto = archivo.read (2)
                    hexadecimal = texto.hex ()
                    queryCount = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                    print (f"        -> Question Entries Count: {queryCount}")

                    texto = archivo.read (2)
                    hexadecimal = texto.hex ()
                    anCount = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)
                    
                    print (f"        -> Answer RRs Count: {anCount}")

                    texto = archivo.read (2)
                    hexadecimal = texto.hex ()
                    auCount = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)
                    
                    print (f"        -> Authority RRs Count: {auCount}")

                    texto = archivo.read (2)
                    hexadecimal = texto.hex ()
                    arCount = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)
                    
                    print (f"        -> Additional Records RRs Count: {arCount}")

                    print ("")
                    contadorLetras = dnsCodigos.leerLetras (archivo)
                    print ("        -> Dominio (Pregunta): ", end='')

                    #Campos de pregunta.
                    while True:
                        if (queryCount != 0):
                            if (contadorLetras >= 1):
                                texto = archivo.read (contadorLetras)
                                dominio = codecs.decode (texto, 'ASCII')
                        
                                contadorLetras = dnsCodigos.leerLetras (archivo)

                                if (contadorLetras == 0):
                                    print (f"{dominio}")
                                else:
                                    print (f"{dominio}.", end='')
                            else:
                                queryCount -= 1
                                break
                        else:
                            break
                    
                    texto = archivo.read (2)
                    hexadecimal = texto.hex ()
                    tipoRecurso = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                    dnsCodigos.tipoRecurso (tipoRecurso)

                    texto = archivo.read (2)
                    hexadecimal = texto.hex ()
                    clase = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                    dnsCodigos.clase (clase)

                    print ("")

                    #Campos de respuesta.
                    while True:    
                        if (anCount != 0):
                            print (f"        -> Dominio (Respuesta): ", end='')
                            
                            while True:
                                texto = archivo.read (1)
                                hexadecimal = texto.hex ()
                                # print (hexadecimal)
                                if (hexadecimal == "c0"):
                                    offset = dnsCodigos.calcularOffset (archivo)

                                    posicionActualDNS = archivo.tell ()
                                    archivo.seek (inicioPaqueteDNS + offset)

                                    dnsCodigos.dominio (archivo, inicioPaqueteDNS)

                                    break
                                else:
                                    break
                            

                            archivo.seek (posicionActualDNS)

                            texto = archivo.read (2)
                            hexadecimal = texto.hex ()
                            tipoRecurso = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                            dnsCodigos.tipoRecurso (tipoRecurso)

                            texto = archivo.read (2)
                            hexadecimal = texto.hex ()
                            clase = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                            dnsCodigos.clase (clase)

                            texto = archivo.read (4)
                            hexadecimal = texto.hex ()
                            tiempoDeVida = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                            print (f"        -> Tiempo de Vida: {tiempoDeVida}")

                            texto = archivo.read (2)
                            hexadecimal = texto.hex ()
                            longitudDeDatos = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)
                            
                            print (f"        -> Longitud de Datos: {longitudDeDatos}")

                            dnsCodigos.respuesta (archivo, tipoRecurso, inicioPaqueteDNS)

                            print ("")

                            anCount -= 1
                            # archivo.seek (archivo.tell () - 1)
                        else:
                            break

            elif (encabezadoSiguiente == 17):
                print ("- Protocolo: UDP")

                texto = archivo.read (2)
                hexadecimal = texto.hex ()
                puertoOrigenUDP = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                tcpCodigos.tipoPuertoOrigen (puertoOrigenUDP)

                texto = archivo.read (2)
                hexadecimal = texto.hex ()
                puertoDestinoUDP = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                tcpCodigos.tipoPuertoDestino (puertoDestinoUDP)

                texto = archivo.read (2)
                hexadecimal = texto.hex ()
                longitudTotal = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                print (f"    -> Longitud Total: {longitudTotal} bytes")

                texto = archivo.read (2)
                checksum = texto.hex ()

                print (f"    -> Checksum: {checksum}")

                if (puertoOrigenUDP == 53 or puertoDestinoUDP == 53):
                    print ("\n    - Paquete DNS")

                    inicioPaqueteDNS = archivo.tell ()
                    texto = archivo.read (2)
                    transID = texto.hex ()
                    
                    print (f"        -> ID de Transaccion: {transID}")

                    texto = archivo.read (1)
                    hexadecimal = texto.hex ()
                    parte1 = bin (int (hexadecimal, 16))[2:].zfill(8)

                    texto = archivo.read (1)
                    hexadecimal = texto.hex ()
                    parte2 = bin (int (hexadecimal, 16))[2:].zfill(8)

                    banderas = parte1 + parte2

                    dnsCodigos.banderasDNS (banderas)

                    texto = archivo.read (2)
                    hexadecimal = texto.hex ()
                    queryCount = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                    print (f"        -> Question Entries Count: {queryCount}")

                    texto = archivo.read (2)
                    hexadecimal = texto.hex ()
                    anCount = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)
                    
                    print (f"        -> Answer RRs Count: {anCount}")

                    texto = archivo.read (2)
                    hexadecimal = texto.hex ()
                    auCount = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)
                    
                    print (f"        -> Authority RRs Count: {auCount}")

                    texto = archivo.read (2)
                    hexadecimal = texto.hex ()
                    arCount = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)
                    
                    print (f"        -> Additional Records RRs Count: {arCount}")

                    print ("")
                    contadorLetras = dnsCodigos.leerLetras (archivo)
                    print ("        -> Dominio (Pregunta): ", end='')

                    #Campos de pregunta.
                    while True:
                        if (queryCount != 0):
                            if (contadorLetras >= 1):
                                texto = archivo.read (contadorLetras)
                                dominio = codecs.decode (texto, 'ASCII')
                        
                                contadorLetras = dnsCodigos.leerLetras (archivo)

                                if (contadorLetras == 0):
                                    print (f"{dominio}")
                                else:
                                    print (f"{dominio}.", end='')
                            else:
                                queryCount -= 1
                                break
                        else:
                            break
                    
                    texto = archivo.read (2)
                    hexadecimal = texto.hex ()
                    tipoRecurso = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                    dnsCodigos.tipoRecurso (tipoRecurso)

                    texto = archivo.read (2)
                    hexadecimal = texto.hex ()
                    clase = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                    dnsCodigos.clase (clase)

                    print ("")

                    #Campos de respuesta.
                    while True:    
                        if (anCount != 0):
                            print (f"        -> Dominio (Respuesta): ", end='')
                            
                            while True:
                                texto = archivo.read (1)
                                hexadecimal = texto.hex ()
                                # print (hexadecimal)
                                if (hexadecimal == "c0"):
                                    offset = dnsCodigos.calcularOffset (archivo)

                                    posicionActualDNS = archivo.tell ()
                                    archivo.seek (inicioPaqueteDNS + offset)

                                    dnsCodigos.dominio (archivo, inicioPaqueteDNS)

                                    break
                                else:
                                    break
                            

                            archivo.seek (posicionActualDNS)

                            texto = archivo.read (2)
                            hexadecimal = texto.hex ()
                            tipoRecurso = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                            dnsCodigos.tipoRecurso (tipoRecurso)

                            texto = archivo.read (2)
                            hexadecimal = texto.hex ()
                            clase = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                            dnsCodigos.clase (clase)

                            texto = archivo.read (4)
                            hexadecimal = texto.hex ()
                            tiempoDeVida = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                            print (f"        -> Tiempo de Vida: {tiempoDeVida}")

                            texto = archivo.read (2)
                            hexadecimal = texto.hex ()
                            longitudDeDatos = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)
                            
                            print (f"        -> Longitud de Datos: {longitudDeDatos}")

                            dnsCodigos.respuesta (archivo, tipoRecurso, inicioPaqueteDNS)

                            print ("")

                            anCount -= 1
                            # archivo.seek (archivo.tell () - 1)
                        else:
                            break

            elif (encabezadoSiguiente == 58):
                print ("- Protocolo: ICMPv6")

                texto = archivo.read (1)
                hexadecimal = texto.hex ()
                tipoMensaje6 = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                texto = archivo.read (1)
                hexadecimal = texto.hex ()
                codigoError6 = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

                icmpv6Codigos.tipoMensaje (tipoMensaje6, codigoError6)

                texto = archivo.read (2)
                checksum = texto.hex ()

                print (f"    -> Checksum: {checksum}")

            elif (encabezadoSiguiente == 118):
                print ("- Protocolo: STP")

            elif (encabezadoSiguiente == 121):
                print ("- Protocolo: SMP")

        print ("")

        texto = archivo.read ()
        datos = texto.hex ()
        datos = puntos.join (datos[i:i+2] for i in range(0, len(datos), 2))
        print (f"Datos: {datos}")

        archivo.close ()

        print ("\n------------------------------------------------------------------------------------------------------------------------------------\n")

    else:
        break
