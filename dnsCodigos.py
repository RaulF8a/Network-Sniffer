import codecs

def banderasDNS (banderas):
    #Query Response
    if (banderas[0] == "0"):
        print (f"        -> Consulta")
    else:
        print (f"        -> Respuesta")
    
    #Op code
    codigoOperacion = int (banderas[1:5], 2)
    if (codigoOperacion == 0):
        print (f"        -> Codigo de Operacion: {codigoOperacion} (Consulta Estandar)")

    elif (codigoOperacion == 1):
        print (f"        -> Codigo de Operacion: {codigoOperacion} (Consulta Inversa)")

    elif (codigoOperacion == 2):
        print (f"        -> Codigo de Operacion: {codigoOperacion} (Solicitud del Estado del Servidor)")
    
    #Autorithative Response
    if (banderas[5] == "1"):
        print ("        -> Respuesta Autoritativa: Permitida")
    else:
        print ("        -> Respuesta Autoritativa: No Permitida")
    
    #Truncado
    if (banderas[6] == "1"):
        print ("        -> Truncado: Activo")
    else:
        print ("        -> Truncado: Inactivo")
    
    #Recursividad Deseada
    if (banderas[7] == "1"):
        print ("        -> Recursividad Deseada: Si")
    else:
        print ("        -> Recursividad Deseada: No")
    
    #Recursividad Disponible
    if (banderas[8] == "1"):
        print ("        -> Recursividad Disponible: Si")
    else:
        print ("        -> Recursividad Disponible: No")

    #Codio de Respuesta
    codigoRespuesta = int (banderas[12:], 2)

    if (codigoRespuesta == 0):
        print (f"        -> Codigo Respuesta: {codigoRespuesta} (Ningun Error)")
    
    elif (codigoRespuesta == 1):
        print (f"        -> Codigo Respuesta: {codigoRespuesta} (Error de Formato)")
    
    elif (codigoRespuesta == 2):
        print (f"        -> Codigo Respuesta: {codigoRespuesta} (Fallo en el Servidor)")
    
    elif (codigoRespuesta == 3):
        print (f"        -> Codigo Respuesta: {codigoRespuesta} (Error en el Nombre)")
    
    elif (codigoRespuesta == 4):
        print (f"        -> Codigo Respuesta: {codigoRespuesta} (No Implementado)")
    
    elif (codigoRespuesta == 5):
        print (f"        -> Codigo Respuesta: {codigoRespuesta} (Rechazado)")
     
def leerLetras (archivo):
    texto = archivo.read (1)
    hexadecimal = texto.hex ()
    contadorLetras = int (bin (int (hexadecimal, 16))[2:].zfill(8), 2)

    return contadorLetras

def tipoRecurso (valor):
    if (valor == 1):
        print ("        -> Tipo de Recurso: A")
    
    elif (valor == 5):
        print ("        -> Tipo de Recurso: Nombre Canónico (CNAME)")
    
    elif (valor == 13):
        print ("        -> Tipo de Recurso: HINFO")

    elif (valor == 15):
        print ("        -> Tipo de Recurso: Intercambio de Correo (MX)")

    elif (valor == 28):
        print ("        -> Tipo de Recurso: AAAA")
    
    elif (valor == 22 or valor == 23):
        print ("        -> Tipo de Recurso: NS")

def clase (valor):
    if (valor == 1):
        print ("        -> Clase: IN")
    
    elif (valor == 3):
        print ("        -> Clase: CH")

def respuesta (archivo, tipoRecurso, inicioPaqueteDNS):
    if (tipoRecurso == 1):
        # print ("        -> Tipo de Recurso: A")
        # texto = archivo.read (4)
        # hexadecimal = texto.hex ()
        # direccionIP = bin (int(hexadecimal, 16))[2:].zfill(8)

        # print (f"        -> Direccion IP: {int (direccionIP[:8], 2)}.{int (direccionIP[8:16], 2)}.{int (direccionIP[16:24], 2)}.{int (direccionIP[24:], 2)}")

        contadorBytes = 0

        print (f"        -> Direccion: ", end='')

        while contadorBytes < 4:
            texto = archivo.read (1)
            hexadecimal = texto.hex ()

            if (contadorBytes == 3):
                print (f"{int (hexadecimal, 16)}")
            else:
                print (f"{int (hexadecimal, 16)}.", end='')

            contadorBytes += 1


    elif (tipoRecurso == 5):
        # print ("        -> Tipo de Recurso: Nombre Canónico (CNAME)")
        print ("        -> CNAME: ", end='')

        contadorLetras = leerLetras (archivo)
        
        while True:
            if (contadorLetras != 0):
                if (contadorLetras != 192):
                    texto = archivo.read (contadorLetras)
                    dominioCNAME = codecs.decode (texto, 'ASCII')
            
                    contadorLetras = leerLetras (archivo)

                    if (contadorLetras == 0):
                        print (f"{dominioCNAME}")
                        break
                    else:
                        print (f"{dominioCNAME}.", end='')
                else:
                    offset = int ((archivo.read (1)).hex (), 16)

                    posicionActual = archivo.tell ()

                    archivo.seek (inicioPaqueteDNS + offset)

                    dominio (archivo, inicioPaqueteDNS)

                    # print (posicionActual)
                    archivo.seek (posicionActual)

                    break
            else:
                break
            
    elif (tipoRecurso == 13):
        # print ("        -> Tipo de Recurso: HINFO")
        pass

    elif (tipoRecurso == 15):
        # print ("        -> Tipo de Recurso: Intercambio de Correo (MX)")
        pass
    
    elif (tipoRecurso == 22 or tipoRecurso == 23):
        # print ("        -> Tipo de Recurso: NS")
        pass

def calcularOffset (archivo):
    offset = int ((archivo.read (1)).hex (), 16)

    return offset

def dominio (archivo, inicioPaqueteDNS):
    contadorLetras = leerLetras (archivo)
    
    while True:
        if (contadorLetras != 0):
            if (contadorLetras != 192):
                texto = archivo.read (contadorLetras)
                dominioCNAME = codecs.decode (texto, 'ASCII')
        
                contadorLetras = leerLetras (archivo)

                if (contadorLetras == 0):
                    print (f"{dominioCNAME}")
                    break
                else:
                    print (f"{dominioCNAME}.", end='')
            else:
                offset = int ((archivo.read (1)).hex (), 16)

                posicionActual = archivo.tell ()

                archivo.seek (inicioPaqueteDNS + offset)

                dominio (archivo, inicioPaqueteDNS)

                archivo.seek (posicionActual)

                break
        else:
            break
