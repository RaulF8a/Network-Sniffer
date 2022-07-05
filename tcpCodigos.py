def tipoPuertoOrigen (valor):
    if (0 <= valor <= 1023):
        print (f"    -> Puerto de Origen: {valor} (Bien Conocido)")

        if (valor == 20):
            print ("    -> Tipo de Servicio: FTP")
        elif (valor == 21):
            print ("    -> Tipo de Servicio: FTP")
        elif (valor == 22):
            print ("    -> Tipo de Servicio: SSH")
        elif (valor == 23):
            print ("    -> Tipo de Servicio: TELNET")
        elif (valor == 25):
            print ("    -> Tipo de Servicio: SMTP")
        elif (valor == 53):
            print ("    -> Tipo de Servicio: DNS")
        elif (valor == 67):
            print ("    -> Tipo de Servicio: DHCP")
        elif (valor == 68):
            print ("    -> Tipo de Servicio: DHCP")
        elif (valor == 69):
            print ("    -> Tipo de Servicio: TFTP")
        elif (valor == 80):
            print ("    -> Tipo de Servicio: HTTP")
        elif (valor == 110):
            print ("    -> Tipo de Servicio: POP3")
        elif (valor == 143):
            print ("    -> Tipo de Servicio: IMAP")
        elif (valor == 443):
            print ("    -> Tipo de Servicio: HTTPS")
        elif (valor == 993):
            print ("    -> Tipo de Servicio: IMAP SSL")
        elif (valor == 995):
            print ("    -> Tipo de Servicio: POP SSL")

    elif (1024 <= valor <= 49151):
        print (f"    -> Puerto de Origen: {valor} (Registrado)")

    elif (49152 <= valor <= 65535):
        print (f"    -> Puerto de Origen: {valor} (Dinamico)")

def tipoPuertoDestino (valor):
    if (0 <= valor <= 1023):
        print (f"    -> Puerto de Destino: {valor} (Bien Conocido)")

        if (valor == 20):
            print ("    -> Tipo de Servicio: FTP")
        elif (valor == 21):
            print ("    -> Tipo de Servicio: FTP")
        elif (valor == 22):
            print ("    -> Tipo de Servicio: SSH")
        elif (valor == 23):
            print ("    -> Tipo de Servicio: TELNET")
        elif (valor == 25):
            print ("    -> Tipo de Servicio: SMTP")
        elif (valor == 53):
            print ("    -> Tipo de Servicio: DNS")
        elif (valor == 67):
            print ("    -> Tipo de Servicio: DHCP")
        elif (valor == 68):
            print ("    -> Tipo de Servicio: DHCP")
        elif (valor == 69):
            print ("    -> Tipo de Servicio: TFTP")
        elif (valor == 80):
            print ("    -> Tipo de Servicio: HTTP")
        elif (valor == 110):
            print ("    -> Tipo de Servicio: POP3")
        elif (valor == 143):
            print ("    -> Tipo de Servicio: IMAP")
        elif (valor == 443):
            print ("    -> Tipo de Servicio: HTTPS")
        elif (valor == 993):
            print ("    -> Tipo de Servicio: IMAP SSL")
        elif (valor == 995):
            print ("    -> Tipo de Servicio: POP SSL")

    elif (1024 <= valor <= 49151):
        print (f"    -> Puerto de Destino: {valor} (Registrado)")

    elif (49152 <= valor <= 65535):
        print (f"    -> Puerto de Destino: {valor} (Dinamico)")

def banderas (valor):
    if (valor[0] == "1"):
        print (f"    -> Bandera NS: Activa")
    elif (valor[1] == "1"):
        print (f"    -> Bandera CWR: Activa")
    elif (valor[2] == "1"):
        print (f"    -> Bandera ECE: Activa")
    elif (valor[3] == "1"):
        print (f"    -> Bandera URG: Activa")
    elif (valor[4] == "1"):
        print (f"    -> Bandera ACK: Activa")
    elif (valor[5] == "1"):
        print (f"    -> Bandera PSH: Activa")
    elif (valor[6] == "1"):
        print (f"    -> Bandera RST: Activa")
    elif (valor[7] == "1"):
        print (f"    -> Bandera SYN: Activa")
    elif (valor[8] == "1"):
        print (f"    -> Bandera FIN: Activa")
    
    