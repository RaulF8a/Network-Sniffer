def tipoHardware (valor):
    if (valor == 1):
        print ("- Tipo de Hardware: 1 (Ethernet 10Mb)")
    elif (valor == 6):
        print ("- Tipo de Hardware: 6 (IEEE 802 Networks)")
    elif (valor == 7):
        print ("- Tipo de Hardware: 7 (ARCNET)")
    elif (valor == 15):
        print ("- Tipo de Hardware: 15 (Frame Relay)")
    elif (valor == 16):
        print ("- Tipo de Hardware: 16 (Asynchronous Transfer Mode)")
    elif (valor == 17):
        print ("- Tipo de Hardware: 17 (HDLC)")
    elif (valor == 18):
        print ("- Tipo de Hardware: 18 (Fibre Channel)")
    elif (valor == 19):
        print ("- Tipo de Hardware: 19 (Asynchronous Transfer Mode)")
    elif (valor == 20):
        print ("- Tipo de Hardware: 20 (Serial Line)")

def codigoDeOperacion (valor):
    if (valor == 1):
        print ("- Codigo de Operacion: 1 (ARP Request)")
    elif (valor == 2):
        print ("- Codigo de Operacion: 2 (ARP Reply)")
    elif (valor == 3):
        print ("- Codigo de Operacion: 3 (RARP Request)")
    elif (valor == 4):
        print ("- Codigo de Operacion: 4 (RARP Reply)")
    elif (valor == 5):
        print ("- Codigo de Operacion: 5 (DRARP Request)")
    elif (valor == 6):
        print ("- Codigo de Operacion: 6 (DRARP Reply)")
    elif (valor == 7):
        print ("- Codigo de Operacion: 7 (DRARP Error)")
    elif (valor == 8):
        print ("- Codigo de Operacion: 9 (InARP Request)")
    elif (valor == 9):
        print ("- Codigo de Operacion: 10 (InARP Reply)")
    
def protocolo (valor):
    if (valor == "0800"):
        print ("- Tipo de Protocolo: 0800 (IPv4)")
    elif (valor == "0806"):
        print ("- Tipo de Protocolo: 0806 (ARP)")
    elif (valor == "8035"):
        print ("- Tipo de Protocolo: 8035 (RARP)")
    elif (valor == "86dd"):
        print ("- Tipo de Protocolo: 86DD (IPv6)")