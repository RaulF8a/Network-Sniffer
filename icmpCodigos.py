def icmpMensaje (valor):
    if (valor == 0):
        print ("    -> Tipo de mensaje informativo: 0 (Echo reply)")
    elif (valor == 3):
        print ("    -> Tipo de mensaje informativo: 3 (Destination unreachable)")
    elif (valor == 4):
        print ("    -> Tipo de mensaje informativo: 4 (Source quench)")
    elif (valor == 5):
        print ("    -> Tipo de mensaje informativo: 5 (Redirect)") 
    elif (valor == 8):
        print ("    -> Tipo de mensaje informativo: 8 (Echo)")
    elif (valor == 11):
        print ("    -> Tipo de mensaje informativo: 11 (Time Exceeded)")
    elif (valor == 12):
        print ("    -> Tipo de mensaje informativo: 12 (Parameter problem)")
    elif (valor == 13):
        print ("    -> Tipo de mensaje informativo: 13 (Timestamp)")
    elif (valor == 14):
        print ("    -> Tipo de mensaje informativo: 14 (Timestamp reply)")
    elif (valor == 15):
        print ("    -> Tipo de mensaje informativo: 15 (Information request)")
    elif (valor == 16):
        print ("    -> Tipo de mensaje informativo: 16 (Information reply)")
    elif (valor == 17):
        print ("    -> Tipo de mensaje informativo: 17 (Addressmask)")
    elif (valor == 18):
        print ("    -> Tipo de mensaje informativo: 18 (Addressmask reply)")

def icmpCodigoError (valor):
    if (valor == 0):
        print ("    -> Codigo de error: 0 (No se puede llegar a la red)")
    elif (valor == 1):
        print ("    -> Codigo de error: 1 (No se puede llegar al host de destino)")
    elif (valor == 2):
        print ("    -> Codigo de error: 2 (El destino no dispone del protocolo solicitado)")
    elif (valor == 3):
        print ("    -> Codigo de error: 3 (No se puede llegar al puerto destino o la aplicación destino no está libre)")
    elif (valor == 4):
        print ("    -> Codigo de error: 4 (Se necesita aplicar fragmentación, pero el flag correspondiente indica lo contrario)")
    elif (valor == 5):
        print ("    -> Codigo de error: 5 (La ruta de origen no es correcta)")
    elif (valor == 6):
        print ("    -> Codigo de error: 6 (No se conoce la red destino)")
    elif (valor == 7):
        print ("    -> Codigo de error: 7 (No se conoce el host destino)")
    elif (valor == 8):
        print ("    -> Codigo de error: 8 (El host origen esta aislado)")
    elif (valor == 9):
        print ("    -> Codigo de error: 9 (La comunicación con la red destino está prohibida por razones administrativas)")
    elif (valor == 10):
        print ("    -> Codigo de error: 10 (La comunicación con el host destino está prohibida por razones administrativas)")
    elif (valor == 11):
        print ("    -> Codigo de error: 11 (No se puede llegar a la red destino debido al Tipo de Servicio)")
    elif (valor == 12):
        print ("    -> Codigo de error: 12 (No se puede llegar al host destino debido al Tipo de Servicio)")