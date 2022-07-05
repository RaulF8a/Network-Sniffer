def tipoMensaje (tipo, codigo):
    if (tipo == 1):
        print ("    -> Tipo de mensaje informativo: 1 (Destino Inalcanzable)")

        if (codigo == 0):
            print ("    -> Codigo: 0 (No Existe la Ruta de Destino)")
        elif (codigo == 1):
            print ("    -> Codigo: 1 (Comunicacion con el Destino Administrativamente Prohibida)")
        elif (codigo == 2):
            print ("    -> Codigo: 2 (No Asignado)")
        elif (codigo == 3):
            print ("    -> Codigo: 3 (Direccion Inalcanzable)")

    elif (tipo == 2):
        print ("    -> Tipo de mensaje informativo: 2 (Paquete Demasiado Grande)")
        print ("    -> Codigo: 0")

    elif (tipo == 3):
        print ("    -> Tipo de mensaje informativo: 3 (Tiempo Excedido)")

        if (codigo == 0):
            print ("    -> Codigo: 0 (Limite de Salto Excedido)")
        elif (codigo == 1):
            print ("    -> Codigo: 1 (Tiempo de Reensamble del Fragmento Excedido)")
    
    elif (tipo == 4):
        print ("    -> Tipo de mensaje informativo: 4 (Problema de Parametro)")

        if (codigo == 0):
            print ("    -> Codigo: 0 (Campo de Cabecera Erroneo Encontrado)")
        elif (codigo == 1):
            print ("    -> Codigo: 1 (Protocolo Siguiente de Cabecera Erroneo Encontrado)")
        elif (codigo == 2):
            print ("    -> Codigo: 2 (Opcion IPv6 Erronea Encontrada)")

    elif (tipo == 128):
        print ("    -> Tipo de mensaje informativo: 128 (Echo Request)")
        print ("    -> Codigo: 0")
    
    elif (tipo == 129):
        print ("    -> Tipo de mensaje informativo: 129 (Echo Reply)")
        print ("    -> Codigo: 0")
    
    elif (tipo == 133):
        print ("    -> Tipo de mensaje informativo: 133 (Solicitud de Router)")
        print ("    -> Codigo: 0")
    
    elif (tipo == 134):
        print ("    -> Tipo de mensaje informativo: 134 (Anuncio de Router)")
        print ("    -> Codigo: 0")
    
    elif (tipo == 135):
        print ("    -> Tipo de mensaje informativo: 135 (Solicitud de Vecino)")
        print ("    -> Codigo: 0")
    
    elif (tipo == 136):
        print ("    -> Tipo de mensaje informativo: 136 (Anuncio de Vecino)")
        print ("    -> Codigo: 0")
    
    elif (tipo == 137):
        print ("    -> Tipo de mensaje informativo: 137 (Reoriente el Mensaje)")
        print ("    -> Codigo: 0")

