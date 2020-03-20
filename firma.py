#-------------------------------------------------------------------------------
# Name:        firma.py
# Purpose:     generación de certificado digital, firma y comprobación de firma
# Author:      DiegoMGuillén
# Contacto:    dmartinez17@alu.ucam.edu
# Created:     19/03/2020
# Notas:
# Testeado con python 3.7.6
#-------------------------------------------------------------------------------
from OpenSSL import crypto, SSL
from os.path import join
import random
import os
import sys
################################################################################
def generarCertificado():
    CN = "diegoUcam"
    clavepublica = "%s.crt" % CN #cambio %s con CN
    claveprivada = "%s.key" % CN
    #rutas donde guardar(directorio actual
    clavepublica = join(os.getcwd(), clavepublica)
    claveprivada = join(os.getcwd(), claveprivada)
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048) #rsa 2048 bytes
    serialnumber=random.getrandbits(64)#generación de número de serie aleatorio
    #Creación del certidicado autofirmado
    cert = crypto.X509()
    cert.get_subject().C = "ES"
    cert.get_subject().ST = "Murcia"
    cert.get_subject().L = "Murcia"
    cert.get_subject().O = "Ucam"
    cert.get_subject().OU = "Alumnos"
    cert.get_subject().CN = CN
    cert.set_serial_number(serialnumber)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(40536000)#tiempo desde hoy en segundos
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha512') #hashing sha512
    pub=crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    priv=crypto.dump_privatekey(crypto.FILETYPE_PEM, k)
    open(clavepublica,"wt").write(pub.decode("utf-8"))
    open(claveprivada,"wt").write(priv.decode("utf-8") )
################################################################################
def getClavePrivada():
    # cargamos la clave privada diegoUcam.key generada antes
    try:
        pf = open("diegoUcam.key")
        buffer = pf.read()
        pf.close()
        priv_key = crypto.load_privatekey(crypto.FILETYPE_PEM, buffer)
        return priv_key
    except:
        print("No la clave privada diegoUcam.key\n")
################################################################################
def getCertificado():
    #cargamos el certificado
    try:
        pf = open("diegoUcam.crt")
        buffer = pf.read()
        pf.close()
        certificado = crypto.load_certificate(crypto.FILETYPE_PEM, buffer)
        return certificado
    except:
        print("No se encuentra el certificado diegoUcam.cert\n")
################################################################################
def getMensajeClaro(filename):
    try:
        mensajeclaro = open(filename, 'r').read()
        return mensajeclaro.encode('utf8')
    except:
        print("No se encuentra el mensaje en claro\n")
################################################################################
def firmar(mensajeclaro,alg_hash):
    firma = crypto.sign(getClavePrivada(),mensajeclaro,alg_hash)
    return firma
################################################################################
def saveFirma(firma):
    rutaarchivofirma = join(os.getcwd(),"diegoUcamfirma")
    try:
        pf = open(rutaarchivofirma, 'w+b')
        formatobinario = bytearray(firma)
        pf.write(formatobinario)
        pf.close()
    except:
        print("Ha ocurrido un error guardado la firma.\n")
################################################################################
def getFirma(filename):
    try:
        firmadig = open(filename, 'r+b').read()
        return firmadig
    except:
        print("Ha ocurrido un error leyendo la firma.\n")
################################################################################
def verificar(certificado,firma,mensajeclaro,alg_hash):
#pasamos:certificado, firma del paso anterior,mensaje a verificar,algoritmo hash
    try:
        resultado=crypto.verify(certificado,firma,mensajeclaro,alg_hash)
        return ":-) Verificación superada.\n"
    except:
        return ":-( Verificación No superada.\n"
################################################################################
def main():
    argumentos = len(sys.argv)-1
    if sys.argv[1]=='-h':
        print("Primer argumento:")
        print(" •gencert para generar certificado y clave privada, ejemplo:python firma.py gencert\n")
        print(" •firmar para firmar, ejemplo:python firma.py firmar mensajeclaro.txt\n")
        print(" •verfificar par verificar, ejemplo:python firma.py verificar mensajeclaro.txt\n")
    if sys.argv[1]=='gencert':
        generarCertificado()
        print("Certificado y clave privada generados correctamente en ", os.getcwd())
    if argumentos==2:
        if sys.argv[1]=='firmar':
            print("PROCESO DE FIRMA.\n")
            certificado = getCertificado()
            mensajeclaro = getMensajeClaro(sys.argv[2])
            print("Se ha cargado el siguiente mensaje en claro:\n",mensajeclaro)
            firma = firmar(mensajeclaro,'sha512')
            print("Esta es la firma generada:\n",firma.hex())
            saveFirma(firma)
            print("La firma se ha guardado como diegoUcamfirma en ", os.getcwd())
        if sys.argv[1]=='verificar':
            print("PROCESO DE VERIFICACION.\n")
            certificado = getCertificado()
            mensajeclaro = getMensajeClaro(sys.argv[2])
            firma_de_archivo=getFirma('diegoUcamfirma')
            verificacion_firma_archivo = verificar(certificado,firma_de_archivo,mensajeclaro,'sha512')
            print("Este es el resultado de la verificación con firma de archivo:",verificacion_firma_archivo)

if __name__ == '__main__':
    main()
