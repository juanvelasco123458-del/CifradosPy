
from cryptography.fernet import Fernet
 
 
def generar_clave_simetrica() -> bytes:
    """Genera una clave aleatoria segura (32 bytes codificados en base64)."""
    return Fernet.generate_key()
 
 
def cifrar_texto_simetrico(mensaje: str, clave: bytes) -> bytes:
    """Cifra un texto y devuelve el token cifrado (incluye fecha y firma de integridad)."""
    f = Fernet(clave)
    # Fernet trabaja con bytes, por eso convertimos el texto con encode()
    return f.encrypt(mensaje.encode('utf-8'))
 
 
def descifrar_texto_simetrico(token_cifrado: bytes, clave: bytes) -> str:
    """Descifra el token con la misma clave y devuelve el texto original."""
    f = Fernet(clave)
    # decrypt() devuelve bytes; decode() los convierte de vuelta a texto
    return f.decrypt(token_cifrado).decode('utf-8')
 