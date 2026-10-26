
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
 
 
def generar_par_claves_rsa(tamano_clave: int = 2048):
    """Genera el par de claves RSA (privada, pública)."""
    clave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=tamano_clave
    )
    clave_publica = clave_privada.public_key()
    return clave_privada, clave_publica
 
 
def obtener_claves_pem(clave_privada, clave_publica):
    """Serializa las claves a formato PEM (texto) para guardarlas o compartirlas."""
    priv_bytes = clave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_bytes = clave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv_bytes.decode('utf-8'), pub_bytes.decode('utf-8')
 
 
def cifrar_texto_asimetrico(mensaje: str, clave_publica) -> bytes:
    """Cifra el mensaje con la clave PÚBLICA usando OAEP + SHA-256."""
    return clave_publica.encrypt(
        mensaje.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
 
 
def descifrar_texto_asimetrico(criptograma: bytes, clave_privada) -> str:
    """Descifra el criptograma con la clave PRIVADA (mismo relleno OAEP)."""
    bytes_descifrados = clave_privada.decrypt(
        criptograma,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return bytes_descifrados.decode('utf-8')