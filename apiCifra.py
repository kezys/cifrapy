import base64
import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.backends import default_backend
from datetime import datetime

API_URL = "https://683972906561b8d882b06ef0.mockapi.io/AsgApi/mensagens"
AUTOR_ID = "Miguel Ribeiro"

def carregar_chave_publica(caminho):
    with open(caminho, "rb") as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())

def carregar_chave_privada(caminho):
    with open(caminho, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

def cifrar_mensagem(mensagem, chave_publica_destinatario):
    return chave_publica_destinatario.encrypt(
        mensagem.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def assinar_mensagem(mensagem_cifrada, chave_privada_autor):
    assinatura = chave_privada_autor.sign(
        mensagem_cifrada,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return assinatura

def enviar_para_api(texto_cifrado, assinatura, chave_publica_autor):
    payload = {
        "createdAt": datetime.utcnow().isoformat() + "Z",
        "texto": base64.b64encode(texto_cifrado).decode(),
        "autor": AUTOR_ID,
        "assinatura": base64.b64encode(assinatura).decode(),
        "publicKey": base64.b64encode(
            chave_publica_autor.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        ).decode()
    }

    resposta = requests.post(API_URL, json=payload)
    print("Status:", resposta.status_code)
    print("Resposta:", resposta.json())

def R(mensagem_cifrada, assinatura, chave_publica_autor):
    try:
        chave_publica_autor.verify(
            assinatura,
            mensagem_cifrada,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print("Assinatura inválida:", e)
        return False

def base64_fixa(texto_b64):
    return texto_b64 + '=' * (-len(texto_b64) % 4)

def verificar_mensagens_recebidas(chave_privada_destinatario):
    resposta = requests.get("https://683972906561b8d882b06ef0.mockapi.io/AsgApi/mensagens")
    mensagens = resposta.json()

    print(f"\n=== Mensagens Recebidas ({len(mensagens)} total) ===")
    for msg in mensagens:
        try:
            texto_cifrado = base64.b64decode(base64_fixa(msg["texto"]))
            assinatura = base64.b64decode(base64_fixa(msg["assinatura"]))

            public_key_str = msg["publicKey"]

            try:
                if "-----BEGIN PUBLIC KEY-----" in public_key_str:
                    chave_publica_autor = serialization.load_pem_public_key(
                        public_key_str.encode()
                    )
                else:
                    chave_publica_autor = serialization.load_pem_public_key(
                        base64.b64decode(base64_fixa(public_key_str))
                    )
            except Exception as e:
                print("⚠️ Erro ao carregar chave pública:", e)
                continue

            try:
                chave_publica_autor.verify(
                    assinatura,
                    texto_cifrado,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                assinatura_valida = True
            except Exception:
                assinatura_valida = False

            if not assinatura_valida:
                print(f"❌ Assinatura inválida da mensagem de {msg['autor']} com o id {msg['id']}")
                continue

            try:
                texto_descifrado = chave_privada_destinatario.decrypt(
                    texto_cifrado,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                ).decode()
            except Exception as e:
                print(f"🔐 Não foi possível descifrar mensagem de {msg['autor']}")
                continue

            print(f"\n📩 Mensagem válida de {msg['autor']}:")
            print(f"🕒 Criada em: {msg['createdAt']}")
            print(f"📝 Texto: {texto_descifrado}\n")

        except Exception as e:
            print("⚠️ Erro geral ao processar mensagem:", e)


if __name__ == "__main__":
    CAMINHO_PRIVADA = "c:\\Users\\migue\\Documents\\chave_privada.pem"
    CAMINHO_PUBLICA_AUTOR = "c:\\Users\\migue\\Documents\\chave_publica.pem"
    CAMINHO_PUBLICA_DEST_DIOGO = "c:\\Users\\migue\\Documents\\publica_destinatario_diogo.pem"
    CAMINHO_PUBLICA_DEST_FILIPA = "c:\\Users\\migue\\Documents\\publica_destinatario_filipa.pem"



    chave_privada_autor = carregar_chave_privada(CAMINHO_PRIVADA)
    chave_publica_autor = carregar_chave_publica(CAMINHO_PUBLICA_AUTOR)

    chave_publica_dest_diogo = carregar_chave_publica(CAMINHO_PUBLICA_DEST_DIOGO)
    chave_publica_dest_filipa = carregar_chave_publica(CAMINHO_PUBLICA_DEST_FILIPA)

    mensagem = "Cafe as 10h"

    # Para mim
    mensagem_cifrada1 = cifrar_mensagem(mensagem, chave_publica_autor)
    assinatura1 = assinar_mensagem(mensagem_cifrada1, chave_privada_autor)
    # enviar_para_api(mensagem_cifrada1, assinatura1, chave_publica_autor)

    # Para outra pessoa
    mensagem_cifrada2 = cifrar_mensagem(mensagem, chave_publica_dest_filipa)
    assinatura2 = assinar_mensagem(mensagem_cifrada2, chave_privada_autor)
    # enviar_para_api(mensagem_cifrada2, assinatura2, chave_publica_autor)
    
    # Verificar
    verificar_mensagens_recebidas(chave_privada_autor)