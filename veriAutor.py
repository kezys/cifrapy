import requests
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

# Carregar chaves públicas
with open(r"C:\Users\diogo\Desktop\chaves\chave_publica_Diogo.pem", "rb") as f:
    public_key_Diogo = serialization.load_pem_public_key(f.read())

with open(r"C:\Users\diogo\Desktop\chaves\chave_publica_Miguel.pem", "rb") as f:
    public_key_Miguel = serialization.load_pem_public_key(f.read())

with open(r"C:\Users\diogo\Desktop\chaves\chave_publica_Filipa.pem", "rb") as f:
    public_key_Filipa = serialization.load_pem_public_key(f.read())

# Pedir ID da mensagem
id_mensagem = input("Digite o ID da mensagem: ")

url = f"https://683972906561b8d882b06ef0.mockapi.io/AsgApi/mensagens/{id_mensagem}"
response = requests.get(url)

if response.status_code == 200:
    mensagem = response.json()

    try:
        mensagem_bytes = base64.b64decode(mensagem['texto'])
        assinatura_bytes = base64.b64decode(mensagem['assinatura'])

        try:
            print("📦 Texto base64:", mensagem['texto'])
            print("📦 Assinatura base64:", mensagem['assinatura'])
            print("📝 Mensagem (decodificada):", mensagem_bytes.decode('utf-8'))
        except UnicodeDecodeError:
            print("⚠️ A mensagem não é texto UTF-8 simples.")

        chaves = {
            "Diogo": public_key_Diogo,
            "Miguel": public_key_Miguel,
            "Filipa": public_key_Filipa
        }

        verificada = False
        for nome, chave in chaves.items():
            try:
                chave.verify(
                    assinatura_bytes,
                    mensagem_bytes,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                print(f"✅ A assinatura é válida com a chave de {nome}!")
                verificada = True
                break
            except InvalidSignature:
                print(f"❌ Assinatura inválida para a chave de {nome}.")
            except Exception as e:
                print(f"❌ Erro inesperado ao verificar com a chave de {nome}: {e}")

        if not verificada:
            print("❌ Nenhuma das chaves corresponde à assinatura.")

    except Exception as e:
        print("❌ Erro ao processar a mensagem ou assinatura:", e)
else:
    print(f"❌ Falha na conexão. Código HTTP: {response.status_code}")
