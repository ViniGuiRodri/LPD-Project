import socket  # Necessário para operações de rede
import threading  # Permite execução paralela, essencial para enviar/receber mensagens simultaneamente
import rsa  # Biblioteca para criptografia RSA

# Geração de chaves RSA para criptografia/criptografia assimétrica
public_key, private_key = rsa.newkeys(1024)

# Solicita ao usuário decidir o modo de operação
escolha_servidor_cliente = input("Digite 1 para Servidor e 2 para Cliente: ")

if escolha_servidor_cliente == "1":
    # Configuração do servidor
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ipservidor = input("Digite o IP para o servidor: ")
    portaservidor = int(input("Digite a porta para o servidor: "))
    server.bind((ipservidor, portaservidor))  # Associação do socket a um IP e porta específicos
    server.listen()  # Inicia a escuta por conexões entrantes

    client, _ = server.accept()  # Aceita uma conexão de cliente
    # Troca de chaves públicas para criptografia RSA
    client.send(public_key.save_pkcs1("PEM"))
    public_partner = rsa.PublicKey.load_pkcs1(client.recv(1024))

elif escolha_servidor_cliente == "2":
    # Configuração do cliente
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ipcliente = input("Digite o IP para o cliente: ")
    portacliente = int(input("Digite a porta para o cliente: "))
    client.connect((ipcliente, portacliente))  # Conecta ao servidor

    # Troca de chaves públicas para criptografia RSA
    public_partner = rsa.PublicKey.load_pkcs1(client.recv(1024))
    client.send(public_key.save_pkcs1("PEM"))

# Funções para enviar e receber mensagens, utilizando criptografia RSA
def sending_messages(c):
    while True:
        message = input("")
        c.send(rsa.encrypt(message.encode(), public_partner))  # Encripta a mensagem antes de enviar

def receiving_messages(c):
    while True:
        # Decifra a mensagem recebida usando a chave privada
        print("Parceiro: " + rsa.decrypt(c.recv(1024), private_key).decode())

# Inicialização de threads separadas para envio e recebimento de mensagens
threading.Thread(target=sending_messages, args=(client,)).start()
threading.Thread(target=receiving_messages, args=(client,)).start()