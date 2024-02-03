    #print("Trabalho Individual Linguagens de Programação Dinâmicas")
    #print("Aluno: Vinícius Guimarães Oliveira Rodrigues\n")


import os
import socket
import ipaddress

def Menu_do_Programa():
    os.system('clear')
    
    print("1- Port Scan")
    print("2- UDP Flood")
    print("3- SYN Flood")
    print("4- Análise e Processamento de Ficheiros de Log")
    print("5- Troca de Mensagens")
    print("6- Client Port Knocking")
    print("7- Reverse Shell")
    print("\n0- Sair\n")

def varredura_de_portas(faixa_ips_alvo, porta_inicial, porta_final):
    faixa_ip = ipaddress.IPv4Network(faixa_ips_alvo, strict=False)

    for ip_alvo in faixa_ip:
        portas_abertas = []
        portas_fechadas = 0

        for porta in range(porta_inicial, porta_final + 1):
            soquete = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            soquete.settimeout(1)

            resultado = soquete.connect_ex((str(ip_alvo), porta))
            soquete.close()

            if resultado == 0:
                portas_abertas.append(str(porta))
            else:
                portas_fechadas += 1

        print(f"\nResultados para o IP {ip_alvo}:")
        print("Portas abertas: " + ", ".join(portas_abertas))
        print(f"Número de Portas Fechadas: {portas_fechadas}")

def main():
    while True:
        Menu_do_Programa()
        escolha = input("Escolha uma opção: ")
        if escolha == "1":
            print("Você escolheu a Opção 1")
            faixa_ips_alvo = input("Digite o IP(s) alvo (Ex. 192.168.0.1-25): ")
            porta_inicial, porta_final = map(int, input("Digite o intervalo de portas (Ex 1-1000): ").split('-'))
            varredura_de_portas(faixa_ips_alvo, porta_inicial, porta_final)
            input("Pressione Enter para continuar...")
        elif escolha == "2":
            print("Você escolheu a Opção 2")
            input("Pressione Enter para continuar...")
        elif escolha == "3":
            print("Você escolheu a Opção 3")
            input("Pressione Enter para continuar...")
        elif escolha == "4":
            print("Você escolheu a Opção 4")
            input("Pressione Enter para continuar...")
        elif escolha == "5":
            print("Você escolheu a Opção 5")
            input("Pressione Enter para continuar...")
        elif escolha == "6":
            print("Você escolheu a Opção 6")
            input("Pressione Enter para continuar...")
        elif escolha == "7":
            print("Você escolheu a Opção 7")
            input("Pressione Enter para continuar...")
        elif escolha == "0":
            print("Saindo do programa")
            break
        else:
            print("Opção Inválida")
            input("Pressione Enter para continuar...")

if __name__ == "__main__":
    main()
