import os

def Menu_do_Programa():
    os.system('clear')
    print("Trabalho Individual Linguagens de Programação Dinâmicas")
    print("Aluno: Vinícius Guimarães Oliveira Rodrigues\n")
    print("1- Port Scan")
    print("2- UDP Flood")
    print("3- SYN Flood")
    print("4- Análise e Processamento de Ficheiros de Log")
    print("5- Troca de Mensagens")
    print("6- Client Port Knocking")
    print("7- Reverse Shell")
    print("\n0- Sair\n")

def main():
    while True:
        Menu_do_Programa()
        escolha = input("Escolha uma opção: ")
        if escolha == "1":
            print("Você escolheu a Opção 1")
            input()
        elif escolha == "2":
            print("Você escolheu a Opção 2")
            input()
        elif escolha == "3":
            print("Você escolheu a Opção 3")
            input()
        elif escolha == "4":
            print("Você escolheu a Opção 4")
            input()
        elif escolha == "5":
            print("Você escolheu a Opção 5")
            input()
        elif escolha == "6":
            print("Você escolheu a Opção 6")
            input()
        elif escolha == "7":
            print("Você escolheu a Opção 7")
            input()
        elif escolha == "0":
            print("Saindo do programa")
            input()
            break
        else:
            print("Opção Inválida")
            input()
1
if __name__ == "__main__":
    main()