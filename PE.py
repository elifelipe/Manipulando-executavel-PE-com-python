import pefile

pe = pefile.PE("C:\Git-2.32.0.2-64-bit.exe") # Caminho do arquivo

# Cabeçalho DOS

print("e_magic : " + hex(pe.DOS_HEADER.e_magic)) # Imprime o campo e_magic do DOS_HEADER
# e_magic , é o chamado número mágico. Este campo é usado
# para identificar um tipo de arquivo compatível com MS-DOS. 
# Todos os arquivos executáveis ​​compatíveis com MS-DOS definem esse valor como 0x5A4D
# que representa os caracteres ASCII MZ

print("e_lfanew : " + hex(pe.DOS_HEADER.e_lfanew)) # Imprime o campo e_lfnew do DOS_HEADER
# e_lfanew , é um deslocamento de 4 bytes no arquivo onde o cabeçalho do arquivo PE está localizado.
# O cabeçalho do arquivo PE é localizado indexando,
# O campo e_lfanew do cabeçalho do MS-DOS. 
# O campo e_lfanew simplesmente fornece o deslocamento no arquivo

# Cabeçalho PE (cabeçalhos NT)

print ( "Signature:" + hex ( pe.NT_HEADERS.Signature )) # Imprime o campo de Assinatura do NT_HEADERS
# O único campo com o qual nos preocupamos no Cabeçalho PE (NT_HEADER) é Assinatura, que identifica 
# O arquivo como um arquivo PE e duas outras estruturas (FILE_HEADER e OPTIONAL_HEADER)

# Cabeçalho do arquivo

print("Machine : " + hex(pe.FILE_HEADER.Machine))
# Máquina: a arquitetura em que este binário deve ser executado
# ( 0x014C == binário x86 e 0x8664 == binário x86-x64)

# Verifica se é um binário de 32 ou 64 bits
if hex(pe.FILE_HEADER.Machine) == '0x14c':
    print("This is a 32-bit binary")
else:
    print("This is a 64-bit binary")

print("TimeDateStamp : " + pe.FILE_HEADER.dump_dict()['TimeDateStamp']['Value'].split('[')[1][:-1])
# TimeDateStamp: carimbo de data / hora UNIX (segundos desde a época ou 00:00:00 01/01/1970)

print("NumberOfSections : " + hex(pe.FILE_HEADER.NumberOfSections))
# NumberOfSections: número de cabeçalhos de seção

print("Characteristics flags : " + hex(pe.FILE_HEADER.Characteristics))
# O campo Características identifica características específicas sobre o arquivo. Por exemplo, 
# considere como arquivos de depuração separados são gerenciados para um executável.
# É possível retirar informações de depuração de um arquivo PE e armazená-las em um arquivo de depuração (.DBG) para uso por depuradores.

# Cabeçalho opcional

print ( "Magic :" + hex ( pe.OPTIONAL_HEADER.Magic ))
# Mágico: dependendo deste valor, o binário será interpretado como um binário de 32 ou 64 bits ( 0x10B == 32 bits e 0x20B == 64 bits)

print("ImageBase : " + hex(pe.OPTIONAL_HEADER.ImageBase))
# ImageBase: especifica o local preferido da memória virtual onde o início do binário deve ser colocado

print ( "SectionAlignment :" + hex ( pe.OPTIONAL_HEADER.SectionAlignment ))
# SectionAlignment: especifica que as seções devem ser alinhadas nos limites que são múltiplos deste valor

# Cabeçalho das Seções

# Analisando cada seção do cabeçalho das seções
print("Sections Info: \n")
print("*" * 50)
for section in pe.sections:
    print(section.Name.decode().rstrip('\x00') + "\n|\n|---- Vitual Size : " +
     hex(section.Misc_VirtualSize) + "\n|\n|---- VirutalAddress : " +
      hex(section.VirtualAddress) + "\n|\n|---- SizeOfRawData : " +
       hex(section.SizeOfRawData) + "\n|\n|---- PointerToRawData : " +
        hex(section.PointerToRawData) + "\n|\n|---- Characterisitcs : " +
         hex(section.Characteristics)+'\n')    
print("*" * 50)

# text → o código real que o binário executa
# data → ler / escrever dados (globais)
# rdata → dados somente leitura (strings)
# bss → Bloco de segmento de armazenamento (formato de dados não inicializado), geralmente mesclado com a seção .data
# idata → tabela de endereços de importação, geralmente mesclada com seções .text ou .rdata
# edata → tabela de endereços de exportação
# pdata → algumas arquiteturas como ARM, MIPS usam essas estruturas de seções para ajudar na movimentação da pilha em tempo de execução
# PAGE * → código / dados que pode ser enviado para o disco se você estiver ficando sem memória
# reolc → informação de realocação para onde modificar os endereços codificados
# rsrc → recursos como ícones, outros binários embutidos, esta seção tem uma estrutura que os organiza como um sistema de arquivos