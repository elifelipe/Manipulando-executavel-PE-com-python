# Manipulando-executavel-PE-com-python

# O que são arquivos PE?

Arquivos PE referem-se a arquivos **executáveis portáteis** no Windows, que podem ter qualquer extensão das listadas abaixo

### Extensões de arquivos executáveis do Windows

| Tipo        | Nome                                  |
| ----------- | ------------------------------------- |
| .exe        | Arquivo executável                    |
| .dll        | Biblioteca de links dinâmicos         |
| .sys / .drv | Arquivo de sistema / Driver de kernel |
| .ocx        | Controle ActiveX                      |
| .cp \|      | Painel de controle                    |
| .scr        | ScreenSaver                           |

## Configuração de ambiente

você deve instalar o módulo **pefile**

```
pip3 install pefile
```

**OU** clone o repositório e siga as instruções de configuração

````
https://github.com/erocarrera/pefile
````

# **Estrutura do arquivo PE**

### **Cabeçalho DOS:**

- **e_magic** → número mágico do cabeçalho DOS é 'MZ' (0x5a4d) e 'MZ' refere-se a **Mark Zbikowski,** o criador do formato de arquivo executável do MS-DOS.
- **e_lfnew** → um ponteiro para o cabeçalho PE (Cabeçalho NT).
  Para a maioria dos programas do Windows, o cabeçalho DOS contém um programa DOS que não faz nada além de imprimir **“Este programa não pode ser executado no modo DOS”** .

![alt text](https://bufferoverflows.net/wp-content/uploads/2019/08/Selection_168-1024x397.jpg "DOS")

Observe que na imagem acima **e_magic** == 0x4d5a (por causa do pequeno endian)

https://en.wikipedia.org/wiki/Endianness

Obtenha todas as informações sobre o cabeçalho PE com o módulo **pefile** python

```
import pefile

pe = pefile.PE("path_to_your_executable")
pe.print_info() # Prints all Headers in a human readable format
```

```
OUTPUT:
```

![alt text](https://bufferoverflows.net/wp-content/uploads/2019/08/Screenshot-from-2019-08-17-19-54-57.png "PRINT")

```
import pefile

pe = pefile.PE("path_to_your_executable")

print("e_magic : " + hex(pe.DOS_HEADER.e_magic)) # Prints the e_magic field of the DOS_HEADER

print("e_lfnew : " + hex(pe.DOS_HEADER.e_lfanew)) # Prints the e_lfnew field of the DOS_HEADER
```

```
OUTPUT:

e_magic : 0x5a4d
e_lfnew : 0xd8
```

##  Cabeçalho PE (cabeçalhos NT)

O único campo com o qual nos preocupamos no Cabeçalho PE (NT_HEADER) é **Assinatura,** que identifica o arquivo como um arquivo PE e duas outras estruturas (FILE_HEADER e OPTIONAL_HEADER)

- **Assinatura** == 0x5045 ('PE' em ASCII)
- **FILE_HEADER**
- **OPTIONAL_HEADER**

```
import pefile

pe = pefile.PE("path_to_your_executable")

print("Signature : " + hex(pe.NT_HEADERS.Signature)) # Prints the Signature field of the NT_HEADERS
```

```
OUTPUT:

Signature : 0x4550
```

## Cabeçalho do arquivo

- **Máquina:** a arquitetura em que este binário deve ser executado ( **0x014C** == binário x86 e **0x8664** == binário x86-x64)

- **TimeDateStamp:** carimbo de data / hora UNIX (segundos desde a época ou 00:00:00 01/01/1970)

- **NumberOfSections:** número de cabeçalhos de seção

- **Características:** especifique algumas características do arquivo PE

```
import pefile

# Loading an executable
pe = pefile.PE("path_to_your_executable")


print("Machine : " + hex(pe.FILE_HEADER.Machine))

# Check if it is a 32-bit or 64-bit binary
if hex(pe.FILE_HEADER.Machine) == '0x14c':
    print("This is a 32-bit binary")
else:
    print("This is a 64-bit binary")

print("TimeDateStamp : " + pe.FILE_HEADER.dump_dict()['TimeDateStamp']['Value'].split('[')[1][:-1]
)

print("NumberOfSections : " + hex(pe.FILE_HEADER.NumberOfSections))

print("Characteristics flags : " + hex(pe.FILE_HEADER.Characteristics))
```

```
OUTPUT:

Machine : 0x14c
This is a 32-bit binary
TimeDateStamp : Tue Jan 30 03:57:45 2018 UTC
NumberOfSections : 0x5
Characteristics flags : 0x10
```

## Cabeçalho opcional

Não é opcional, a seguir estão os campos interessantes no Cabeçalho Opcional

- **Mágico** : dependendo deste valor, o binário será interpretado como um binário de 32 ou 64 bits ( **0x10B** == 32 bits e **0x20B** == 64 bits)

- **AddressOfEntryPoint** : especifica o RVA (endereço virtual relativo)

- **ImageBase** : especifica o local preferido da memória virtual onde o início do binário deve ser colocado

- **SectionAlignment** : especifica que as seções devem ser alinhadas nos limites que são múltiplos deste valor

- **FileAlignment** : se os dados foram gravados no binário em blocos não menores que este valor

- **SizeOfImage** : a quantidade de memória contígua que deve ser reservada para carregar o binário na memória

- **DllCharacteristics** : especifique algumas características de segurança para o arquivo PE

- **DataDirectory [IMAGE_NUMBER_OF_DIRECTORY_ENTRIES]** : uma matriz de entradas de dados

```
import pefile

# Loading an executable
pe = pefile.PE("path_to_your_executable")


print("Magic : " + hex(pe.OPTIONAL_HEADER.Magic))

# Check if it is a 32-bit or 64-bit binary
if hex(pe.OPTIONAL_HEADER.Magic) == '0x10b':
    print("This is a 32-bit binary")
elif hex(pe.OPTIONAL_HEADER.Magic) == '0x20b':
    print("This is a 64-bit binary")


print("ImageBase : " + hex(pe.OPTIONAL_HEADER.ImageBase))

print("SectionAlignment : " + hex(pe.OPTIONAL_HEADER.SectionAlignment))

print("FileAlignment : " + hex(pe.OPTIONAL_HEADER.FileAlignment))

print("SizeOfImage : " + hex(pe.OPTIONAL_HEADER.SizeOfImage))

print("DllCharacteristics flags : " + hex(pe.OPTIONAL_HEADER.DllCharacteristics))

print("DataDirectory: ")
print("*" * 50)
# print name, size and virtualaddress of every DATA_ENTRY in DATA_DIRECTORY
for entry in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
    print(entry.name + "\n|\n|---- Size : " + str(entry.Size) + "\n|\n|---- VirutalAddress : " + hex(entry.VirtualAddress) + '\n')    
print("*" * 50)
```

```
OUTPUT:

Magic : 0x10b
This is a 32-bit binary
ImageBase : 0x400000
SectionAlignment : 0x1000
FileAlignment : 0x200
SizeOfImage : 0x46000
DllCharacteristics flags : 0x8540
DataDirectory: 
**************************************************
IMAGE_DIRECTORY_ENTRY_EXPORT
|
|---- Size : 0
|
|---- VirutalAddress : 0x0

IMAGE_DIRECTORY_ENTRY_IMPORT
|
|---- Size : 160
|
|---- VirutalAddress : 0x8534

IMAGE_DIRECTORY_ENTRY_RESOURCE
|
|---- Size : 53856
|
|---- VirutalAddress : 0x38000

IMAGE_DIRECTORY_ENTRY_EXCEPTION
|
|---- Size : 0
|
|---- VirutalAddress : 0x0

IMAGE_DIRECTORY_ENTRY_SECURITY
|
|---- Size : 10808
|
|---- VirutalAddress : 0x5b6b0

IMAGE_DIRECTORY_ENTRY_BASERELOC
|
|---- Size : 0
|
|---- VirutalAddress : 0x0

IMAGE_DIRECTORY_ENTRY_DEBUG
|
|---- Size : 0
|
|---- VirutalAddress : 0x0

IMAGE_DIRECTORY_ENTRY_COPYRIGHT
|
|---- Size : 0
|
|---- VirutalAddress : 0x0

IMAGE_DIRECTORY_ENTRY_GLOBALPTR
|
|---- Size : 0
|
|---- VirutalAddress : 0x0

IMAGE_DIRECTORY_ENTRY_TLS
|
|---- Size : 0
|
|---- VirutalAddress : 0x0

IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG
|
|---- Size : 0
|
|---- VirutalAddress : 0x0

IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT
|
|---- Size : 0
|
|---- VirutalAddress : 0x0

IMAGE_DIRECTORY_ENTRY_IAT
|
|---- Size : 664
|
|---- VirutalAddress : 0x8000

IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT
|
|---- Size : 0
|
|---- VirutalAddress : 0x0

IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
|
|---- Size : 0
|
|---- VirutalAddress : 0x0

IMAGE_DIRECTORY_ENTRY_RESERVED
|
|---- Size : 0
|
|---- VirutalAddress : 0x0

**************************************************
```

### **Cabeçalho das Seções:**

As seções são grupos de código ou dados que têm permissões semelhantes na memória

**Nomes de seções comuns:**

- **.text** → o código real que o binário executa
- **.data** → ler / escrever dados (globais)
- **.rdata** → dados somente leitura (strings)
- **.bss** → Bloco de segmento de armazenamento (formato de dados não inicializado), geralmente mesclado com a seção .data
- **.idata** → tabela de endereços de importação, geralmente mesclada com seções .text ou .rdata
- **.edata** → tabela de endereços de exportação
- **.pdata** → algumas arquiteturas como ARM, MIPS usam essas estruturas de seções para ajudar na movimentação da pilha em tempo de execução
- **PAGE \*** → código / dados que pode ser enviado para o disco se você estiver ficando sem memória
- **.reolc** → informação de realocação para onde modificar os endereços codificados
- **.rsrc** → recursos como ícones, outros binários embutidos, esta seção tem uma estrutura que os organiza como um sistema de arquivos

**Estrutura comum de um cabeçalho de seção:**

- **Nome**
- **VirtualSize**
- **VirtualAddress**
- **SizeOfRawData**
- **PointerToRawData**
- **Características**

```
import pefile

# Loading an executable
pe = pefile.PE("path_to_your_executable")


# Parsing every section from Sections Header

print("Sections Info: \n")
print("*" * 50)

for section in pe.sections:
    print(section.Name.decode().rstrip('\x00') + "\n|\n|---- Vitual Size : " + hex(section.Misc_VirtualSize) + "\n|\n|---- VirutalAddress : " + hex(section.VirtualAddress) + "\n|\n|---- SizeOfRawData : " + hex(section.SizeOfRawData) + "\n|\n|---- PointerToRawData : " + hex(section.PointerToRawData) + "\n|\n|---- Characterisitcs : " + hex(section.Characteristics)+'\n')    

print("*" * 50)
```

```
OUTPUT:

Sections Info: 

**************************************************
.text
|
|---- Vitual Size : 0x628f
|
|---- VirutalAddress : 0x1000
|
|---- SizeOfRawData : 0x6400
|
|---- PointerToRawData : 0x400
|
|---- Characterisitcs : 0x60000020

.rdata
|
|---- Vitual Size : 0x1354
|
|---- VirutalAddress : 0x8000
|
|---- SizeOfRawData : 0x1400
|
|---- PointerToRawData : 0x6800
|
|---- Characterisitcs : 0x40000040

.data
|
|---- Vitual Size : 0x25518
|
|---- VirutalAddress : 0xa000
|
|---- SizeOfRawData : 0x600
|
|---- PointerToRawData : 0x7c00
|
|---- Characterisitcs : 0xc0000040

.ndata
|
|---- Vitual Size : 0x8000
|
|---- VirutalAddress : 0x30000
|
|---- SizeOfRawData : 0x0
|
|---- PointerToRawData : 0x0
|
|---- Characterisitcs : 0xc0000080

.rsrc
|
|---- Vitual Size : 0xd260
|
|---- VirutalAddress : 0x38000
|
|---- SizeOfRawData : 0xd400
|
|---- PointerToRawData : 0x8200
|
|---- Characterisitcs : 0x40000040

**************************************************
```

Para obter mais exemplos de uso de **pefile** para familiarizá-lo, consulte o seguinte link

https://github.com/erocarrera/pefile/blob/wiki/UsageExamples.md

## **Recursos:**

- https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
- https://code.google.com/archive/p/corkami/wikis/PE.wiki
- http://www.opensecuritytraining.info/LifeOfBinaries.html
- https://github.com/erocarrera/pefile
- https://winitor.com/index.html
- https://www.aldeid.com/wiki/PEiD
- https://github.com/hasherezade/pe-sieve
