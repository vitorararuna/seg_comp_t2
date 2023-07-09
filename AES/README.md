# AES

Criptografa arquivos binários de tamanho variado. 

* É feito um padding no arquivo antes de cifrar o arquivo 

* Quando o arquivo é decifrado esse pad é removido

---

## Compilar

> ``` g++ -g interface_aes.cpp aes.cpp -o aes.exe ```

## Cifrar

> ``` aes.exe -e <your_key> <input_file> <output_file> ```

Exemplo:

> ``` .\aes.exe -e key message.txt output.txt ```

## Decifrar
> ``` aes.exe -d <your_key> <input_file> <output_file> ```

Exemplo:

> ``` .\aes.exe -e key cipher.txt result.txt ```

---
## Erros

Se aparecer o erro: 

```Error opening: output.txt, -1```

Provavelmente, o arquivo "output.txt" já existe. Tente outro nome.