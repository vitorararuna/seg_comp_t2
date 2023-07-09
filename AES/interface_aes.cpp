#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <string>

#include "aes.h"

void encrypt_file(uint8_t * key,
                  const char * input_name, 
                  const char * output_name)
{
  struct stat sb;
  int input_file, output_file;

  input_file = open(input_name, 0, 0644);
  output_file = open(output_name,  O_WRONLY | O_TRUNC | O_CREAT, 0644);
    
  if(input_file > 0 && output_file > 0)
  {
    fstat(input_file, &sb);
    std::vector<uint8_t> file_data(sb.st_size);
    read(input_file, file_data.data(), sb.st_size);

    AES128 aes(key);
    auto encrypted_file = aes.encrypt(file_data);

    write(output_file, encrypted_file.data(), encrypted_file.size());
  }
  else{
    if(!input_file)
      printf("Error opening: %s, %d\n", input_name, input_file);
    else
      printf("Error opening: %s, %d\n", output_name, output_file);
  }
  
  close(input_file);
  close(output_file);
}

void decrypt_file(uint8_t * key,
                  const char * input_name, 
                  const char * output_name)
{
  struct stat sb;
  int input_file, output_file;

  input_file = open(input_name, 0, 0644);
  output_file = open(output_name,  O_WRONLY | O_TRUNC | O_CREAT, 0644);

  if((input_file > 0 ) && (output_file > 0))
  {
    fstat(input_file, &sb);
    std::vector<uint8_t> file_data(sb.st_size);
    read(input_file, file_data.data(), sb.st_size);

    AES128 aes(key);
    auto decrypted_file = aes.decrypt(file_data);

    write(output_file, decrypted_file.data(), decrypted_file.size());

  }
  else{
    if(!input_file)
      printf("Error opening: %s, %d\n", input_name, input_file);
    else
      printf("Error opening: %s, %d\n", output_name, output_file);
  }
  
  close(input_file);
  close(output_file);
}

int main(int argc, const char * argv[]){
  if(argc == 5)
  {
    
    if(!strcmp(argv[1], "-e"))
    {
      std::string key = argv[2];
      if (key.length() < 17)
      { 
        key.append(16 - key.length(), ' '); 
        encrypt_file((uint8_t *)key.data(), argv[3], argv[4]);
      }
      else 
          printf("Key too big: %s\n", argv[1]);
    }
    else if(!strcmp(argv[1], "-d"))
    {
      std::string key = argv[2];
      if (key.length() < 17)
      { 
        key.append(16 - key.length(), ' ');  
        decrypt_file((uint8_t *)key.data(), argv[3], argv[4]);
      }
      else 
          printf("Key too big: %s\n", argv[1]);
    }
    else
        printf("Invalid command: %s\n", argv[1]);
  }
  else
  {
    printf("Few arguments\nExample: \n\t%s -e key input_file output_file\n", argv[0]);
  }
  return 0;
}