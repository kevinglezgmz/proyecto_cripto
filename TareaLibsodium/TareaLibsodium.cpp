#include <iostream>
#include <iomanip>
#include "sodium.h"
#include <fstream>
#include <string>
#include <stdio.h>

/* Write data of size content_size pointed by contents array into a file with name file_name */
void write_contents_to_file(const char* file_name, unsigned char* contents, size_t content_size) {
    FILE* f_pointer;
    fopen_s(&f_pointer, file_name, "wb");
    fwrite(contents, 1, content_size, f_pointer);
    fclose(f_pointer);
}

/* Read data of size content_size into contents array from a file with name file_name */
void read_file_contents(const char* file_name, unsigned char* contents, size_t content_size) {
    FILE* f_pointer;
    fopen_s(&f_pointer, file_name, "rb");
    fread(contents, 1, content_size, f_pointer);
    fclose(f_pointer);
}

/* Read data of unknown size contents array from a file with name file_name and set size in content_size */
void read_file_contents(const char* file_name, unsigned char** contents, long* content_size) {
    FILE* f_pointer;
    fopen_s(&f_pointer, file_name, "rb");
    fseek(f_pointer, 0, SEEK_END);
    *content_size = ftell(f_pointer);
    *contents = new unsigned char[*content_size];
    fseek(f_pointer, 0, SEEK_SET);
    fread(*contents, 1, *content_size, f_pointer);
    fclose(f_pointer);
}

/* Generate the encryption key and save it to cipher_key_filename key filename */
void generate_cipher_key(const char* cipher_key_filename) {
    unsigned char key[crypto_stream_chacha20_KEYBYTES];
    crypto_secretbox_keygen(key);
    write_contents_to_file(cipher_key_filename, key, crypto_stream_chacha20_KEYBYTES);
    std::cout << std::endl << "Llave de cifrado guardado como: " << cipher_key_filename << std::endl << std::endl;
}

/* Cipher the specified file with the specified cipher key and save it to a new file */
void cipher_file(const char* filename_to_cipher, const char* filename_to_save_ciphered_file, const char* cipher_key_filename) {
    unsigned char key[crypto_stream_chacha20_KEYBYTES];
    read_file_contents(cipher_key_filename, key, crypto_stream_chacha20_KEYBYTES);

    unsigned char buf_in[1024];
    unsigned char buf_out[1024];
    FILE* fp_target, * fp_source;
    size_t rlen;
    int eof;
    fopen_s(&fp_source, filename_to_cipher, "rb");
    fopen_s(&fp_target, filename_to_save_ciphered_file, "wb");
     
    unsigned char nonce[crypto_stream_chacha20_NONCEBYTES];
    randombytes_buf(nonce, sizeof nonce); 

    fwrite(nonce, 1, sizeof nonce, fp_target);
    do {
        rlen = fread(buf_in, 1, sizeof buf_in, fp_source);
        eof = feof(fp_source);
        crypto_stream_chacha20_xor(buf_out, buf_in, rlen, nonce, key);
        fwrite(buf_out, 1, (size_t)rlen, fp_target);
    } while (!eof);
    fclose(fp_target);
    fclose(fp_source);

    std::cout << std::endl << "Archivo encriptado satisfactoriamente." << std::endl << std:: endl;
}

/* Decipher the specified file with the specified cipher key and save it to a new file */
void decipher_file(const char* filename_to_decipher, const char* filename_to_save_deciphered_file, const char* cipher_key_filename) {
    unsigned char key[crypto_stream_chacha20_KEYBYTES];
    read_file_contents(cipher_key_filename, key, crypto_stream_chacha20_KEYBYTES);

    unsigned char  buf_in[1024];
    unsigned char  buf_out[1024];
    FILE* fp_target, * fp_source;
    size_t         rlen;
    int            eof;
    fopen_s(&fp_source, filename_to_decipher, "rb");
    fopen_s(&fp_target, filename_to_save_deciphered_file, "wb");

    unsigned char nonce[crypto_stream_chacha20_NONCEBYTES];
    fread(nonce, 1, sizeof nonce, fp_source);
    do {
        rlen = fread(buf_in, 1, sizeof buf_in, fp_source);
        eof = feof(fp_source);
        crypto_stream_chacha20_xor(buf_out, buf_in, rlen, nonce, key);
        fwrite(buf_out, 1, (size_t)rlen, fp_target);
    } while (!eof);
    fclose(fp_target);
    fclose(fp_source);

    std::cout << std::endl << std::endl << "Archivo desencriptado satisfactoriamente." << std::endl << std::endl;
}

/* Generate private and public key and save both keys with same key filename suffix */
void generate_key_pair(const char* key_file_name) {
    unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
    unsigned char private_key[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(public_key, private_key);

    // Write private key with priv_ prefix in the filename
    std::string private_("priv_");
    std::string p_file_name(key_file_name);
    write_contents_to_file((private_ + p_file_name).c_str(), private_key, crypto_sign_SECRETKEYBYTES);
    std::cout << std::endl << "Se ha guardado la llave privada como: " << (private_ + p_file_name).c_str() << std::endl;

    // Write public key with pub_ prefix in the filename
    std::string public_("pub_");
    write_contents_to_file((public_ + p_file_name).c_str(), public_key, crypto_sign_PUBLICKEYBYTES);
    std::cout << "Se ha guardado la llave privada como: " << (public_ + p_file_name).c_str() << std::endl << std::endl;
}

/* Extract public key from the private key and save it with the same file name but pub_ prefix */
void recover_public_key(const char* private_key_filename) {
    unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
    unsigned char private_key[crypto_sign_SECRETKEYBYTES];
    read_file_contents(private_key_filename, private_key, crypto_sign_SECRETKEYBYTES);
    crypto_sign_ed25519_sk_to_pk(public_key, private_key);
    std::string priv_key_filename(private_key_filename);
    write_contents_to_file(("pub" + priv_key_filename.substr(4)).c_str(), public_key, crypto_sign_PUBLICKEYBYTES);

    std::cout << std::endl << "Se ha recuperado la llave pUblica y ha sido guardada como: " << "pub" + priv_key_filename.substr(4) << std::endl << std::endl;

}

/* Sign document with the specified private key and save it to the specified filename */
void sign_document(const char* unsigned_document_file_name, const char* private_key_filename, const char* signed_document_file_name_to_save) {
    // Read contents of file to sign
    unsigned char* unsigned_doc = NULL;
    long fsize;
    read_file_contents(unsigned_document_file_name, &unsigned_doc, &fsize);

    // Read contents of the private key to sign the document
    unsigned char private_key[crypto_sign_SECRETKEYBYTES];
    read_file_contents(private_key_filename, private_key, crypto_sign_SECRETKEYBYTES);

    unsigned char* signed_message = new unsigned char[crypto_sign_BYTES + fsize];
    unsigned long long signed_message_len;
    crypto_sign(signed_message, &signed_message_len, unsigned_doc, fsize, private_key);

    // Write the signed document contents to the specified filename
    write_contents_to_file(signed_document_file_name_to_save, signed_message, signed_message_len);
    std::cout << std::endl << "Archivo firmado exitosamente! El archivo firmado ha sido firmado como: " << signed_document_file_name_to_save << std::endl << std::endl;
}

/* Verify that the signed document has not been altered and inform the user */
void verify_sign_document(const char* signed_document_filename, const char* public_key_filename) {
    // Read contents of the signed document
    unsigned char* signed_doc = NULL;
    long fsize;
    read_file_contents(signed_document_filename, &signed_doc, &fsize);
    
    // Read contents of the public key corresponding to the private key that signed the document
    unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
    read_file_contents(public_key_filename, public_key, crypto_sign_PUBLICKEYBYTES);

    unsigned char* unsigned_message = new unsigned char[fsize - crypto_sign_BYTES];
    if (crypto_sign_open(unsigned_message, NULL, signed_doc, fsize, public_key) != 0) {
        std::cout << "Firma invAlida! El archivo ha sido modificado!" << std::endl << std::endl;
    } else {
        std::cout << "Firma vAlida! El archivo NO ha sido modificado!" << std::endl << std::endl;
    }
}


int main()
{
    // Verify that libsodium loads correctly
    if (sodium_init() < 0) {
        std::cout << "No se pudo inicializar libsodium correctamente.";
        return -1;
    }

    char option = '*';
    do {
        system("cls");
        std::cout << "Operaciones disponibles:" << std::endl;
        std::cout << "\t1. GeneraciOn y recuperaciOn de claves." << std::endl;
        std::cout << "\t2. Cifrado de archivos." << std::endl;
        std::cout << "\t3. Descifrado de archivos." << std::endl;
        std::cout << "\t4. Firma de archivos." << std::endl;
        std::cout << "\t5. VerificaciOn de firma de archivos." << std::endl;
        std::cout << "\t\t0. Salir." << std::endl;
        std::cout << "Introduce la opciOn deseada: ";
        std::string input;
        std::getline(std::cin, input);
        if (input.empty()) {
            continue;
        }
        option = input.at(0);
        system("cls");
        switch (option) {
        case '1': {
            std::cout << "¿QuE deseas hacer?:" << std::endl;
            std::cout << "\t1. Generar un nuevo par de clave privada y pUblica." << std::endl;
            std::cout << "\t2. Recuperar una clave pUblica a partir de una clave privada." << std::endl;
            std::cout << "\t3. Generar una nueva clave de cifrado de archivos." << std::endl;
            std::cout << "Introduce la opciOn deseada: ";
            std::string key_input;
            std::getline(std::cin, key_input);
            char key_option = key_input.at(0);
            if (key_option != '1' && key_option != '2' && key_option != '3') {
                break;
            }

            std::string file_name;
            if (key_option == '1') {
                std::cout << std::endl << "Introduce el nombre para tus claves: ";
                std::getline(std::cin, file_name);
                generate_key_pair(file_name.c_str());
            } else if (key_option == '2') {
                std::cout << std::endl << "Introduce el nombre completo de tu clave privada: ";
                std::getline(std::cin, file_name);
                recover_public_key(file_name.c_str());
            } else if (key_option == '3') {
                std::cout << std::endl << "Introduce el nombre para generar la clave de cifrado: ";
                std::getline(std::cin, file_name);
                generate_cipher_key(file_name.c_str());
            }
            break;
        }
        case '2': {
            std::string file_name_str;
            std::cout << "Introduce el nombre del archivo a cifrar: ";
            std::getline(std::cin, file_name_str);
            std::string ciphered_file_name_str;
            std::cout << "Introduce el nombre del archivo de destino (archivo a crear con el contenido cifrado): ";
            std::getline(std::cin, ciphered_file_name_str);
            std::string cipher_key_file_name_str;
            std::cout << "Introduce el nombre del archivo con tu clave de cifrado: ";
            std::getline(std::cin, cipher_key_file_name_str);
            std::cout << std::endl;
            cipher_file(file_name_str.c_str(), ciphered_file_name_str.c_str(), cipher_key_file_name_str.c_str());
            break;
        }
        case '3': {
            std::string file_name_str;
            std::cout << "Introduce el nombre del archivo a descifrar: ";
            std::getline(std::cin, file_name_str);
            std::string deciphered_file_name_str;
            std::cout << "Introduce el nombre del archivo de destino (archivo a crear con el contenido descifrado): ";
            std::getline(std::cin, deciphered_file_name_str);
            std::string cipher_key_file_name_str;
            std::cout << "Introduce el nombre del archivo con tu clave de cifrado: ";
            std::getline(std::cin, cipher_key_file_name_str);
            std::cout << std::endl;
            decipher_file(file_name_str.c_str(), deciphered_file_name_str.c_str(), cipher_key_file_name_str.c_str());
            break;
        }
        case '4': {
            std::string file_to_sign_str;
            std::cout << "Introduce el nombre del archivo a firmar: ";
            std::getline(std::cin, file_to_sign_str);
            std::string private_key_name_str;
            std::cout << "Introduce el nombre de la llave privada (empieza con priv_): ";
            std::getline(std::cin, private_key_name_str);
            std::string signed_name_str;
            std::cout << "Introduce el nombre del documento firmado a guardar: ";
            std::getline(std::cin, signed_name_str);
            std::cout << std::endl;
            sign_document(file_to_sign_str.c_str(), private_key_name_str.c_str(), signed_name_str.c_str());
            break;
        }
        case '5': {
            std::string signed_file_to_verify_str;
            std::cout << "Introduce el nombre del archivo firmado: ";
            std::getline(std::cin, signed_file_to_verify_str);
            std::string public_key_name_str;
            std::cout << "Introduce el nombre de la llave publica (empieza con pub_): ";
            std::getline(std::cin, public_key_name_str);
            std::cout << std::endl;
            verify_sign_document(signed_file_to_verify_str.c_str(), public_key_name_str.c_str());
            break;
        }
        default:
            break;
        }
        system("pause");
    } while (option != '0');
    return 0;
}