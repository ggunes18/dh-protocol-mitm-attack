import sys
import time
from utils import *

time_interval = 10

def main(is_mitm_attack):
    is_first_user = False
    # get the user name
    user_name = input("Enter your user name: ")

    if is_mitm_attack == "True":
        file_name = user_name + ".txt"
    else:
        file_name = "Communication.txt"
        
    # create parameters for the current user
    parameters = get_or_create_parameters()

    # create diffie-hellman secrets (a for Alice, b for Bob) and publics (g^a for Alice, g^b for Bob)
    parameter_key = parameters.generate_private_key()
    dh_secret = generate_dh_secrets(parameter_key)
    dh_public = generate_dh_public(parameter_key)

    # write current user's dh public to txt file
    write_to_txt_file(dh_public, file_name=file_name)
    # read if there exists a previous dh public
    other_dh_public = read_dh_public_value(dh_public, file_name)
    # if there is no previous dh public, read until get one
    while other_dh_public is None:
        if is_first_user is False:
            print("Waiting for other user to connect...")
        is_first_user = True
        other_dh_public = read_dh_public_value(dh_public, file_name)
        time.sleep(time_interval)
    other_dh_public = int(other_dh_public)

    # calculate private key
    private_gab = pow(other_dh_public, dh_secret, parameters.parameter_numbers().p) # = g^ab
    private_key = sha256(str(private_gab).encode('utf-8')).hexdigest() # = H(g^ab)
    key = bytes.fromhex(private_key)

    if is_first_user:
        my_message = input("Enter your message: ")
    else:
        last_message = read_last_message(file_name)
        while last_message == str(dh_public):
            time.sleep(time_interval)
            last_message = read_last_message(file_name)
        decrypted_message = decrypt_message(key, last_message)
        print(f"New message! : {decrypted_message}")
        my_message = input("Enter your message: ")
    encrypted_message = encrypt_message(key, my_message)
    write_to_txt_file(encrypted_message, file_name=file_name)

    while True:
        last_message = read_last_message(file_name)
        decrypted_message = decrypt_message(key, last_message)
        if last_message != encrypted_message:
            print(f"New message! : {decrypted_message}")
            my_message = input("Enter your message: ")
            encrypted_message = encrypt_message(key, my_message)
            write_to_txt_file(encrypted_message, file_name=file_name)
        else:
            time.sleep(time_interval)


if __name__ == "__main__":
    arg1 = sys.argv[1]
    main(arg1)