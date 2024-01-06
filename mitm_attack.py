import sys
import time
from utils import *

time_interval = 10


def main(user1, user2):

    # create parameters for the attacker
    parameters = get_or_create_parameters()

    # create diffie-hellman secrets (c for attacker) and publics (g^c for attacker)
    parameter_key = parameters.generate_private_key()
    dh_secret = generate_dh_secrets(parameter_key)
    dh_public = generate_dh_public(parameter_key)

    while not os.path.exists(user1) or not os.path.exists(user2):
        time.sleep(time_interval)

    # write attacker's dh public to both txt files
    write_to_txt_file(dh_public, file_name=user1)
    write_to_txt_file(dh_public, file_name=user2)

    # read users' dh public values
    dh_public1 = int(read_dh_public_value(dh_public, user1))
    dh_public2 = int(read_dh_public_value(dh_public, user2))

    # calculate private key of user 1
    private_gab1 = pow(dh_public1, dh_secret, parameters.parameter_numbers().p) # = g^ac
    private_key1 = sha256(str(private_gab1).encode('utf-8')).hexdigest() # = H(g^ac)
    key1 = bytes.fromhex(private_key1)

    # calculate private key of user 2
    private_gab2 = pow(dh_public2, dh_secret, parameters.parameter_numbers().p) # = g^bc
    private_key2 = sha256(str(private_gab2).encode('utf-8')).hexdigest() # = H(g^bc)
    key2 = bytes.fromhex(private_key2)

    print("Waiting for communication to start...")

    last_message1 = read_last_message(user1)
    while last_message1 == str(dh_public):
        time.sleep(time_interval)
        last_message1 = read_last_message(user1)
    decrypted_message1 = decrypt_message(key1, last_message1)
    print(f"User1's first message: {decrypted_message1}")
    my_message = input("Enter your first modified message to User2: ")
    encrypted_message2 = encrypt_message(key2, my_message)
    last_message2 = read_last_message(user2)
    write_to_txt_file(encrypted_message2, file_name=user2)

    while last_message2 == str(dh_public2) or last_message2 == encrypted_message2:
        time.sleep(time_interval)
        last_message2 = read_last_message(user2)
    decrypted_message2 = decrypt_message(key2, last_message2)
    print(f"User2's first message: {decrypted_message2}")
    my_message = input("Enter your first modified message to User1: ")
    encrypted_message1 = encrypt_message(key1, my_message)
    write_to_txt_file(encrypted_message1, file_name=user1)

    while True:
        while read_last_message(user1) == encrypted_message1:
            time.sleep(time_interval)
            last_message1 = read_last_message(user1)
        decrypted_message1 = decrypt_message(key1, last_message1)
        print(f"User1's last message: {decrypted_message1}")
        my_message = input("Enter your modified message to User2: ")
        encrypted_message2 = encrypt_message(key2, my_message)
        last_message2_old = last_message2
        last_message2 = read_last_message(user2)
        write_to_txt_file(encrypted_message2, file_name=user2)
            
        while last_message2_old == encrypted_message2:
            time.sleep(time_interval)
            last_message2 = read_last_message(user2)
        decrypted_message2 = decrypt_message(key2, last_message2)
        print(f"User2's last message: {decrypted_message2}")
        my_message = input("Enter your modified message to User1: ")
        encrypted_message1 = encrypt_message(key1, my_message)
        write_to_txt_file(encrypted_message1, file_name=user1)


if __name__ == "__main__":
    arg1 = sys.argv[1]
    arg2 = sys.argv[2]
    main(arg1, arg2)
