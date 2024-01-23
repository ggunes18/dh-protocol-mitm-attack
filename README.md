# COMP443 MODERN CRYPTOGRAPHY Project - Fall2023

## Diffie-Hellman Protocol
To simulate a server-like communication between two users without the attacker:
  * dh_protocol.py should be run in 2 separate instances with the input is_mitm_attack = False
```
python dh_protocol.py False
```

## Man-in-the-Middle Attack
To simulate a server-like communication between two users and a Man in the Middle attacker:
  * dh_protocol.py should be run in 2 separate instances with the input is_mitm_attack = True:
```
python dh_protocol.py True
```
  * mitm_attack.py should be run in a separate instance with the inputs user1 = alice.txt, user2 = bob.txt (assuming usernames are alice and bob)
```
python mitm_attack.py alice.txt bob.txt
```

MitM attack code simulates the scenario where
1. user1 sends its first message
2. user2 sends its first message
3. The attacker reads and modifies user1's first message and sends the modified message to user2.
4. The attacker reads and modifies user2's first message and sends the modified message to user1.
5. user1 reads the modified message and sends another message.
6. user2 reads the modified message and sends another message.
7. The attacker reads, modifies, and sends the new messages to both users.

Steps 5-6-7 repeat until the end of the communication.  


  **Previous .txt files should be removed before re-simulating the DH Protocol or MitM Attack.**
