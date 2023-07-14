# Parity's AppSec Capture The Flag (CTF) Challenge

Welcome to our Capture the Flag (CTF) challenge! This challenge is built around a Rust web application using the Actix framework, and will test your ability to perform both dynamic testing on the application and a static audit on the provided backend code. Your goal is to find and exploit vulnerabilities to locate and capture a series of flags scattered throughout the system.

## Challenge Format

In this CTF, your task is to hunt for flags which confirm that you have successfully exploited a particular vulnerability. The flag format will be `flag{value}`. For example: `flag{d46c49fa1fd0a29bff313783fbb0beca31cfbcaf6a087e513b7bc1a225b6d2c7}`. 

There are four tasks that need to be completed:

1. **Task 1 - Invited User Signup**: In this task, you are to find a way to sign up to the system as an invited user. Upon successful exploitation, the system will provide you with the first flag.

2. **Task 2 - Admin Password Discovery**: Once you are signed in as an invited user, your next task is to find the encrypted admin password. The encrypted password will be the second flag.

3. **Task 3 - Password Decryption**: After discovering the encrypted admin password, you will need to find a way to decrypt it. The decrypted password is your third flag.

4. **Task 4 - Admin Login**: With the decrypted admin password in hand, the final task will be to find a way to log in to the admin account. The admin's session cookie will be the final flag.

## Challenge Rules

1. Only attack the target, not the CTF platform itself.
2. Flags or explicit solutions should not be shared with other participants.
3. The tasks are not solveable with automated tools, and useage of automated tools are prohibited. Understanding the code, the vulnerabilities, and crafting targeted exploits is required.
4. For flag submission, visit the ctf.parity.tech/flag endpoint and make sure to use a valid email when submitting the flags.
5. Have fun and treat this as a learning experience!
