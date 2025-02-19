# honeypot
A practice honeypot system to find and log attackers targeting a list of simulated vulnerable services.
# How it works
The system listens on multiple ports corresponding to commonly targeted services such as FTP, SSH, Telnet, SMTP, DNS, HTTP, and HTTPS. Whenever a connection is established with one of these ports, it logs the IP address of the connecting client and sends a predefined response indicating that access is denied, simulating a vulnerable system.
To run this honeypot system, follow these steps:

Clone this repository to your local machine.

Ensure you have Python installed (version 3.x).

Open a terminal or command prompt and navigate to the directory containing the cloned repository.

Run the Python script honeypot.py using the command:

python honeypot.py
The honeypot system will start listening on the specified ports for incoming connections.
