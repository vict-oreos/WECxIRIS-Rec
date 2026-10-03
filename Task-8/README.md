# WECxIRIS-Rec (Task 8: Networking)

I'm writing the code for this on VS Code on Windows OS using C++ and g++ compiler. (unfortunately don't have a dual boot, just Ubuntu on VirtualBox and the resolution isn't great :/)

__Level 1: TCP Plumbing and Message Framing__
Main resource referred to: geeksforgeeks.com [Computer Networking, Client-Server Model (got my server and client C++ boiler template code from here, I modified it to meet the requirements)]

Level 1 focuses on setting up a TCP client and server. This is done using sockets, which are used for communication between a client and a server over a network. In a client-server model, the client sends a request to the server, which processes it and sends back a response to the client. The basic flow of communication looks something like this:

Server: Create Socket -> Bind -> Listen -> Accept -> Receive -> Send

Client: Create Socket -> Connect -> Send -> Receive (taken from geeksforgeeks.com)

We will be using various socket functions to implement this. Since this is a Windows socket program, I included winsock2.h and ws2tcpip.h as they contain the core socket functions and IP extensions. If this was done using a Linux kernel instead, they could be avoided as these socket functions are built into the kernel.
TCP is a byte stream protocol, so data arrives as an unsegmented continuous flow of bytes. What this means is that without proper framing, the message may end up jumbled as TCP doesn't have set message boundaries. To tackle this problem, I'm using TLV framing (Type, Length, Value/Payload). This system of framing is used in modern day network protocols like TCP/IP. Basically, a message is composed of 3 components: 1 byte specifies the type of the message (whether it is a chat message or a key exchange etc (we will see this properly in later levels), the next 4 bytes specify the length of the payload, and then the n byte payload follows. Within the program, the recv() function works in such a way that it takes each of these components into consideration by reading the headers first and then the payload itself to ensure that the messages don't splice into each other. 

To prove that this works for multiple messages of different sizing, messages have been hardcoded and sent from between the sockets to show that they arrive in the correct order (TCP) without being merged or spliced into (TLV). Further explanations are written into the code.

__Level 2: Diffie-Hellman Key Exchange__
