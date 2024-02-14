#!/bin/bash

#Keygen
cd KeyGen
javac Keygen.java && java Keygen
cp XPrivate.key ../Sender
cp symmetric.key ../Sender
cp XPublic.key ../Receiver
cp symmetric.key ../Receiver

#Sender
cd ../Sender
javac Sender.java && java Sender
cp message.aescipher ../Receiver

#Receiver
cd ../Receiver
javac Receiver.java && java Receiver
