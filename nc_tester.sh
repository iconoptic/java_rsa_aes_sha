#!/bin/bash

digSig () {
    #Keygen
    cd KeyGen
    java Keygen
    cp XPrivate.key ../Sender
    cp symmetric.key ../Sender
    cp XPublic.key ../Receiver
    cp symmetric.key ../Receiver

    #Sender
    cd ../Sender
    java Sender
    cp message.aescipher ../Receiver

    #Receiver
    cd ../Receiver
    java Receiver
}

time digSig
