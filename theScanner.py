#!/usr/bin/python

import os
import sys
import time

def slowprint(s):
    for c in s + '\n':
        sys.stdout.write(c)
        sys.stdout.flush()
        time.sleep(1 / 1000)

def menu():
    slowprint("""
    
  _   _           _____                                 
 | | | |         / ____|                                
 | |_| |__   ___| (___   ___ __ _ _ __  _ __   ___ _ __ 
 | __| '_ \ / _ \\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 | |_| | | |  __/____) | (_| (_| | | | | | | |  __/ |   
  \__|_| |_|\___|_____/ \___\__,_|_| |_|_| |_|\___|_|
  
  ! theScanner 1.0
  ! Coded by Leif R Bruce
  ! Netrunner Security
  ! leifbruce1996@gmail.com
    
    
    
    
    
    1. RUN NMAP SCAN
    2. RUN FPING SCAN
    3. EXIT
    """)
    choice = int(input("Please enter a valid option \n>>> "))
    return choice

def NMAP():
    nmap_command = input("Please enter an IP address. EX: 0.0.0.0 0.0.0.0 \n>>> ")
    os.system(f"nmap -sT -O -T4 {nmap_command}")

def FPING():
    fping = input("Please enter an IP range EX: 0.0.0.0 0.0.0.0 \n>>> ")
    os.system(f"fping -a -g {fping}")

def main():
    choice = 0
    while choice != 3:
        choice = menu()
        if choice == 1:
            NMAP()
        elif choice == 2:
            FPING()
        elif choice == 3:
            slowprint("Now Exiting Program.......")
        else:
            print("Please choice a valid option.")

if __name__ == "__main__":
    main()
