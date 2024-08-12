// atom install script
#! /usr/bin/sh

sudo apt install libxcb-cursor0
sudo apt install docker.io

sudo groupadd docker
sudo usermod -aG $USER

sudo apt install golang
pip install -m requirements.txt