#!/bin/bash
# This script will install the dependencies for the project
# Author: Rick Sanchez
# Date: 2/9/2022

linux_install_with_package_manager() {
  # if the OS is debian/ubuntu use apt-get to install $1
    if [ -f /etc/debian_version ]; then
        sudo apt-get install -y $1
    # elif the OS is archlinux use pacman to install $1
    elif [ -f /etc/arch-release ]; then
        sudo pacman -S --noconfirm $1
    # elif the OS is redhat/fedora use yum to install $1
    elif [ -f /etc/redhat-release ]; then
        sudo yum install -y $1
    else
        echo "OS not supported"
        exit 1
    fi
}

linux_update_package_manager(){
    if [ -f /etc/debian_version ]; then
        sudo apt-get update
    elif [ -f /etc/arch-release ]; then
        sudo pacman -Syu
    elif [ -f /etc/redhat-release ]; then
        sudo yum update
    else
        echo "OS not supported"
        exit 1
    fi
}

# update the packager appropriately for the OS and architecture
if [ "$(uname)" == "Darwin" ]; then
    export PACKAGER="macosx"
elif [ "$(expr substr $(uname -s) 1 5)" == "Linux" ]; then
    export PACKAGER="linux"
fi

# update the architecture appropriately for the OS and architecture
if [ "$(uname -m)" == "x86_64" ]; then
    export ARCH="amd64"
elif [ "$(uname -m)" == "i686" ]; then
    export ARCH="386"
fi

# if the var $PACKAGER is not set, exit with an error
if [ -z "$PACKAGER" ]; then
    echo "Unable to determine the packager for this OS and architecture."
    exit 1
else
# else call the appropriate package manager to install
    if [[ "$PACKAGER" == "linux" ]]; then
        echo 'linux package manager update...'
        linux_update_package_manager
        echo 'linux package manager install...'
        linux_install_with_package_manager python3
    elif [[ "$PACKAGER" == "macosx" ]]; then
        if [ -f /usr/local/bin/brew ]; then
            echo "Homebrew is already installed so brew update and brew upgrade"
            echo "Homebrew installation skipped."
            brew update
            brew install python@3.9 pipenv
        else
            echo "Homebrew is not installed. Installation of homebrew..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            echo "Now installing, brew update and install python@3.9 and pipenv..."
            brew update
            brew install python@3.9 pipenv
        fi
    fi
fi

# function to install packages with the appropriate package manager, linux, mac, fedora, etc.
function install_packages() {
    if [ "$(uname)" == "Darwin" ]; then
        brew install $1
    elif [ "$(expr substr $(uname -s) 1 5)" == "Linux" ]; then
        #detect linux branch based
        linux_install_with_package_manager $1
    elif [ "$(expr substr $(uname -s) 1 10)" == "MINGW32_NT" ]; then
        echo "Windows"
    else
        echo "Unknown OS"
    fi
}

# install the packages
install_packages hostapd
install_packages haveged
install_packages dnsmasq
install_packages qrencode

# make the /opt/lnxrouter directory
sudo mkdir -p /opt/lnxrouter

# make the /opt/lnxrouter/bin directory
sudo mkdir -p /opt/lnxrouter/bin

# copy the lnxrouter script to /opt/lnxrouter/bin
sudo cp lnxrouter /opt/lnxrouter/bin/lnxrouter

# change the permissions on the lnxrouter script
sudo chown -R $USER:$USER /opt/lnxrouter/
sudo chmod a+x /opt/lnxrouter/bin/lnxrouter

# create symbolic link to the lnxrouter.sh script
sudo ln -s /opt/lnxrouter/bin/lnxrouter /usr/bin/lnxrouter

# display "It's done!" in yellow
echo -e "\e[33mIt's done!\e[0m"
