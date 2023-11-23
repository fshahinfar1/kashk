#! /bin/bash
set -e
# set -x
CURDIR=$(realpath $(dirname $0))

echo "Checking the kernel version (expecting > 5.17)"
MAJOR=$(uname -r | cut -d '.' -f 1)
MINOR=$(uname -r | cut -d '.' -f 2)
if [ $MAJOR -lt 5 ]; then
	echo Update kernel
	exit 1
elif [ $MAJOR -eq 5 -a $MINOR -lt 17 ]; then
	echo Update kernel
	exit 1
fi
echo Found kernel $MAJOR.$MINOR

echo Install libclang-15-dev
sudo apt update
sudo apt install libclang-15-dev

echo Install python
sudo apt install python3 python3-pip python3-venv

echo Create python virtual environment
if [ ! -d $CURDIR/venv ]; then
	python3 -m venv $CURDIR/venv
fi
source $CURDIR/venv/bin/activate
pip install -r ./requirements.txt

echo Configuring the environment variable
if [ -z $KASHK_DIR ]; then
	# If the KASHK_DIR is not defined
	if [ -f $HOME/.bashrc ]; then
		echo "Found BASH"
		printf "export KASHK_DIR=$CURDIR\n" | tee -a $HOME/.bashrc
	fi

	if [ -f $HOME/.config/fish/config.fish ]; then
		echo "Found Fish"
		printf "set -x KASHK_DIR $CURDIR\n" | tee -a $HOME/.config/fish/config.fish
	fi
fi

echo Install gcc-multilib to fix issue with some header files
sudo apt install gcc-multilib
