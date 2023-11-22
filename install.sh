CURDIR=$(realpath $(dirname $0))
if [ -f $HOME/.bashrc ]; then
	echo "Found BASH"
	printf "export KASHK_DIR=$CURDIR\n" | tee -a $HOME/.bashrc
fi

if [ -f $HOME/.config/fish/config.fish ]; then
	echo "Found Fish"
	printf "set -x KASHK_DIR $CURDIR\n" | tee -a $HOME/.config/fish/config.fish
fi
