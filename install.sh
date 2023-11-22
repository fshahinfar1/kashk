CURDIR=$(realpath $(dirname $0))
if [ -d $HOME/.bashrc ]; then
	echo "Found BASH"
	printf "export KASHK_DIR=$CURDIR" | tee -a ~/.bashrc
fi

if [ -d $HOME/.config/fish/config.fish ]; then
	echo "Found Fish"
	printf "set -x KASHK_DIR $CURDIR" | tee -a ~/.bashrc
fi
