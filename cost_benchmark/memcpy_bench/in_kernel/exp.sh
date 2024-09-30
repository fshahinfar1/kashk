for i in $(seq 100); do
	make test &>> /tmp/results.txt
done
