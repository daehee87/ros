ID="$(basename $PWD)"
cp ../4dfuzzer_file.py .
sudo docker build -t "ros-$ID" .
sudo docker rm -f "ros-$ID-nick"
# add --cap-add=SYS_PTRACE --security-opt seccomp=unconfined to debug nginx
sudo docker run --cap-add=SYS_PTRACE \
                --security-opt \
                seccomp=unconfined \
                -v $PWD/out:/out \
                --name "ros-$ID-nick" \
                -it \
                "ros-$ID"

