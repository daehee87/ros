mkdir out 2>/dev/null
sudo docker build -t "ros-build" .
sudo docker rm -f ros-build-nick
# add --cap-add=SYS_PTRACE --security-opt seccomp=unconfined to debug nginx
sudo docker run --cap-add=SYS_PTRACE \
                --security-opt \
                seccomp=unconfined \
                -v $PWD/out:/out \
                --name ros-build-nick \
                -it \
                ros-build

