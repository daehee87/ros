FROM ubuntu:20.04

RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/kr.archive.ubuntu.com/g" /etc/apt/sources.list

# install related libraries
ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Seoul
RUN apt update && apt-get install -y build-essential clang gcc g++ bsdmainutils git cmake ant

# at root
WORKDIR /

# setup PX4 source
RUN git clone https://github.com/PX4/PX4-Autopilot.git
RUN apt-get install -y python3 python3-pip
RUN pip3 install kconfiglib jinja2
RUN pip3 install --user empy pyros-genmsg jsonschema packaging toml numpy future crccheck

WORKDIR /PX4-Autopilot
ENV CC clang
ENV CXX clang
ENV PX4_MSAN 1
ENV PX4_ASAN 1
ENV PX4_FUZZ 1

ADD PX4-Autopilot/platforms/common/shutdown.cpp platforms/common/shutdown.cpp
ADD PX4-Autopilot/platforms/posix/src/px4/common/ platforms/posix/src/px4/common/
ADD PX4-Autopilot/platforms/common/shutdown.cpp platforms/common/shutdown.cpp

RUN make px4_sitl jmavsim

ADD 4dfuzzer_file.py /
ADD init.sh /
STOPSIGNAL SIGTERM
CMD ["/init.sh"]


