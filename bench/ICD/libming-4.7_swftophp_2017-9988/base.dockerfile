FROM my-aflplusplus:latest

RUN apt-get update && apt-get install -y \
    make cmake pkg-config wget curl git

WORKDIR /src

RUN git clone https://github.com/libming/libming.git && \
    cd libming && \
    git checkout ming-0_4_7
RUN mkdir /workspace
WORKDIR /src/libming

RUN ./autogen.sh
RUN ./configure --disable-shared --disable-freetype \
    CC=afl-clang-lto CXX=afl-clang-lto++

ENV AFL_DGF_FILE=parser.c
ENV AFL_DGF_LINE=2995
ENV AFL_DGF_MAX_DEPTH=1000
ENV AFL_DGF_INFO_DIR=/workspace
ENV AFL_DGF_CONTROL_GROUP=1

RUN make -C src && make -C util swftophp

WORKDIR /workspace
RUN cp /src/libming/util/swftophp ./swftophp
RUN mkdir in
RUN mkdir out
COPY seed/ in
COPY script.sh .

RUN apt install -y tmux
