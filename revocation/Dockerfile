# From revocation/:
#   docker build -t revocation-bench -f Dockerfile .
#
# Server profile (8 CPUs, 16 GB):
#   docker run --rm --cpus=8 --memory=16g --memory-swap=16g \
#     -v "$(pwd)/results:/bench/results" \
#     revocation-bench \
#     bash -lc 'npm run experiment'
#
FROM node:20-bookworm

WORKDIR /bench

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash ca-certificates python3 python3-matplotlib python3-numpy \
 && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json ./
RUN npm ci

COPY . .

RUN npm run verify

CMD ["bash"]
