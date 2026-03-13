# --- Stage 1: Build WASM ---
FROM rust:bookworm AS wasm

RUN curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
RUN rustup target add wasm32-unknown-unknown

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/

RUN wasm-pack build --target web --out-dir pkg

# --- Stage 2: Serve ---
FROM node:20-bookworm-slim

RUN apt-get update && apt-get install -y python3 make g++ && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY example/package.json ./
RUN npm install --omit=dev

COPY example/server.js ./
COPY example/public/ public/
COPY --from=wasm /build/pkg/ public/pkg/

RUN mkdir -p data

EXPOSE 3000
CMD ["node", "server.js"]
