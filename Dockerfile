# ------------------------------ BUILD ------------------------------
FROM rustlang/rust:nightly AS BUILD

# Set the working directory.
WORKDIR /build

# Copy source code to image.
COPY .env Cargo.toml Cargo.lock ./
COPY src ./
COPY resources ./
COPY .sqlx ./

# Run build process.
RUN cargo build --release

# ------------------------------ RUN ------------------------------
FROM debian:stretch-slim

# Copy the built binary from the build image.
COPY --from=BUILD /build/target/release/pancake /app/pancake

# Copy the configuration file.
COPY ./Rocket.prod.toml /app/Rocket.toml

# Set the working directory.
WORKDIR /app

# Expose the port.
EXPOSE 8000

# Run the binary.
CMD ["/app/pancake"]