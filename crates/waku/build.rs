fn main() {
    let proto_dir = "proto";

    prost_build::compile_protos(
        &[
            format!("{proto_dir}/message.proto"),
            format!("{proto_dir}/light_push.proto"),
            format!("{proto_dir}/peer_exchange.proto"),
            format!("{proto_dir}/metadata.proto"),
            format!("{proto_dir}/filter.proto"),
        ],
        &[proto_dir],
    )
    .expect("failed to compile protos");

    println!("cargo:rerun-if-changed={proto_dir}/message.proto");
    println!("cargo:rerun-if-changed={proto_dir}/light_push.proto");
    println!("cargo:rerun-if-changed={proto_dir}/peer_exchange.proto");
    println!("cargo:rerun-if-changed={proto_dir}/metadata.proto");
    println!("cargo:rerun-if-changed={proto_dir}/filter.proto");
}
