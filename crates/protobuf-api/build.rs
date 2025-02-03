fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_path = "proto/vpn_detector.proto";

    // Генерируем код в директорию out
    let out_dir = "src/generated";
    std::fs::create_dir_all(out_dir)?;

    tonic_build::configure()
        .out_dir(out_dir)
        .compile_protos(&[proto_path], &["proto"])?;

    // Перегенерируем при изменении .proto файла
    println!("cargo:rerun-if-changed={}", proto_path);

    Ok(())
}
